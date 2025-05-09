//! Bitcoin protocol state machine.
#![warn(missing_docs)]
use crossbeam_channel as chan;
use log::*;

pub mod bloom_cache;
pub mod event;
pub mod fees;
pub mod filter_cache;
pub mod output;

// Sub-protocols.
mod addrmgr;
mod bfmgr;
mod cbfmgr;
mod invmgr;
mod peermgr;
mod pingmgr;
mod syncmgr;

#[cfg(test)]
mod tests;

use addrmgr::AddressManager;
use bfmgr::BloomManager;
use cbfmgr::FilterManager;
use invmgr::InventoryManager;
use nakamoto_common::bitcoin::util::bloom::BloomFilter;
use output::Outbox;
use peermgr::PeerManager;
use pingmgr::PingManager;
use syncmgr::SyncManager;

pub use event::Event;
pub use nakamoto_net::Link;

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::{self, Debug};
use std::net;
use std::ops::{Bound, RangeInclusive};
use std::sync::Arc;

use nakamoto_common::bitcoin::blockdata::block::BlockHeader;
use nakamoto_common::bitcoin::consensus::encode;
use nakamoto_common::bitcoin::consensus::params::Params;
use nakamoto_common::bitcoin::network::constants::ServiceFlags;
use nakamoto_common::bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use nakamoto_common::bitcoin::network::message_blockdata::Inventory;
use nakamoto_common::bitcoin::network::message_filter::GetCFilters;
use nakamoto_common::bitcoin::network::message_network::VersionMessage;
use nakamoto_common::bitcoin::network::Address;
use nakamoto_common::bitcoin::util::uint::Uint256;
use nakamoto_common::bitcoin::{Script, Txid};
use nakamoto_common::block::filter::Filters;
use nakamoto_common::block::time::AdjustedClock;
use nakamoto_common::block::time::{LocalDuration, LocalTime};
use nakamoto_common::block::tree::{self, BlockReader, BlockTree, ImportResult};
use nakamoto_common::block::{BlockHash, Height};
use nakamoto_common::block::{BlockTime, Transaction};
use nakamoto_common::network;
use nakamoto_common::nonempty::NonEmpty;
use nakamoto_common::p2p::{peer, Domain};
use nakamoto_net as traits;

use thiserror::Error;

/// Peer-to-peer protocol version.
pub const PROTOCOL_VERSION: u32 = 70016;
/// Minimum supported peer protocol version.
/// This version includes support for the `sendheaders` feature.
pub const MIN_PROTOCOL_VERSION: u32 = 70012;
/// User agent included in `version` messages.
pub const USER_AGENT: &str = "/nakamoto:0.3.0/";

/// Block locators. Consists of starting hashes and a stop hash.
type Locators = (Vec<BlockHash>, BlockHash);

/// Output of a state transition.
pub type Io = nakamoto_net::Io<RawNetworkMessage, Event, DisconnectReason>;

/// Identifies a peer.
pub type PeerId = net::SocketAddr;

/// Source of blocks.
pub trait BlockSource {
    /// Get a block by asking peers.
    /// The block is returned asychronously via a [`Event::BlockProcessed`] event.
    fn get_block(&mut self, hash: BlockHash);
}

impl<C: nakamoto_common::block::time::Clock> BlockSource for InventoryManager<C> {
    fn get_block(&mut self, hash: BlockHash) {
        self.get_block(hash)
    }
}

impl BlockSource for () {
    fn get_block(&mut self, _hash: BlockHash) {}
}

/// Disconnect reason.
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Peer is misbehaving.
    PeerMisbehaving(&'static str),
    /// Peer protocol version is too old or too recent.
    PeerProtocolVersion(u32),
    /// Peer doesn't have the required services.
    PeerServices(ServiceFlags),
    /// Peer chain is too far behind.
    PeerHeight(Height),
    /// Peer magic is invalid.
    PeerMagic(u32),
    /// Peer timed out.
    PeerTimeout(&'static str),
    /// Connection to self was detected.
    SelfConnection,
    /// Inbound connection limit reached.
    ConnectionLimit,
    /// Error trying to decode incoming message.
    DecodeError(Arc<encode::Error>),
    /// Peer was forced to disconnect by external command.
    Command,
    /// Peer was disconnected for another reason.
    Other(&'static str),
}

impl DisconnectReason {
    /// Check whether the disconnect reason is transient, ie. may no longer be applicable
    /// after some time.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::ConnectionLimit | Self::PeerTimeout(_) | Self::PeerHeight(_)
        )
    }
}

impl From<DisconnectReason> for nakamoto_net::Disconnect<DisconnectReason> {
    fn from(reason: DisconnectReason) -> Self {
        Self::StateMachine(reason)
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerMisbehaving(reason) => write!(f, "peer misbehaving: {}", reason),
            Self::PeerProtocolVersion(_) => write!(f, "peer protocol version mismatch"),
            Self::PeerServices(_) => write!(f, "peer doesn't have the required services"),
            Self::PeerHeight(_) => write!(f, "peer is too far behind"),
            Self::PeerMagic(magic) => write!(f, "received message with invalid magic: {}", magic),
            Self::PeerTimeout(s) => write!(f, "peer timed out: {:?}", s),
            Self::SelfConnection => write!(f, "detected self-connection"),
            Self::ConnectionLimit => write!(f, "inbound connection limit reached"),
            Self::DecodeError(err) => write!(f, "message decode error: {}", err),
            Self::Command => write!(f, "received external command"),
            Self::Other(reason) => write!(f, "{}", reason),
        }
    }
}

/// A remote peer.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer address.
    pub addr: net::SocketAddr,
    /// Local peer address.
    pub local_addr: net::SocketAddr,
    /// Whether this is an inbound or outbound peer connection.
    pub link: Link,
    /// Connected since this time.
    pub since: LocalTime,
    /// The peer's best height.
    pub height: Height,
    /// The peer's services.
    pub services: ServiceFlags,
    /// Peer user agent string.
    pub user_agent: String,
    /// Whether this peer relays transactions.
    pub relay: bool,
    /// latency
    pub latency: LocalDuration,
}

impl Peer {
    /// Check if this is an outbound peer.
    pub fn is_outbound(&self) -> bool {
        self.link.is_outbound()
    }
}

impl From<(&peermgr::PeerInfo, &peermgr::Connection, &pingmgr::Peer)> for Peer {
    fn from(
        (peer, conn, ping): (&peermgr::PeerInfo, &peermgr::Connection, &pingmgr::Peer),
    ) -> Self {
        Self {
            addr: conn.addr,
            local_addr: conn.local_addr,
            link: conn.link,
            since: conn.since,
            height: peer.height,
            services: peer.services,
            user_agent: peer.user_agent.clone(),
            relay: peer.relay,
            latency: ping.latency(),
        }
    }
}

impl From<(&peermgr::PeerInfo, &peermgr::Connection)> for Peer {
    fn from((peer, conn): (&peermgr::PeerInfo, &peermgr::Connection)) -> Self {
        Self {
            addr: conn.addr,
            local_addr: conn.local_addr,
            link: conn.link,
            since: conn.since,
            height: peer.height,
            services: peer.services,
            user_agent: peer.user_agent.clone(),
            relay: peer.relay,
            latency: LocalDuration::from_secs(0),
        }
    }
}

/// A command or request that can be sent to the protocol.
#[derive(Clone)]
pub enum Command {
    /// Get block header at height.
    GetBlockByHeight(Height, chan::Sender<Option<BlockHeader>>),
    /// Get a block from the active chain.
    GetBlock(BlockHash),
    /// Get connected peers.
    GetPeers(ServiceFlags, chan::Sender<Vec<Peer>>),
    /// Get the tip of the active chain.
    GetTip(chan::Sender<(Height, BlockHeader, Uint256)>),
    /// Get a block from the active chain.
    RequestBlock(BlockHash),
    /// Get block filters.
    RequestFilters(
        RangeInclusive<Height>,
        chan::Sender<Result<(), GetFiltersError>>,
    ),
    /// Rescan the chain for matching scripts and addresses.
    Rescan {
        /// Start scan from this height. If unbounded, start at the current height.
        from: Bound<Height>,
        /// Stop scanning at this height. If unbounded, don't stop scanning.
        to: Bound<Height>,
        /// Scripts to match on.
        watch: Vec<Script>,
    },
    /// Rescan the chain for matching scripts and addresses.
    MerkleBlockRescan {
        /// Start scan from this height. If unbounded, start at the current height.
        from: Bound<Height>,
        /// Stop scanning at this height. If unbounded, don't stop scanning.
        to: Bound<Height>,
        /// peers to load bloom filter.
        peers: Vec<PeerId>,
    },
    /// Update the watchlist with the provided scripts.
    Watch {
        /// Scripts to watch.
        watch: Vec<Script>,
    },
    /// Broadcast to peers matching the predicate.
    Broadcast(NetworkMessage, fn(Peer) -> bool, chan::Sender<Vec<PeerId>>),
    /// Query the block tree.
    QueryTree(Arc<dyn Fn(&dyn BlockReader) + Send + Sync>),
    /// Connect to a peer.
    Connect(net::SocketAddr),
    /// Disconnect from a peer.
    Disconnect(net::SocketAddr),
    /// Import headers directly into the block store.
    ImportHeaders(
        Vec<BlockHeader>,
        chan::Sender<Result<ImportResult, tree::Error>>,
    ),
    /// Import addresses into the address book.
    ImportAddresses(Vec<Address>),
    /// Submit a transaction to the network.
    SubmitTransaction(
        Transaction,
        chan::Sender<Result<NonEmpty<PeerId>, CommandError>>,
    ),
    /// Get a previously submitted transaction.
    GetSubmittedTransaction(Txid, chan::Sender<Option<Transaction>>),
    /// Load Bloom filters to the .
    LoadBloomFilter((BloomFilter, Vec<PeerId>)),
    /// Get mempool
    GetMempool,
    /// get non bloom loaded peers
    GetPeersNotBloomFiltered(chan::Sender<Vec<PeerId>>),
    /// Clear Bloom Filters
    BloomFilterClear,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetMempool => write!(f, "GetMempool"),
            Self::BloomFilterClear => write!(f, "Command Filter Clear"),
            Self::GetBlockByHeight(height, _) => write!(f, "GetBlockByHeight({})", height),
            Self::GetBlock(hash) => write!(f, "GetBlock({})", hash),
            Self::GetPeers(flags, _) => write!(f, "GetPeers({})", flags),
            Self::GetTip(_) => write!(f, "GetTip"),
            Self::RequestBlock(hash) => write!(f, "GetBlock({})", hash),
            Self::RequestFilters(range, _) => write!(f, "GetFilters({:?})", range),
            Self::Rescan { from, to, watch } => {
                write!(f, "Rescan({:?}, {:?}, {:?})", from, to, watch)
            }
            Self::MerkleBlockRescan { from, to, peers } => {
                write!(f, "MerkleBlockRescan ({:?}, {:?}, {:?})", from, to, peers)
            }
            Self::Watch { watch } => {
                write!(f, "Watch({:?})", watch)
            }
            Self::Broadcast(msg, _, _) => write!(f, "Broadcast({})", msg.cmd()),
            Self::QueryTree(_) => write!(f, "QueryTree"),
            Self::Connect(addr) => write!(f, "Connect({})", addr),
            Self::Disconnect(addr) => write!(f, "Disconnect({})", addr),
            Self::ImportHeaders(_headers, _) => write!(f, "ImportHeaders(..)"),
            Self::ImportAddresses(addrs) => write!(f, "ImportAddresses({:?})", addrs),
            Self::SubmitTransaction(tx, _) => write!(f, "SubmitTransaction({:?})", tx),
            Self::GetSubmittedTransaction(txid, _) => write!(f, "GetSubmittedTransaction({txid})"),
            Self::GetPeersNotBloomFiltered(_) => write!(f, "GetPeersNotBloomFilterd"),
            Self::LoadBloomFilter(_) => {
                write!(f, "LoadBloomFilter Request" /* filter */,)
            }
        }
    }
}

/// A generic error resulting from processing a [`Command`].
#[derive(Error, Debug)]
pub enum CommandError {
    /// Not connected to any peer with the required services.
    #[error("not connected to any peer with the required services")]
    NotConnected,
}

pub use cbfmgr::GetFiltersError;

/// Holds functions that are used to hook into or alter protocol behavior.
#[derive(Clone)]
pub struct Hooks {
    /// Called when we receive a message from a peer.
    /// If an error is returned, the message is not further processed.
    pub on_message:
        Arc<dyn Fn(PeerId, &NetworkMessage, &Outbox) -> Result<(), &'static str> + Send + Sync>,
    /// Called when a `version` message is received.
    /// If an error is returned, the peer is dropped, and the error is logged.
    pub on_version: Arc<dyn Fn(PeerId, &VersionMessage) -> Result<(), &'static str> + Send + Sync>,
    /// Called when a `getcfilters` message is received.
    pub on_getcfilters: Arc<dyn Fn(PeerId, GetCFilters, &Outbox) + Send + Sync>,
    /// Called when a `getdata` message is received.
    pub on_getdata: Arc<dyn Fn(PeerId, Vec<Inventory>, &Outbox) + Send + Sync>,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            on_message: Arc::new(|_, _, _| Ok(())),
            on_version: Arc::new(|_, _| Ok(())),
            on_getcfilters: Arc::new(|_, _, _| {}),
            on_getdata: Arc::new(|_, _, _| {}),
        }
    }
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hooks").finish()
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////

/// An instance of the Bitcoin P2P network protocol. Parametrized over the
/// block-tree and compact filter store.
#[derive(Debug)]
pub struct StateMachine<T, F, P, C> {
    /// Block tree.
    tree: T,
    /// Bitcoin network we're connecting to.
    network: network::Network,
    /// Peer address manager.
    addrmgr: AddressManager<P, C>,
    /// Blockchain synchronization manager.
    syncmgr: SyncManager<C>,
    /// Ping manager.
    pingmgr: PingManager<C>,
    /// CBF (Compact Block Filter) manager.
    cbfmgr: FilterManager<F, C>,
    /// BFM (Bloom Filter) manager.
    bfmgr: BloomManager<C>,
    /// Peer manager.
    peermgr: PeerManager<C>,
    /// Inventory manager.
    invmgr: InventoryManager<C>,
    /// Network-adjusted clock.
    clock: C,
    /// Last time a "tick" was triggered.
    #[allow(dead_code)]
    last_tick: LocalTime,
    /// Outbound I/O. Used to communicate protocol events with a reactor.
    outbox: Outbox,
    /// State machine event hooks.
    hooks: Hooks,
}

/// Configured limits.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Target outbound peer connections.
    pub max_outbound_peers: usize,
    /// Maximum inbound peer connections.
    pub max_inbound_peers: usize,
    /// Size in bytes of the compact filter cache.
    pub filter_cache_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_outbound_peers: peermgr::TARGET_OUTBOUND_PEERS,
            max_inbound_peers: peermgr::MAX_INBOUND_PEERS,
            filter_cache_size: cbfmgr::DEFAULT_FILTER_CACHE_SIZE,
        }
    }
}

/// State machine configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Bitcoin network we are connected to.
    pub network: network::Network,
    /// Peers to connect to.
    pub connect: Vec<net::SocketAddr>,
    /// Supported communication domains.
    pub domains: Vec<Domain>,
    /// Services offered by our peer.
    pub services: ServiceFlags,
    /// Required peer services.
    pub required_services: ServiceFlags,
    /// Peer whitelist. Peers in this list are trusted by default.
    pub whitelist: Whitelist,
    /// Consensus parameters.
    pub params: Params,
    /// Our protocol version.
    pub protocol_version: u32,
    /// Our user agent.
    pub user_agent: &'static str,
    /// Ping timeout, after which remotes are disconnected.
    pub ping_timeout: LocalDuration,
    /// State machine event hooks.
    pub hooks: Hooks,
    /// Configured limits.
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: network::Network::default(),
            params: Params::new(network::Network::default().into()),
            connect: Vec::new(),
            domains: Domain::all(),
            services: ServiceFlags::NONE,
            required_services: ServiceFlags::NETWORK,
            whitelist: Whitelist::default(),
            protocol_version: PROTOCOL_VERSION,
            ping_timeout: pingmgr::PING_TIMEOUT,
            user_agent: USER_AGENT,
            hooks: Hooks::default(),
            limits: Limits::default(),
        }
    }
}

impl Config {
    /// Construct a new configuration.
    pub fn from(network: network::Network, connect: Vec<net::SocketAddr>) -> Self {
        let params = Params::new(network.into());

        Self {
            network,
            connect,
            params,
            ..Self::default()
        }
    }

    /// Get the listen port.
    pub fn port(&self) -> u16 {
        self.network.port()
    }
}

/// Peer whitelist.
#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    /// Trusted addresses.
    addr: HashSet<net::IpAddr>,
    /// Trusted user-agents.
    user_agent: HashSet<String>,
}

impl Whitelist {
    fn contains(&self, addr: &net::IpAddr, user_agent: &str) -> bool {
        self.addr.contains(addr) || self.user_agent.contains(user_agent)
    }
}

impl<T: BlockTree, F: Filters, P: peer::Store, C: AdjustedClock<PeerId>> StateMachine<T, F, P, C> {
    /// Construct a new protocol instance.
    pub fn new(
        tree: T,
        filters: F,
        peers: P,
        clock: C,
        rng: fastrand::Rng,
        config: Config,
    ) -> Self {
        let Config {
            network,
            connect,
            domains,
            services,
            whitelist,
            protocol_version,
            ping_timeout,
            user_agent,
            required_services,
            params,
            hooks,
            limits,
        } = config;

        let outbox = Outbox::new(protocol_version);
        let syncmgr = SyncManager::new(
            syncmgr::Config {
                max_message_headers: syncmgr::MAX_MESSAGE_HEADERS,
                request_timeout: syncmgr::REQUEST_TIMEOUT,
                params,
            },
            rng.clone(),
            clock.clone(),
        );
        let pingmgr = PingManager::new(ping_timeout, rng.clone(), clock.clone());
        let cbfmgr = FilterManager::new(
            cbfmgr::Config {
                filter_cache_size: limits.filter_cache_size,
                ..cbfmgr::Config::default()
            },
            rng.clone(),
            filters,
            clock.clone(),
        );
        let peermgr = PeerManager::new(
            peermgr::Config {
                protocol_version: PROTOCOL_VERSION,
                whitelist,
                persistent: connect,
                domains: domains.clone(),
                target_outbound_peers: limits.max_outbound_peers,
                max_inbound_peers: limits.max_inbound_peers,
                retry_max_wait: LocalDuration::from_mins(60),
                retry_min_wait: LocalDuration::from_secs(1),
                required_services,
                preferred_services: syncmgr::REQUIRED_SERVICES | bfmgr::REQUIRED_SERVICES,
                services,
                user_agent,
            },
            rng.clone(),
            hooks.clone(),
            clock.clone(),
        );
        let addrmgr = AddressManager::new(
            addrmgr::Config {
                required_services,
                domains,
            },
            rng.clone(),
            peers,
            clock.clone(),
        );
        let invmgr = InventoryManager::new(rng.clone(), clock.clone());

        let bfmgr = BloomManager::new(rng, clock.clone());

        Self {
            tree,
            network,
            clock,
            addrmgr,
            syncmgr,
            pingmgr,
            cbfmgr,
            bfmgr,
            peermgr,
            invmgr,
            last_tick: LocalTime::default(),
            outbox,
            hooks,
        }
    }

    /// Disconnect a peer.
    pub fn disconnect(&mut self, addr: PeerId, reason: DisconnectReason) {
        self.peermgr.disconnect(addr, reason);
    }

    /// Create a draining iterator over the protocol outputs.
    pub fn drain(&mut self) -> Box<dyn Iterator<Item = Io> + '_> {
        Box::new(std::iter::from_fn(|| self.next()))
    }

    /// Send a message to a all peers matching the predicate.
    fn broadcast<Q>(&mut self, msg: NetworkMessage, predicate: Q) -> Vec<PeerId>
    where
        Q: Fn(&Peer) -> bool,
    {
        let mut peers = Vec::new();

        for peer in self.peermgr.peers().map(Peer::from) {
            if predicate(&peer) {
                peers.push(peer.addr);
                self.outbox.message(peer.addr, msg.clone());
            }
        }
        peers
    }
}

impl<T: BlockTree, F: Filters, P: peer::Store, C: AdjustedClock<PeerId>> Iterator
    for StateMachine<T, F, P, C>
{
    type Item = Io;

    fn next(&mut self) -> Option<Io> {
        let next = self
            .outbox
            .next()
            .or_else(|| self.peermgr.next())
            .or_else(|| self.syncmgr.next())
            .or_else(|| self.invmgr.next())
            .or_else(|| self.pingmgr.next())
            .or_else(|| self.addrmgr.next())
            .or_else(|| self.bfmgr.next())
            .or_else(|| self.cbfmgr.next())
            .map(|io| match io {
                output::Io::Write(addr, payload) => Io::Write(
                    addr,
                    RawNetworkMessage {
                        magic: self.network.magic(),
                        payload,
                    },
                ),
                output::Io::Connect(addr) => Io::Connect(addr),
                output::Io::Disconnect(addr, reason) => Io::Disconnect(addr, reason),
                output::Io::SetTimer(t) => Io::SetTimer(t),
                output::Io::Event(e) => Io::Event(e),
            });

        match next {
            Some(Io::Event(e)) => {
                self.event(e.clone());

                Some(Io::Event(e))
            }
            other => other,
        }
    }
}

impl<T: BlockTree, F: Filters, P: peer::Store, C: AdjustedClock<PeerId>> StateMachine<T, F, P, C> {
    /// Propagate an event internally to the sub-systems.
    pub fn event(&mut self, e: Event) {
        self.cbfmgr
            .received_event(e.clone(), &self.tree, &mut self.invmgr);
        self.pingmgr.received_event(e.clone(), &self.tree);
        self.invmgr.received_event(e.clone(), &self.tree);
        self.syncmgr.received_event(e.clone(), &mut self.tree);
        self.addrmgr.received_event(e.clone());
        self.bfmgr.received_event(e.clone(), &mut self.tree);
        self.peermgr.received_event(e, &self.tree);
    }

    /// Process a user command.
    pub fn command(&mut self, cmd: Command) {
        debug!(target: "p2p", "Received command: {:?}", cmd);

        match cmd {
            Command::QueryTree(query) => {
                query(&self.tree);
            }
            Command::GetBlock(hash) => {
                self.invmgr.get_block(hash);
            }
            Command::GetBlockByHeight(height, reply) => {
                let header = self.tree.get_block_by_height(height).copied();

                reply.send(header).ok();
            }
            Command::GetPeers(services, reply) => {
                let latencies = self
                    .pingmgr
                    .peers
                    .iter()
                    .map(|p| (p.0, p.1.latency()))
                    .collect::<Vec<_>>();
                let mut peers: Vec<Peer> = Vec::new();
                self.peermgr
                    .peers()
                    .filter(|(p, _)| p.is_negotiated())
                    .filter(|(p, _)| p.services.has(services))
                    .map(Peer::from)
                    .collect::<Vec<Peer>>()
                    .iter()
                    .for_each(|peer| {
                        if let Some((_socket, latency)) =
                            latencies.iter().find(|l| *l.0 == peer.addr)
                        {
                            let mut p = peer.clone();
                            p.latency = *latency;
                            peers.push(p.clone());
                        }
                    });

                reply.send(peers).ok();
            }
            Command::Connect(addr) => {
                self.peermgr.whitelist(addr);
                self.peermgr.connect(&addr);
            }
            Command::Disconnect(addr) => {
                self.peermgr.disconnect(addr, DisconnectReason::Command);
            }
            Command::Broadcast(msg, predicate, reply) => {
                let peers = self.broadcast(msg, |p| predicate(p.clone()));
                reply.send(peers).ok();
            }
            Command::ImportHeaders(headers, reply) => {
                let result = self
                    .syncmgr
                    .import_block_headers(headers.into_iter(), &mut self.tree);

                match result {
                    Ok(import_result) => {
                        reply.send(Ok(import_result)).ok();
                    }
                    Err(err) => {
                        reply.send(Err(err)).ok();
                    }
                }
            }
            Command::ImportAddresses(addrs) => {
                self.addrmgr.insert(
                    // Nb. For imported addresses, the time last active is not relevant.
                    addrs.into_iter().map(|a| (BlockTime::default(), a)),
                    peer::Source::Imported,
                );
            }
            Command::GetTip(reply) => {
                let (_, header) = self.tree.tip();
                let height = self.tree.height();
                let chainwork = self.tree.chain_work();

                reply.send((height, header, chainwork)).ok();
            }
            Command::RequestFilters(range, reply) => {
                let result = self.cbfmgr.get_cfilters(range, &self.tree);
                reply.send(result).ok();
            }
            Command::RequestBlock(hash) => {
                self.invmgr.get_block(hash);
            }
            Command::SubmitTransaction(tx, reply) => {
                // Update local watchlist to track submitted transactions.
                //
                // Nb. This is currently non-optimal, as the cfilter matching is based on the
                // output scripts. This may trigger false-positives, since the same
                // invoice (address) can be re-used by multiple transactions, ie. outputs
                // can figure in more than one block.
                // NOT USING CBF for now
                // self.cbfmgr.watch_transaction(&tx);

                let peers = self.invmgr.announce(tx.clone());
                if let Some(peers) = NonEmpty::from_vec(peers) {
                    // self.outbox.message(*peers.first(), NetworkMessage::Tx(tx));

                    reply.send(Ok(peers)).ok();
                } else {
                    reply.send(Err(CommandError::NotConnected)).ok();
                }
            }
            Command::Rescan { from, to, watch } => {
                // A rescan with a new watch list may return matches on cached filters.
                for (_, hash) in self.cbfmgr.rescan(from, to, watch, &self.tree) {
                    self.invmgr.get_block(hash);
                }
            }
            Command::MerkleBlockRescan { from, to, peers } => {
                self.bfmgr.merkle_scan(from, to, peers, &self.tree);
            }
            Command::Watch { watch } => {
                self.cbfmgr.watch(watch);
            }
            Command::GetSubmittedTransaction(ref txid, reply) => {
                let tx = self.invmgr.get_submitted_tx(txid);
                reply.send(tx).ok();
            }
            Command::LoadBloomFilter((filter, peers)) => {
                self.bfmgr.send_bloom_filter_all_connected(filter, peers);
                // _ => self.bfmgr.send_bloom_filter_single_peer(filter, peers[0]),
                // reply.send(bloom_data).ok();
            }
            Command::GetMempool => self.bfmgr.get_mempool(),
            Command::GetPeersNotBloomFiltered(reply) => {
                let peers = self.bfmgr.by_ref().get_peers_not_filter_loaded();

                reply.send(peers).ok();
            }
            Command::BloomFilterClear => {
                 self.bfmgr.by_ref().send_bloom_filter_clear();

            }
        }
    }
}

impl<T: BlockTree, F: Filters, P: peer::Store, C: AdjustedClock<PeerId>> traits::StateMachine
    for StateMachine<T, F, P, C>
{
    type Message = RawNetworkMessage;
    type Event = Event;
    type DisconnectReason = DisconnectReason;

    fn initialize(&mut self, time: LocalTime) {
        self.clock.set(time);
        self.outbox.event(Event::Initializing);
        self.addrmgr.initialize();
        self.syncmgr.initialize(&self.tree);
        self.peermgr.initialize(&mut self.addrmgr);
        self.cbfmgr.initialize(&self.tree);
        self.bfmgr.initialize(&self.tree);
        self.outbox.event(Event::Ready {
            tip: self.tree.height(),
            filter_tip: self.cbfmgr.filters.height(),
            time,
        });
    }

    fn message_received(&mut self, addr: &net::SocketAddr, msg: Cow<RawNetworkMessage>) {
        let cmd = msg.cmd();
        let addr = *addr;
        let msg = msg.into_owned();

        if msg.magic != self.network.magic() {
            return self
                .peermgr
                .disconnect(addr, DisconnectReason::PeerMagic(msg.magic));
        }

        if !self.peermgr.is_connected(&addr) {
            debug!(target: "p2p", "Received {:?} from unknown peer {}", cmd, addr);
            return;
        }

        // debug!(target: "p2p", "Received {:?} from {}", cmd, addr);

        if let Err(err) = (self.hooks.on_message)(addr, &msg.payload, &self.outbox) {
            debug!(
                target: "p2p",
                "Message {:?} from {} dropped by user hook: {}",
                cmd, addr, err
            );
            return;
        }

        // Nb. We only send this message internally, hence we don't
        // push it to our outbox.
        self.event(Event::MessageReceived {
            from: addr,
            message: Arc::new(msg.payload),
        });
    }

    fn attempted(&mut self, addr: &net::SocketAddr) {
        self.peermgr.peer_attempted(addr);
    }

    fn connected(&mut self, addr: net::SocketAddr, local_addr: &net::SocketAddr, link: Link) {
        self.peermgr
            .peer_connected(addr, *local_addr, link, self.tree.height());
    }

    fn disconnected(
        &mut self,
        addr: &net::SocketAddr,
        reason: nakamoto_net::Disconnect<DisconnectReason>,
    ) {
        self.peermgr
            .peer_disconnected(addr, &mut self.addrmgr, reason);
    }

    fn tick(&mut self, local_time: LocalTime) {
        trace!("Received tick");

        self.clock.set(local_time);
    }

    fn timer_expired(&mut self) {
        trace!("Received wake");

        self.invmgr.timer_expired(&self.tree);
        self.syncmgr.timer_expired(&self.tree);
        self.pingmgr.timer_expired();
        self.addrmgr.timer_expired();
        self.peermgr.timer_expired(&mut self.addrmgr);
        self.cbfmgr.timer_expired(&self.tree);
        self.bfmgr.timer_expired(&self.tree);

        #[cfg(not(test))]
        let local_time = self.clock.local_time();
        #[cfg(not(test))]
        if local_time - self.last_tick >= LocalDuration::from_secs(10) {
            let (tip, _) = self.tree.tip();
            let height = self.tree.height();
            let best = self
                .syncmgr
                .best_height()
                .unwrap_or_else(|| self.tree.height());
            let sync = if best > 0 {
                height as f64 / best as f64 * 100.
            } else {
                0.
            };
            let outbound = self.peermgr.negotiated(Link::Outbound).count();
            let inbound = self.peermgr.negotiated(Link::Inbound).count();
            let connecting = self.peermgr.connecting().count();
            let target = self.peermgr.config.target_outbound_peers;
            let max_inbound = self.peermgr.config.max_inbound_peers;
            let addresses = self.addrmgr.len();
            let preferred = self
                .peermgr
                .negotiated(Link::Outbound)
                .filter(|(p, _)| p.services.has(self.peermgr.config.preferred_services))
                .count();

            // TODO: Add cache sizes on disk
            // TODO: Add protocol state(s)
            // TODO: Trim block hash
            // TODO: Add average headers/s or bandwidth

            let mut msg = Vec::new();

            msg.push(format!("tip = {}", tip));
            msg.push(format!("headers = {}/{} ({:.1}%)", height, best, sync));
            msg.push(format!(
                "cfheaders = {}/{}",
                self.cbfmgr.filters.height(),
                height
            ));
            msg.push(format!("inbound = {}/{}", inbound, max_inbound));
            msg.push(format!(
                "outbound = {}/{} ({})",
                outbound, target, preferred,
            ));
            msg.push(format!("connecting = {}/{}", connecting, target));
            msg.push(format!("addresses = {}", addresses));

            log::info!(target: "p2p", "{}", msg.join(", "));

            if self.cbfmgr.rescan.active {
                let rescan = &self.cbfmgr.rescan;
                log::info!(target: "p2p", "{}", rescan.info());
            }
            log::info!(
                target: "p2p",
                "inventory block queue = {}, requested = {}, mempool = {}",
                self.invmgr.received.len(),
                self.invmgr.remaining.len(),
                self.invmgr.mempool.len(),
            );

            self.last_tick = local_time;
        }
    }
}
