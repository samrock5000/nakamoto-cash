// //! Bloom Filter Manager.
// //!
// //! Manages BIP 37 compact block filter sync.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::{Bound, RangeInclusive};

// use nakamoto_common::bitcoin::util::bloom::BloomFilter;
use nakamoto_common::bitcoin_hashes::Hash;
use thiserror::Error;

mod rescan;
use super::bloom_cache::FilterCache;
use super::output::{Io, Outbox};
use super::Event;
use super::{DisconnectReason, Link, Locators, PeerId};

use nakamoto_common::bitcoin::network::constants::ServiceFlags;
use nakamoto_common::bitcoin::network::message::NetworkMessage;
use nakamoto_common::bitcoin::network::message_blockdata::Inventory;
use nakamoto_common::bitcoin::network::message_bloom::FilterLoad;
use nakamoto_common::bitcoin::Txid;
use nakamoto_common::block::time::{Clock, LocalDuration, LocalTime};
use nakamoto_common::block::tree::{BlockReader, BlockTree};
use nakamoto_common::block::{BlockHash, Height};
use nakamoto_common::collections::{AddressBook, HashMap};
use nakamoto_common::source;
use rescan::Rescan;

/// Idle timeout.
pub const IDLE_TIMEOUT: LocalDuration = LocalDuration::from_secs(60);
/// How long to wait for a request, eg. `getheaders` to be fulfilled.
pub const REQUEST_TIMEOUT: LocalDuration = LocalDuration::from_secs(30);
/// Services required from peers for header sync.
pub const REQUIRED_SERVICES: ServiceFlags = ServiceFlags::BLOOM;
/// Filter cache capacity in bytes.
pub const DEFAULT_FILTER_CACHE_SIZE: usize = 1024 * 1024 * 4; // 1 MB.

/// State of a bloom filter peer.
#[derive(Debug, Clone)]
pub struct Peer {
    has_filter: bool,
    // last_active: Option<LocalTime>,
    // last_asked: Option<Locators>,
    // height: Height,
    // preferred: bool,
    // tip: BlockHash,
    // link: Link,
}

/// What to do if a timeout for a peer is received.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OnTimeout {
    /// Disconnect peer on timeout.
    Disconnect,
    /// Do nothing on timeout.
    Ignore,
    /// Retry with a different peer on timeout.
    Retry(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GetBlocks {
    /// Locators hashes.
    locators: Locators,
    /// Time at which the request was sent.
    sent_at: LocalTime,
    /// What to do if this request times out.
    on_timeout: OnTimeout,
}

/// An error from attempting to get compact filters.
#[derive(Error, Debug)]
pub enum GetMerkleBlocksError {
    /// The specified range is invalid, eg. it is out of bounds.
    #[error("the specified range is invalid")]
    InvalidRange,
    /// Not connected to any bloom filter peer.
    #[error("not connected to any peer with bloom filters support")]
    NotConnected,
    // #[error("peer already sent blocks")]
    // AlreadyAsked,
}

/// A bloom filter manager.
#[derive(Debug)]
pub struct BloomManager<C> {
    /// Rescan state.
    pub rescan: Rescan,

    clock: C,
    /// Sync-specific peer state.
    peers: AddressBook<PeerId, Peer>,
    /// The last time we idled.
    last_idle: Option<LocalTime>,
    /// State-machine output.
    outbox: Outbox,
    /// block-In flight
    blocks_inflight: HashMap<PeerId, GetBlocks>,
    /// How long to wait for a response from a peer.
    request_timeout: LocalDuration,
    /// transactions matched
    matches: VecDeque<Txid>,
}

impl<C> Iterator for BloomManager<C> {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        self.outbox.next()
    }
}

impl<C: Clock> BloomManager<C> {
    pub fn new(rng: fastrand::Rng, clock: C) -> Self {
        let peers = AddressBook::new(rng.clone());
        let rescan = Rescan::new(DEFAULT_FILTER_CACHE_SIZE);
        let blocks_inflight = HashMap::with_hasher(rng.into());
        let matches: VecDeque<Txid> = VecDeque::new();
        Self {
            rescan,
            clock,
            peers,
            last_idle: None,
            outbox: Outbox::default(),
            blocks_inflight,
            request_timeout: REQUEST_TIMEOUT,
            matches,
        }
    }
    pub fn idle<T: BlockReader>(&mut self, tree: &T) {
        _ = tree;
        let now = self.clock.local_time();

        if now - self.last_idle.unwrap_or_default() >= IDLE_TIMEOUT {
            self.last_idle = Some(now);
            self.outbox.set_timer(IDLE_TIMEOUT);
        }
    }
    /// Initialize the bloom manager.
    pub fn initialize<T: BlockReader>(&mut self, tree: &T) {
        self.idle(tree);
    }
    /// Event received.
    pub fn received_event<T: BlockTree>(&mut self, event: Event, tree: &mut T) {
        match event {
            Event::PeerNegotiated {
                addr,
                link,
                services,
                height,
                ..
            } => {
                self.peer_negotiated(addr, height, services, link, tree);
            }
            Event::MerkleBlockProcessed {
                // merkle_block,
                // height,
                // matches,
                // matched,
                // cached,
                ..
            } => {}
            Event::PeerDisconnected { addr, .. } => {
                self.unregister(&addr);
            }

            Event::PeerLoadedBloomFilter { .. } => {
                // self.send_bloom_filter(filter);
            }
            Event::LoadBloomFilter { peers, filter, all } => match all {

                true => self.send_bloom_filter_all_connected(filter,peers),
                _ => self.outbox.send_bloom_filter_load(&peers[0], filter),
            },
            Event::BlockHeadersSynced { .. } => {}
            // Event::ReceivedMerkleBlock { height, .. } => {}
            Event::MessageReceived { from, message } => match message.as_ref() {
                NetworkMessage::MerkleBlock(block) => {
                    _ = from;
                    if let Some((height, _)) = tree.get_block(&block.header.block_hash()) {
                        let event = Event::ReceivedMerkleBlock {
                            height,
                            merkle_block: block.clone(),
                        };
                        self.outbox.event(event);
                    }
                }
                NetworkMessage::Tx(tx) => {
                    let txid = tx.txid();
                    if self.matches.contains(&txid) {
                        self.matches.pop_front();
                    }
                    self.outbox.event(Event::ReceivedMatchedTx {
                        transaction: tx.to_owned(),
                    });
                }

                _ => {}
            },
            _ => {}
        }
    }
    /// Unregister a peer.
    fn unregister(&mut self, id: &PeerId) {
        // self.inflight.remove(id);
        self.peers.remove(id);
    }

    /// Called when a new peer was negotiated.
    fn peer_negotiated<T: BlockReader>(
        &mut self,
        addr: PeerId,
        height: Height,
        services: ServiceFlags,
        link: Link,
        tree: &T,
    ) {
        _ = tree;
        _ = height;
        _ = addr;
        if link.is_outbound() && !services.has(REQUIRED_SERVICES) {
            return;
        }
        self.register(addr);
    }

    /// Register a new peer.
    fn register(
        &mut self,
        addr: PeerId,
        // height: Height,
        // preferred: bool,
        // link: Link,
    ) {
        self.peers.insert(addr, Peer { has_filter: false });
    }
    /// send a bloom filter to all connected peers
    pub fn send_bloom_filter_all_connected(&mut self, filter: FilterLoad, peers: Vec<PeerId>) {
        for peer in peers.iter() {
            self.outbox.send_bloom_filter_load(peer, filter.clone())
        }
    }
    /// get bloom filter unset connected peers
    pub fn get_peers_not_filter_loaded(&mut self) -> Vec<SocketAddr> {
        let mut peers_set: Vec<SocketAddr> = Vec::new();

        for peer in self.peers.iter() {
            if !peer.1.has_filter {
                let peer = *peer.0;
                peers_set.push(peer);
            }
        }
        peers_set
    }
    /// A tick was received.
    pub fn timer_expired<T: BlockReader>(&mut self, _tree: &T) {
        let local_time = self.clock.local_time();
        let timeout = self.request_timeout;
        let timed_out = self
            .blocks_inflight
            .iter()
            .filter_map(|(peer, req)| {
                if local_time - req.sent_at >= timeout {
                    Some((*peer, req.on_timeout, req.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (peer, on_timeout, _req) in timed_out {
            self.blocks_inflight.remove(&peer);

            match on_timeout {
                OnTimeout::Ignore => {
                    // It's likely that the peer just didn't have the requested header.
                }
                OnTimeout::Retry(0) | OnTimeout::Disconnect => {
                    self.outbox
                        .disconnect(peer, DisconnectReason::PeerTimeout("getmerkleblocks"));
                    // sync = true;
                }
                OnTimeout::Retry(_n) => {
                    // if let Some((addr, _)) = self.peers.sample_with(|a, p| {
                    //     // TODO: After the first retry, it won't be a request candidate anymore,
                    //     // since it will have `last_asked` set?
                    //     *a != peer && self.is_request_candidate(a, p, &req.locators.0)
                    // }) {
                    //     let addr = *addr;
                    //     self.request_blocks(addr, req.locators, timeout, OnTimeout::Retry(n - 1));
                    // }
                }
            }
        }
    }
    pub fn get_mempool(&mut self) {
        if let Some(x) = self.peers.sample() {
            self.outbox.get_mempool(&x.0);
        }
    }

    pub fn get_merkle_blocks<T: BlockReader>(
        &mut self,
        range: RangeInclusive<Height>,
        tree: &T,
    ) -> Result<(), GetMerkleBlocksError> {
        if self.peers.is_empty() {
            return Err(GetMerkleBlocksError::NotConnected);
        }
        if range.is_empty() {
            return Err(GetMerkleBlocksError::InvalidRange);
        }
        // Don't request more than once from the same peer.
        assert!(*range.end() <= tree.height());

        // TODO: Only ask peers synced to a certain height.
        // TODO: use privacy segement.
        // Choose a different peer for each requested range.
        let peers_with_blocks_inflight: Vec<_> = self
            .blocks_inflight
            .iter()
            .map(|(peer_addr, _)| peer_addr)
            .collect();
        let peers_with_no_blocks_inflight = self
            .peers
            .iter()
            .filter(|(addr, _)| !peers_with_blocks_inflight.iter().any(|x| x == addr))
            .map(|(addr, peer)| vec![(addr, peer)])
            .clone();

        for (range, peer) in self
            .rescan
            .requests(range, tree)
            .into_iter()
            .zip(peers_with_no_blocks_inflight.cycle())
        {
            let timeout = self.request_timeout;

            log::debug!(
                target: "p2p",
                "Requested merkle blocks(s) in range {} to {} from peer {}",
                range.start(),
                range.end(),
                peer[0].0,
            );

            let locators: Vec<BlockHash> = tree
                .range(*range.start()..*range.end() + 1)
                .map(|(_height, blockhash)| blockhash)
                .collect();
            let mut bock_request: Vec<Inventory> = Vec::new();
            locators.iter().for_each(|block| {
                bock_request.push(Inventory::FilteredBlock(*block));
            });
            let sent_at = self.clock.local_time();
            let req = GetBlocks {
                locators: (locators.clone(), BlockHash::all_zeros()),
                sent_at,
                on_timeout: OnTimeout::Ignore,
            };
            self.outbox.get_data(*peer[0].0, bock_request);
            self.outbox.set_timer(timeout);
            self.blocks_inflight.to_owned().insert(*peer[0].0, req);
            self.rescan.reset();
        }
        Ok(())
    }
    // /// Called when we receive merkle blocks from a peer.
    // pub fn received_merkle_blocks<T: BlockTree>(
    //     &mut self,
    //     height: &Height,
    //     merkle_block: MerkleBlock,
    //     tree: &mut T,
    // ) {
    //     _ = tree;
    //     self.rescan.received(
    //         *height,
    //         merkle_block.clone(),
    //         merkle_block.header.block_hash(),
    //     );
    // }

    /// Rescan merkle blocks.
    pub fn merkle_scan<T: BlockReader>(
        &mut self,
        start: Bound<Height>,
        end: Bound<Height>,
        // watch: Vec<Script>,
        tree: &T,
    ) /*-> Vec<(Height, BlockHash)>*/
    {
        self.rescan.restart(
            match start {
                Bound::Unbounded => tree.height() + 1,
                Bound::Included(h) => h,
                Bound::Excluded(h) => h + 1,
            },
            match end {
                Bound::Unbounded => None,
                Bound::Included(h) => Some(h),
                Bound::Excluded(h) => Some(h - 1),
            },
            // watch,
        );

        self.outbox.event(Event::MerkleBlockRescanStarted {
            start: self.rescan.start,
            stop: self.rescan.end,
        });

        let height = tree.height();
        let start = self.rescan.start;
        let stop = self
            .rescan
            .end
            // Don't request further than the chain height.
            .map(|h| Height::min(h, height))
            .unwrap_or(height);
        let range = start..=stop;
        // if range.is_empty() {
        //     return vec![];
        // }
        // Start fetching the filters we can.
        match self.get_merkle_blocks(range.clone(), tree) {
            Ok(()) => {}
            Err(GetMerkleBlocksError::NotConnected) => {}
            Err(err) => panic!("{}: Error fetching merkle blocks: {}", source!(), err),
        }
        // When we reset the rescan range, there is the possibility of getting immediate cache
        // hits from `get_cfilters`. Hence, process the filter queue.
        // let (matches, _events, _) = self.rescan.process();

        // matches
    }
}

/// Iterator over height ranges.
struct HeightIterator {
    start: Height,
    stop: Height,
    step: Height,
}

impl Iterator for HeightIterator {
    type Item = RangeInclusive<Height>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.stop {
            let start = self.start;
            let stop = self.stop.min(start + self.step - 1);

            self.start = stop + 1;

            Some(start..=stop)
        } else {
            None
        }
    }
}
