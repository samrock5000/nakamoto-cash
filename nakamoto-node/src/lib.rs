pub mod error;
pub mod handle;
pub mod node;

use std::io;
use std::net;
use std::path::Path;
use std::time::SystemTime;

use nakamoto_chain as chain;
use nakamoto_chain::block::cache::BlockCache;
use nakamoto_chain::block::store::{self, Store};
use nakamoto_chain::block::time::AdjustedTime;
use nakamoto_p2p as p2p;
use nakamoto_p2p::address_book::AddressBook;
use nakamoto_p2p::protocol::bitcoin::Config;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    P2p(#[from] p2p::error::Error),
    #[error(transparent)]
    Chain(#[from] chain::block::tree::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Error loading address book: {0}")]
    AddressBook(io::Error),
    #[error(transparent)]
    BlockStore(#[from] store::Error),
}

pub fn run(connect: &[net::SocketAddr], listen: &[net::SocketAddr]) -> Result<(), Error> {
    log::info!("Initializing daemon..");

    let cfg = Config::default();
    let genesis = cfg.network.genesis();
    let params = cfg.network.params();

    log::info!("Genesis block hash is {}", cfg.network.genesis_hash());

    let path = Path::new("headers.db");
    let mut store = match store::File::create(path, genesis) {
        Err(store::Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
            log::info!("Found existing store {:?}", path);
            store::File::open(path, genesis)?
        }
        Err(err) => panic!(err.to_string()),
        Ok(store) => {
            log::info!("Initializing new block store {:?}", path);
            store
        }
    };
    if store.check().is_err() {
        log::warn!("Corruption detected in store, healing..");
        store.heal()?; // Rollback store to the last valid header.
    }
    log::info!("Store height = {}", store.height()?);
    log::info!("Loading blocks from store..");

    let local_time = SystemTime::now().into();
    let checkpoints = cfg.network.checkpoints().collect::<Vec<_>>();
    let clock = AdjustedTime::<net::SocketAddr>::new(local_time);
    let cache = BlockCache::from(store, params, &checkpoints)?;

    let address_book = if connect.is_empty() {
        match AddressBook::load("peers") {
            Ok(peers) if peers.is_empty() => {
                log::info!("Address book is empty. Trying DNS seeds..");
                AddressBook::bootstrap(cfg.network.seeds(), cfg.network.port())?
            }
            Ok(peers) => peers,
            Err(err) => {
                return Err(Error::AddressBook(err));
            }
        }
    } else {
        AddressBook::from(connect)?
    };

    log::info!("{} peer(s) found..", address_book.len());
    log::debug!("{:?}", address_book);

    let protocol = p2p::protocol::Bitcoin::new(cache, address_book, clock, cfg);
    let mut reactor = p2p::reactor::poll::Reactor::new()?;

    if listen.is_empty() {
        reactor.run(protocol, &[([0, 0, 0, 0], cfg.port()).into()])?;
    } else {
        reactor.run(protocol, listen)?;
    }

    Ok(())
}
