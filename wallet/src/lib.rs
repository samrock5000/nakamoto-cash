//! A TUI Bitcoin wallet.
#![allow(clippy::too_many_arguments)]
pub mod error;
pub mod input;
pub mod logger;
pub mod wallet;

use std::path::Path;
use std::{io, net, thread};

use nakamoto_common::bitcoin::network::message_bloom::{BloomFlags, FilterLoad};
use nakamoto_common::bitcoin::util::bloom::BloomFilter;
use nakamoto_common::bitcoin_hashes::hex::FromHex;
use nakamoto_common::bloom::store::cache::PrivacySegment;
use nakamoto_common::collections::HashMap;
use termion::raw::IntoRawMode;
use termion::screen::IntoAlternateScreen;

use nakamoto_client::chan;
use nakamoto_client::handle::Handle;
use nakamoto_client::Network;
use nakamoto_client::{Client, Config};
use nakamoto_common::bitcoin::util::bip32::DerivationPath;
use nakamoto_common::block::Height;

use crate::error::Error;
use crate::wallet::Db;
use crate::wallet::Hw;
use crate::wallet::Wallet;

/// The network reactor we're going to use.
type Reactor = nakamoto_net_poll::Reactor<net::TcpStream>;

/// Entry point for running the wallet.
pub fn run(
    wallet: &Path,
    birth: Height,
    hd_path: DerivationPath,
    network: Network,
    connect: Vec<net::SocketAddr>,
    offline: bool,
) -> Result<(), Error> {
    let mut script_hash = Vec::from_hex("347eeb9896b64a484d1019a16075c194a17e6081").unwrap();
    // Vec::from_hex("64462479fb3bf5b307ab42123dea68d9ec6db353").unwrap();
    // Vec::from_hex("7dcc5bd98ad7f437957c28d4d0312d91818d1d236531b5ae78e59e10b9610155").unwrap();
    // Vec::from_hex("84487d5b5448dcb272921965eebb266728b25853").unwrap();

    let mut bf = BloomFilter::new(1000, 0.0001, 987987, 0);
    bf.insert(&mut script_hash);
    // let data = bf.content;

    // let bloom_filters = FilterLoad {
    //     filter: data,
    //     hash_funcs: bf.hashes,
    //     tweak: bf.tweak,
    //     flags: match bf.flags {
    //         0 => BloomFlags::None,
    //         1 => BloomFlags::All,
    //         2 => BloomFlags::PubkeyOnly,
    //         _ => BloomFlags::None,
    //     },
    // };
    let privacy_segment = PrivacySegment {
        filter: bf,
        ..Default::default()
    };
    let mut bf_map = HashMap::with_hasher(fastrand::Rng::new().into());
    bf_map.insert(0, privacy_segment);
    let cfg = Config {
        network,
        connect,
        listen: vec![], // Don't listen for incoming connections.
        bloom_segments: bf_map,
        ..Config::default()
    };

    // Create a new client using `Reactor` for networking.
    let client = Client::<Reactor>::new()?;
    let handle = client.handle();
    let client_recv = handle.events();
    let (loading_send, loading_recv) = chan::unbounded();

    log::info!("Opening wallet file `{}`..", wallet.display());

    let db = Db::open(wallet)?;
    let hw = Hw::new(hd_path);

    let (inputs_tx, inputs_rx) = crossbeam_channel::unbounded();
    let (exit_tx, exit_rx) = crossbeam_channel::bounded(1);
    let (signals_tx, signals_rx) = crossbeam_channel::unbounded();

    log::info!("Spawning client threads..");

    // Start the UI loop in the background.
    let t1 = thread::spawn(|| input::run(inputs_tx, exit_rx));
    // Start the signal handler thread.
    let t2 = thread::spawn(|| input::signals(signals_tx));
    // Start the network client in the background.
    let t3 = thread::spawn(move || {
        if offline {
            Ok(())
        } else {
            client.load(cfg, loading_send)?.run()
        }
    });

    log::info!("Switching to alternative screen..");

    let stdout = io::stdout().into_raw_mode()?;
    let term = termion::cursor::HideCursor::from(termion::input::MouseTerminal::from(stdout))
        .into_alternate_screen()?;

    // Run the main wallet loop. This will block until the wallet exits.
    log::info!("Running main wallet loop..");
    Wallet::new(handle.clone(), network, db, hw).run(
        birth,
        inputs_rx,
        signals_rx,
        loading_recv,
        client_recv,
        offline,
        term,
    )?;

    // Tell other threads that they should exit.
    log::info!("Exiting..");
    exit_tx.send(()).unwrap();

    // Shutdown the client, since the main loop exited.
    log::info!("Shutting down client..");
    handle.shutdown()?;

    t1.join().unwrap()?;
    t2.join().unwrap()?;
    t3.join().unwrap()?;

    Ok(())
}
