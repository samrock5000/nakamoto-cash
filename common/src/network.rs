//! Bitcoin peer network. Eg. *Mainnet*.
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::params::Params;
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::network::constants::ServiceFlags;
use bitcoincash as bitcoin;
use std::str::FromStr;

use bitcoin_hashes::sha256d;

use crate::block::Height;

/// Peer services supported by nakamoto.
#[derive(Debug, Copy, Clone)]
pub enum Services {
    /// Peers with compact filter support.
    All,
    /// Peers with only block support.
    Chain,
}

impl From<Services> for ServiceFlags {
    fn from(value: Services) -> Self {
        match value {
            Services::All => Self::COMPACT_FILTERS | Self::NETWORK,
            Services::Chain => Self::NETWORK,
        }
    }
}

impl Default for Services {
    fn default() -> Self {
        Services::All
    }
}

/// Bitcoin peer network.
#[derive(Debug, Copy, Clone)]
pub enum Network {
    /// Bitcoin Mainnet.
    Mainnet,
    /// Bitcoin Testnet.
    Testnet,
    /// Bitcoin regression test net.
    Regtest,
    /// Bitcoin signet.
    Chipnet,
}

impl Default for Network {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" | "bitcoin" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            "chipnet" => Ok(Self::Chipnet),
            _ => Err(format!("invalid network specified {:?}", s)),
        }
    }
}

impl From<Network> for bitcoin::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => Self::Bitcoin,
            Network::Testnet => Self::Testnet,
            Network::Regtest => Self::Regtest,
            Network::Chipnet => Self::Chipnet,
        }
    }
}

impl From<bitcoin::Network> for Network {
    fn from(value: bitcoin::Network) -> Self {
        match value {
            bitcoin::Network::Bitcoin => Self::Mainnet,
            bitcoin::Network::Testnet => Self::Testnet,
            bitcoin::Network::Chipnet => Self::Chipnet,
            bitcoin::Network::Regtest => Self::Regtest,
            _ => Self::Mainnet,
        }
    }
}

impl Network {
    /// Return the default listen port for the network.
    pub fn port(&self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::Regtest => 18334,
            Network::Chipnet => 48333,
        }
    }

    /// Blockchain checkpoints.
    pub fn checkpoints(&self) -> Box<dyn Iterator<Item = (Height, BlockHash)>> {
        use crate::block::checkpoints;

        let iter = match self {
            Network::Mainnet => checkpoints::MAINNET,
            Network::Testnet => checkpoints::TESTNET,
            Network::Regtest => checkpoints::REGTEST,
            Network::Chipnet => checkpoints::CHIPNET,
        }
        .iter()
        .cloned()
        .map(|(height, hash)| {
            let hash = BlockHash::from_hex(hash).unwrap();
            (height, hash)
        });

        Box::new(iter)
    }

    /// Return the short string representation of this network.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
            Network::Chipnet => "chipnet",
        }
    }

    /// DNS seeds. Used to bootstrap the client's address book.
    pub fn seeds(&self) -> &[&str] {
        match self {
            Network::Mainnet => &[
                "seed.flowee.cash",
                "seed-bch.bitcoinforks.org",
                "btccash-seeder.bitcoinunlimited.info",
                "seed.bchd.cash",
                "seed.bch.loping.net",
                "dnsseed.electroncash.de",
                "bchseed.c3-soft.com",
                "bch.bitjson.com",
            ],
            Network::Testnet => &[
                //TODO
            ],
            Network::Regtest => &[], // No seeds
            Network::Chipnet => &["chipnet.bitjson.com"],
        }
    }
}

impl Network {
    /// Get the genesis block header.
    ///
    /// ```
    /// use nakamoto_common::network::Network;
    ///
    /// let network = Network::Mainnet;
    /// let genesis = network.genesis();
    ///
    /// assert_eq!(network.genesis_hash(), genesis.block_hash());
    /// ```
    pub fn genesis(&self) -> BlockHeader {
        self.genesis_block().header
    }

    /// Get the genesis block.
    pub fn genesis_block(&self) -> Block {
        use bitcoin::blockdata::constants;

        constants::genesis_block((*self).into())
    }

    /// Get the hash of the genesis block of this network.
    pub fn genesis_hash(&self) -> BlockHash {
        use crate::block::genesis;
        use bitcoin_hashes::Hash;

        let hash = match self {
            Self::Mainnet => genesis::MAINNET,
            Self::Testnet => genesis::TESTNET,
            Self::Regtest => genesis::REGTEST,
            Self::Chipnet => genesis::CHIPNET,
        };
        BlockHash::from_hash(
            sha256d::Hash::from_slice(hash)
                .expect("the genesis hash has the right number of bytes"),
        )
    }

    /// Get the consensus parameters for this network.
    pub fn params(&self) -> Params {
        Params::new((*self).into())
    }

    /// Get the network magic number for this network.
    pub fn magic(&self) -> u32 {
        bitcoin::Network::from(*self).net_magic()
    }
}
