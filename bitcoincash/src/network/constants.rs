// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network constants.
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network.
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoincash::network::constants::Network;
//! use bitcoincash::consensus::encode::serialize;
//!
//! let network = Network::Bitcoin;
//! let bytes = serialize(&network.disk_magic());
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD9]);
//! ```

use core::{fmt, ops, convert::From};

use crate::io;
use crate::consensus::encode::{self, Encodable, Decodable};
use crate::internal_macros::user_enum;

/// Version of the protocol as appearing in network message headers
/// This constant is used to signal to other peers which features you support.
/// Increasing it implies that your software also supports every feature prior to this version.
/// Doing so without support may lead to you incorrectly banning other peers or other peers banning you.
/// These are the features required for each version:
/// 70016 - Support receiving `wtxidrelay` message between `version` and `verack` message
/// 70015 - Support receiving invalid compact blocks from a peer without banning them
/// 70014 - Support compact block messages `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn`
/// 70013 - Support `feefilter` message
/// 70012 - Support `sendheaders` message and announce new blocks via headers rather than inv
/// 70011 - Support NODE_BLOOM service flag and don't support bloom filter messages if it is not set
/// 70002 - Support `reject` message
/// 70001 - Support bloom filter messages `filterload`, `filterclear` `filteradd`, `merkleblock` and FILTERED_BLOCK inventory type
/// 60002 - Support `mempool` message
/// 60001 - Support `pong` message and nonce in `ping` message
pub const PROTOCOL_VERSION: u32 = 70001;

user_enum! {
    /// The cryptocurrency to act on
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
    pub enum Network {
        /// Classic Bitcoin
        Bitcoin <-> "bitcoin",
        /// Bitcoin's testnet
        Testnet <-> "testnet",
        /// Bitcoin's regtest
        Regtest <-> "regtest",
        /// Bitcoin Cash testnet4
        Testnet4 <-> "testnet4",
        /// Bitcoin Cash scalenet
        Scalenet <-> "scalenet",
        /// Bitcoin Cash chipnet
        Chipnet <-> "chipnet"
    }
}

impl Network {
    /// Creates a `Network` from the disk magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoincash::network::constants::Network;
    ///
    /// assert_eq!(Some(Network::Bitcoin), Network::from_disk_magic(0xD9B4BEF9));
    /// assert_eq!(None, Network::from_disk_magic(0xFFFFFFFF));
    /// ```
    pub fn from_disk_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xD9B4BEF9 => Some(Network::Bitcoin),
            0x0709110B => Some(Network::Testnet),
            0xDAB5BFFA => Some(Network::Regtest),
            // Chipnet also shares this value,
            // so it cannot be identified by disk magic.
            0x92A722CD => Some(Network::Testnet4),
            0xC42DC2BA => Some(Network::Scalenet),
            _ => None
        }
    }


    /// Creates a `Network` from the net magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoincash::network::constants::Network;
    ///
    /// assert_eq!(Some(Network::Bitcoin), Network::from_net_magic(0xE8F3E1E3));
    /// assert_eq!(None, Network::from_net_magic(0xFFFFFFFF));
    /// ```
    pub fn from_net_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xE8F3E1E3 => Some(Network::Bitcoin),
            0xF4F3E5F4 => Some(Network::Testnet),
            0xFABFB5DA => Some(Network::Regtest),
            // Chipnet also shares this value,
            // so it cannot be identified by disk magic.
            0xAFDAB7E2 => Some(Network::Testnet4),
            0xA2E1AFC3 => Some(Network::Scalenet),
            _ => None
        }
    }

    /// Return the disk magic bytes
    ///
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoincash::network::constants::Network;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.disk_magic(), 0xD9B4BEF9);
    /// ```
    pub fn disk_magic(self) -> u32 {
        // Note: any new entries here must be added to `from_disk_magic` above
        match self {
            Network::Bitcoin => 0xD9B4BEF9,
            Network::Testnet => 0x0709110B,
            Network::Regtest => 0xDAB5BFFA,
            Network::Testnet4 | Network::Chipnet => 0x92A722CD,
            Network::Scalenet => 0xC42DC2BA,
        }
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoincash::network::constants::Network;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.net_magic(), 0xE8F3E1E3);
    /// ```
    pub fn net_magic(self) -> u32 {
        // Note: any new entries here must be added to `from_net_magic` above
        match self {
            Network::Bitcoin => 0xE8F3E1E3,
            Network::Testnet => 0xF4F3E5F4,
            Network::Regtest => 0xFABFB5DA,
            Network::Testnet4 | Network::Chipnet => 0xAFDAB7E2,
            Network::Scalenet => 0xA2E1AFC3,
        }
    }
}

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: ServiceFlags = ServiceFlags(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request.  Bitcoin
    /// Core does not support this but a patch set called Bitcoin XT does.
    /// See BIP 64 for details on how this is implemented.
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Bitcoin
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);
    ///  Node supports Bitcoin Cash/
    pub const NODE_BITCOIN_CASH: ServiceFlags = ServiceFlags(1 << 5);

    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP157 and BIP158 for details on how this is implemented.
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP159 for details on how this is implemented.
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    pub fn add(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 |= other.0;
        *self
    }

    /// Remove [ServiceFlags] from this.
    ///
    /// Returns itself.
    pub fn remove(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 ^= other.0;
        *self
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(self, flags: ServiceFlags) -> bool {
        (self.0 | flags.0) == self.0
    }

    /// Get the integer representation of this [ServiceFlags].
    #[deprecated(since = "0.29.0", note = "use to_u64 instead")]
    pub fn as_u64(self) -> u64 {
        self.to_u64()
    }

    /// Gets the integer representation of this [`ServiceFlags`].
    pub fn to_u64(self) -> u64 {
        self.0
    }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = *self;
        if flags == ServiceFlags::NONE {
            return write!(f, "ServiceFlags(NONE)");
        }
        let mut first = true;
        macro_rules! write_flag {
            ($f:ident) => {
                if flags.has(ServiceFlags::$f) {
                    if !first {
                        write!(f, "|")?;
                    }
                    first = false;
                    write!(f, stringify!($f))?;
                    flags.remove(ServiceFlags::$f);
                }
            }
        }
        write!(f, "ServiceFlags(")?;
        write_flag!(NETWORK);
        write_flag!(GETUTXO);
        write_flag!(BLOOM);
        write_flag!(NODE_BITCOIN_CASH);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        // If there are unknown flags left, we append them in hex.
        if flags != ServiceFlags::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self {
        ServiceFlags(f)
    }
}

impl From<ServiceFlags> for u64 {
    fn from(flags: ServiceFlags) -> Self {
        flags.0
    }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.add(rhs);
    }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self {
        self.remove(rhs)
    }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.remove(rhs);
    }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{Network, ServiceFlags};
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_test() {
        assert_eq!(
            serialize(&Network::Bitcoin.disk_magic()),
            &[0xf9, 0xbe, 0xb4, 0xd9]
        );
        assert_eq!(
            serialize(&Network::Testnet.disk_magic()),
            &[0x0b, 0x11, 0x09, 0x07]
        );
        assert_eq!(
            serialize(&Network::Regtest.disk_magic()),
            &[0xfa, 0xbf, 0xb5, 0xda]
        );

        assert_eq!(
            deserialize(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(),
            Some(Network::Bitcoin.disk_magic())
        );
        assert_eq!(
            deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(),
            Some(Network::Testnet.disk_magic())
        );
        assert_eq!(
            deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(),
            Some(Network::Regtest.disk_magic())
        );
    }

    #[test]
    fn string_test() {
        assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");

        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(flags2.has(*f), *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO);
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!("ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)", flag.to_string());
    }
}
