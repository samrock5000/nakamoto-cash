//! BIP32 implementation.

use crate::consensus::{Decodable, Encodable};
use murmur3::murmur3_32;
use rand::{self, thread_rng, Rng};
use std::convert::TryInto;

use std::{
    f32::consts::LN_2,
    io::{Cursor, Write},
};
///
pub const LN2_SQUARED: f32 = std::f32::consts::LN_2 * std::f32::consts::LN_2;
///
pub const MAX_FILTER_HASH_FUNCS: u32 = 50;
///
pub const MAX_FILTER_SIZE: u32 = 36000;
///
pub const MIN_HASH_FUNCS: u32 = 1;

/// min
pub fn min_uint32(a: u32, b: u32) -> u32 {
    a.min(b)
}

// #[repr(u8)]
// #[derive(Debug)]
// enum BloomUpdate {
//     BloomUpdateNone = 0,
//     BloomUpdateAll = 1,
//     BloomUpdateP2PkOnly = 2,
// }

/// BIP37 BloomFilter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    /// the filter
    pub content: Vec<u8>,
    /// how many hash functions to apply
    pub hashes: u32,
    /// nonce seed
    pub tweak: u32,
    /// Bloom update flag
    pub flags: u8,
}

impl BloomFilter {
    /// Create a new bloom filter
    pub fn new(elements: u32, false_positive_rate: f64, tweak: u32, flags: u8) -> BloomFilter {
        let size = -1.0 / LN2_SQUARED as f64 * elements as f64 * f64::ln(false_positive_rate);
        // let mut filter_size = get_size(elements, false_positive_rate);
        let mut filter_size = (size / 8f64).floor();

        let max = MAX_FILTER_SIZE * 8;
        let mut filter_data = Vec::new();

        if filter_size > max as f64 {
            filter_size = max as f64;
        }
        for _ in 0..filter_size as u8 {
            filter_data.push(0);
        }
        let mut nhashes = filter_data.len() as f32 * 8f32 / elements as f32 * LN_2;
        if nhashes > MAX_FILTER_HASH_FUNCS as f32 {
            nhashes = MAX_FILTER_HASH_FUNCS as f32;
        }
        if nhashes < MIN_HASH_FUNCS as f32 {
            nhashes = MIN_HASH_FUNCS as f32;
        }
        BloomFilter { content: filter_data, hashes: nhashes as u32, tweak, flags }
    }
    /// returns a default bloom filter.
    // TODO use optimized setting
    pub fn default() -> Self {
        let mut rng = thread_rng();
        let tweak: u32 = rng.gen();
        let content = Vec::with_capacity(10000);
        Self { content, hashes: 6, tweak, flags: 0 }
    }
    /// murmur3 hash
    pub fn hash(&self, hashes: u32, data: &mut Vec<u8>) -> u32 {
        let mut cursor = Cursor::new(data);
        let x = murmur3_32(&mut cursor, (hashes as u64 * 0xFBA4C795 + self.tweak as u64) as u32);
        let modulus: u32 = (self.content.len() * 8).try_into().unwrap();
        x % modulus
    }
    /// add item to filter
    pub fn insert(&mut self, data: &mut Vec<u8>) {
        for i in 0..self.hashes {
            let index = self.hash(i, data);
            let position = 1 << (7 & index);
            self.content[index as usize >> 3] |= position;
        }
    }
    /// Checks if filter cointains the data element;
    pub fn cointains(&mut self, data: &mut Vec<u8>) -> bool {
        if self.hashes == 0 {
            return false;
        }
        for i in 0..self.hashes {
            let index = self.hash(i, data) as usize;
            if (self.content[index >> 3] & (1 << (7 & index)) == 0) {
                return false;
            }
        }
        true
    }
}

impl Encodable for BloomFilter {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.content.consensus_encode(w)?;
        len += self.hashes.consensus_encode(w)?;
        len += self.tweak.consensus_encode(w)?;
        len += self.flags.consensus_encode(w)?;
        Ok(len)
    }
}
impl Decodable for BloomFilter {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, crate::consensus::encode::Error> {
        let content: Vec<u8> = Decodable::consensus_decode(r)?;
        let hashes: u32 = Decodable::consensus_decode(r)?;
        let tweak: u32 = Decodable::consensus_decode(r)?;
        let flags: u8 = Decodable::consensus_decode(r)?;
        Ok(BloomFilter { content, flags, hashes, tweak })
    }
}

/// number of hashes applied
pub fn get_hash_amount(elements: u32, false_positive_rate: f64) -> u32 {
    let data_len = get_size(elements, false_positive_rate);
    let n = data_len as f64 * 8.0 / elements as f64 * std::f32::consts::LN_2 as f64;
    u32::max(1, min_uint32(n as u32, MAX_FILTER_HASH_FUNCS))
}
/// unused in impl for now
pub fn get_size(elements: u32, false_positive_rate: f64) -> u32 {
    //res = -(elemebts * lg(p)) / (lg(2)^2)
    let m0 = -1.0 / LN2_SQUARED as f64 * elements as f64 * false_positive_rate.log10();
    let m1 = MAX_FILTER_SIZE * 8;
    min_uint32(m0 as u32, m1 as u32) / 8
}
/// TODO
pub fn optimal_size() -> BloomFilter {
    !todo!()
}
/// TODO
pub fn optimal_hash_amount() -> BloomFilter {
    !todo!()
}

mod test {

    #[test]
    fn test_bloom() {
        use super::BloomFilter;
        use crate::consensus::Encodable;
        use bitcoin_hashes::hex::FromHex;

        let mut d = Vec::from_hex("84487d5b5448dcb272921965eebb266728b25853").unwrap();
        let mut x = BloomFilter::new(2, 0.001, 123123, 1);

        let mut buf = Vec::new();
        x.insert(&mut d);
        _ = x.consensus_encode(&mut buf);
        assert_eq!(buf, vec![3, 1, 27, 24, 8, 0, 0, 0, 243, 224, 1, 0, 1]);
        let mut data = Vec::from_hex("deadbeef").unwrap();
        let mut more_data = Vec::from_hex("84487d5b5448dcb272921965eebb266728b25853ef").unwrap();
        let should_be_false = x.cointains(&mut data);
        let should_be_true = x.cointains(&mut d);
        let should_be_false2 = x.cointains(&mut more_data);
        assert!(!should_be_false);
        assert!(should_be_true);
        assert!(!should_be_false2);
    }
    #[test]
    fn test_bloom2() {
        use super::BloomFilter;
        use crate::consensus::Encodable;
        use bitcoin_hashes::hex::FromHex;

        let mut d = Vec::from_hex("347eeb9896b64a484d1019a16075c194a17e6081").unwrap();
        let mut x = BloomFilter::new(2, 0.001, 123123, 1);

        let mut buf = Vec::new();
        x.insert(&mut d);
        _ = x.consensus_encode(&mut buf);
        // assert_eq!(buf, vec![3, 1, 27, 24, 8, 0, 0, 0, 243, 224, 1, 0, 1])
        println!("{:?}", buf);
    }
}
