//! Bloom bip37 functions.
use std::cmp;
use std::convert::TryFrom;
use std::f64;
use std::hash::Hash;
use std::io::Cursor;
use std::marker::PhantomData;

use bit_vec::BitVec;
use murmur3::murmur3_32;
use rand::{self};

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

impl From<Bloom<u8>> for BloomFilter {
    fn from(b: Bloom<u8>) -> Self {
        Self { content: b.bit_vec.to_bytes(), hashes: b.k_num, tweak: b.tweak, flags: 0 }
    }
}

// modified https://github.com/jedisct1/rust-bloom-filter
/// Bloom filter structure
#[derive(Clone, Debug)]
pub struct Bloom<T: ?Sized> {
    ///
    pub bit_vec: BitVec,
    bitmap_bits: u64,
    k_num: u32,
    tweak: u32,

    _phantom: PhantomData<T>,
}

impl<T: ?Sized> Bloom<T> {
    /// Create a new bloom filter structure.
    /// bitmap_size is the size in bytes (not bits) that will be allocated in
    /// memory items_count is an estimation of the maximum number of items
    /// to store.
    pub fn new(bitmap_size: usize, items_count: usize) -> Self {
        assert!(bitmap_size > 0 && items_count > 0);
        let bitmap_bits = u64::try_from(bitmap_size).unwrap().checked_mul(8u64).unwrap();
        let k_num = Self::optimal_k_num(bitmap_bits, items_count);
        let bitmap = BitVec::from_elem(usize::try_from(bitmap_bits).unwrap(), false);
        let tweak = rand::random(); // default tweak value, can be changed later
        Self { bit_vec: bitmap, bitmap_bits, k_num, tweak, _phantom: PhantomData }
    }

    /// Create a new bloom filter structure.
    /// items_count is an estimation of the maximum number of items to store.
    /// fp_p is the wanted rate of false positives, in ]0.0, 1.0[
    pub fn new_for_fp_rate(items_count: usize, fp_p: f64) -> Self {
        let bitmap_size = Self::compute_bitmap_size(items_count, fp_p);
        Bloom::new(bitmap_size, items_count)
    }

    /// Compute a recommended bitmap size for items_count items
    /// and a fp_p rate of false positives.
    /// fp_p obviously has to be within the ]0.0, 1.0[ range.
    pub fn compute_bitmap_size(items_count: usize, fp_p: f64) -> usize {
        assert!(items_count > 0);
        assert!(fp_p > 0.0 && fp_p < 1.0);
        let log2 = f64::consts::LN_2;
        let log2_2 = log2 * log2;
        ((items_count as f64) * f64::ln(fp_p) / (-8.0 * log2_2)).ceil() as usize
    }

    /// Record the presence of an item.
    pub fn set(&mut self, data: &mut Vec<u8>)
    where
        T: Hash,
    {
        // let mut v = Vec::with_capacity(36_000);
        // let mut v = self.bit_vec.to_bytes();
        // for k in 0..self.k_num {
        //     let index = self.hash(k, data);
        //     let bit_offset = 1 << (7 & index);
        //     v[index as usize >> 3] |= bit_offset;
        // }
        // self.bit_vec = BitVec::from_bytes(&v);
        for k_i in 0..self.k_num {
            let bit_offset = (self.hash(k_i, data) % self.bitmap_bits as u32) as usize;
            self.bit_vec.set(bit_offset, true);
        }
    }

    /// Check if an item is present in the set.
    /// There can be false positives, but no false negatives.
    pub fn check(&self, data: &mut Vec<u8>) -> bool
    where
        T: Hash,
    {
        for k_i in 0..self.k_num {
            let bit_offset = (self.hash(k_i, data) as u64 % self.bitmap_bits) as usize;

            if self.bit_vec.get(bit_offset).unwrap() == false {
                return false;
            }
        }
        true
    }

    /// murmur3 hash
    pub fn hash(&self, hashes: u32, data: &mut Vec<u8>) -> u32 {
        let mut cursor = Cursor::new(data);
        let h = murmur3_32(&mut cursor, (hashes as u64 * 0xFBA4C795 + self.tweak as u64) as u32)
            .unwrap();
        let modulus: u32 = (self.bit_vec.to_bytes().len() * 8) as u32;
        h % modulus
    }

    fn optimal_k_num(bitmap_bits: u64, items_count: usize) -> u32 {
        let m = bitmap_bits as f64;
        let n = items_count as f64;
        let k_num = (m / n * f64::ln(2.0f64)).ceil() as u32;
        cmp::max(k_num, 1)
    }
}

mod test {
    #[test]
    fn test_bloom2() {
        use super::Bloom;
        // use crate::consensus::Encodable;
        let mut bloom: Bloom<u8> = Bloom::new_for_fp_rate(1000, 0.01);
        let mut vec_a = vec![];
        let mut vec_b = vec![];
        let mut vec_c = vec![];
        let mut vec_d = vec![];
        let mut vec_e = vec![];
        let mut vec_f = vec![];
        let mut vec_g = vec![];
        let mut vec_h = vec![];
        for _ in 0..100 {
            let a = rand::random::<u8>();
            let b = rand::random::<u8>();
            let c = rand::random::<u8>();
            let d = rand::random::<u8>();
            let e = rand::random::<u8>();
            let f = rand::random::<u8>();
            let g = rand::random::<u8>();
            let h = rand::random::<u8>();
            vec_a.push(a);
            vec_b.push(b);
            vec_c.push(c);
            vec_d.push(d);
            vec_e.push(e);
            vec_f.push(f);
            vec_g.push(g);
            vec_h.push(h);
        }
        // // println!("VEC A {:?}", vec_a);
        // println!("bit vec unset {:?}", bloom.bit_vec);

        // bloom.set(&mut vec_a);
        // println!("bit vec set a {:?}", bloom.bit_vec);

        // bloom.set(&mut vec_b);
        // println!("bit vec set b {:?}", bloom.bit_vec);

        bloom.set(&mut vec_a);
        bloom.set(&mut vec_b);
        bloom.set(&mut vec_c);
        bloom.set(&mut vec_d);

        assert!(bloom.check(&mut vec_a));
        assert!(bloom.check(&mut vec_b));
        assert!(bloom.check(&mut vec_c));
        assert!(bloom.check(&mut vec_d));
        assert!(!bloom.check(&mut vec_e));
        assert!(!bloom.check(&mut vec_f));
        assert!(!bloom.check(&mut vec_g));
        assert!(!bloom.check(&mut vec_h));
        // assert_eq!(buf, vec![3, 1, 27, 24, 8, 0, 0, 0, 243, 224, 1, 0, 1])
        // println!("{:?}", bloom);
    }
}
