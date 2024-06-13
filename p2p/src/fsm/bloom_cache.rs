//! Bloom filter cache.
use std::collections::BTreeMap;
use std::rc::Rc;

use nakamoto_common::bitcoin::consensus::Encodable;
// use nakamoto_common::bitcoin::util::bloom::BloomFilter;
use nakamoto_common::block::{Height, MerkleBlock};

/// Cachable Bloom filter.
#[allow(clippy::len_without_is_empty)]
pub trait Filter: Eq + PartialEq {
    /// Length in bytes of the block filter.
    fn len(&self) -> usize;
}

impl Filter for Rc<MerkleBlock> {
    fn len(&self) -> usize {
        self.consensus_encode(&mut Vec::new()).unwrap()
    }
}

impl Filter for MerkleBlock {
    fn len(&self) -> usize {
        self.consensus_encode(&mut Vec::new()).unwrap()
    }
}

/// An in-memory bloom filter cache with a fixed capacity.
#[derive(Debug)]
pub struct FilterCache<T: Filter> {
    /// Cache.
    cache: BTreeMap<Height, T>,
    /// Cache size in bytes.
    size: usize,
    /// Cache capacity in bytes.
    capacity: usize,
}

impl<T: Filter> Default for FilterCache<T> {
    fn default() -> Self {
        Self {
            cache: BTreeMap::new(),
            size: 0,
            capacity: 0,
        }
    }
}

impl<T: Filter> FilterCache<T> {
    /// Create a new filter cache.
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: BTreeMap::new(),
            size: 0,
            capacity,
        }
    }

    /// Return the size of the cache filters in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the cache capacity in bytes.
    ///
    /// ```
    /// use nakamoto_p2p::fsm::filter_cache::FilterCache;
    /// use nakamoto_common::block::filter::BloomFilter;
    ///
    /// let mut cache = FilterCache::<BloomFilter>::new(some_filter_len);
    /// assert_eq!(cache.capacity(), some_filter_len);
    /// ```
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return the number of filters in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.len() == 0
    }
    /// TODO Doccument
    pub fn push(&mut self, height: Height, filter: T) -> bool {
        assert!(self.size <= self.capacity);
        let size = filter.len();
        if size > self.capacity {
            return false;
        }

        self.cache.insert(height, filter);
        self.size += size;

        while self.size > self.capacity {
            if let Some(height) = self.cache.keys().cloned().next() {
                if let Some(filter) = self.cache.remove(&height) {
                    self.size -= filter.len();
                }
            }
        }
        true
    }
    /// Get the end height of the cache.
    pub fn start(&self) -> Option<Height> {
        self.cache.keys().next().copied()
    }
    /// Iterate over cached filters.
    pub fn end(&self) -> Option<Height> {
        self.cache.keys().next_back().copied()
    }

    /// Iterate over cached filters.
    pub fn iter(&self) -> impl Iterator<Item = (&Height, &T)> {
        self.cache.iter().map(|(h, b)| (h, b))
    }

    /// Iterate over cached heights.
    pub fn heights(&self) -> impl Iterator<Item = Height> + '_ {
        self.cache.keys().copied()
    }
    /// Get a filter in the cache by height.
    pub fn get(&self, height: &Height) -> Option<&T> {
        self.cache.get(height)
    }
    /// Rollback the cache to a certain height. Drops all filters with a height greater
    /// than the given height.
    pub fn rollback(&mut self, height: Height) {
        while let Some(h) = self.end() {
            if h > height {
                if let Some(k) = self.cache.keys().cloned().next_back() {
                    if let Some(filter) = self.cache.remove(&k) {
                        self.size -= filter.len();
                    }
                }
            } else {
                break;
            }
        }
    }
}
