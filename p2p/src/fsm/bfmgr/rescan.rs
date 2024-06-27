//! Blockchain (re-)scanning for matching bloom filters.
#[allow(unused)]
use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::rc::Rc;

// use nakamoto_common::bitcoin::util::bloom::{self, BloomFilter};
use nakamoto_common::bitcoin::{Script, Txid};
use nakamoto_common::block::tree::BlockReader;
use nakamoto_common::block::{BlockHash, Height, MerkleBlock};
use nakamoto_common::collections::{HashMap, HashSet};

use super::{FilterCache, HeightIterator /* MAX_MESSAGE_CFILTERS */};

/// Bloom Filter (re)scan state.
#[derive(Debug, Default)]
pub struct Rescan {
    /// Whether a rescan is currently in progress.
    pub active: bool,
    /// Current height from merkle blocks are scanned.
    /// Must be between `start` and `end`.
    pub current: Height,
    /// Start height of the filter rescan.
    pub start: Height,
    /// End height of the filter rescan. If `None`, keeps scanning new blocks until stopped.
    pub end: Option<Height>,
    /// Filter cache.
    pub cache: FilterCache<Rc<MerkleBlock>>,
    /// Addresses and outpoints to watch for.
    pub watch: HashSet<Script>,
    /// Transactions to watch for.
    pub transactions: HashMap<Txid, HashSet<Script>>,

    /// Filters requested and remaining to download.
    requested: BTreeSet<Height>,
    /// Received filters waiting to be matched.
    received: HashMap<Height, (Rc<MerkleBlock>, BlockHash, bool)>,
}

impl Rescan {
    /// Create a new rescan state.
    pub fn new(cache: usize) -> Self {
        let cache = FilterCache::new(cache);

        Self {
            cache,
            ..Self::default()
        }
    }
    /// Start or restart a rescan. Resets the request state.
    pub fn restart(
        &mut self,
        start: Height,
        end: Option<Height>,
        // watch: impl IntoIterator<Item = Script>,
    ) {
        self.active = true;
        self.start = start;
        self.current = start;
        self.end = end;
        // self.watch = watch.into_iter().collect();
        self.requested.clear();
    }

    /// Reset requested heights. This allows for requests to be re-issued.
    pub fn reset(&mut self) {
        self.requested.clear();
    }

    /// Given a range of heights, return the ranges that are missing.
    /// This is useful to figure out which ranges to fetch while ensuring we don't request
    /// the same heights more than once.
    pub fn requests<T: BlockReader>(
        &mut self,
        range: RangeInclusive<Height>,
        tree: &T,
    ) -> Vec<RangeInclusive<Height>> {
        if range.is_empty() {
            return vec![];
        }
        for height in range.clone() {
            if let Some(merkle_block) = self.cache.get(&height) {
                if let Some(header) = tree.get_block_by_height(height) {
                    let block_hash = header.block_hash();
                    // Insert the cached merkle_blocks into the processing queue.
                    self.received
                        .insert(height, (merkle_block.clone(), block_hash, true));
                }
            }
        }
        // Heights to skip.
        // Note that cached heights will have been added to the `received` list.
        let mut skip: BTreeSet<Height> = BTreeSet::new();
        // Heights we've received but not processed.
        skip.extend(self.received.keys().cloned());
        // Heights we've already requested.
        skip.extend(&self.requested);

        // Iterate over requested ranges, taking care that heights are only requested once.
        // If there are gaps in the requested range after the difference is taken, split
        // the requests in groups of consecutive heights.
        let mut ranges: Vec<RangeInclusive<Height>> = Vec::new();
        for height in range.collect::<BTreeSet<_>>().difference(&skip) {
            if let Some(r) = ranges.last_mut() {
                if *height == r.end() + 1 {
                    *r = *r.start()..=r.end() + 1;
                    continue;
                }
            }
            // Either this is the first range request, or there is a gap between the previous
            // range and this height. Start a new range.
            let range = *height..=*height;

            ranges.push(range);
        }

        // Limit the requested ranges to `MAX_MESSAGE_INVS`.
        let ranges: Vec<RangeInclusive<Height>> = ranges
            .into_iter()
            .flat_map(|r| HeightIterator {
                start: *r.start(),
                stop: *r.end(),
                // step: MAX_MESSAGE_INVS as Height,
                step: 25_000 as Height,
            })
            .collect();

        for range in &ranges {
            self.requested.extend(range.clone());
        }
        ranges
    }
}
