//! Bloom filter cache.

#![allow(dead_code)]

use std::io;
use std::ops::ControlFlow;
// use std::ops::RangeInclusive;

use bitcoincash::consensus::{encode, Decodable, Encodable};

use crate::bitcoin::util::bloom::BloomFilter;
use crate::block::Height;
use crate::bloom::store::{Error, Store};
use crate::nonempty::NonEmpty;

///
#[derive(Debug, Clone /* Copy */)]
pub struct PrivacySegment {
    /// segment id
    pub segment: u32,
    /// this segments bloom filter
    pub filter: BloomFilter,
    /// first [Height] in which this segment was used in chain.
    pub birth: Height,
    /// Last [Height] in which this segment synced.
    pub synced_height: Height,
    /// is the segment currently set
    pub is_enabled: bool,
}

impl Default for PrivacySegment {
    fn default() -> Self {
        Self {
            filter: BloomFilter::default(),
            segment: 0,
            birth: 0,
            synced_height: 0,
            is_enabled: false,
        }
    }
}

impl Encodable for PrivacySegment {
    fn consensus_encode<W: io::Write + ?Sized>(&self, e: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.segment.consensus_encode(e)?;
        len += self.filter.consensus_encode(e)?;
        len += self.birth.consensus_encode(e)?;
        len += self.synced_height.consensus_encode(e)?;
        len += self.is_enabled.consensus_encode(e)?;
        Ok(len)
    }
}

impl Decodable for PrivacySegment {
    fn consensus_decode<D: io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let segment = u32::consensus_decode(d)?;
        let filter = BloomFilter::consensus_decode(d)?;
        let birth = Height::consensus_decode(d)?;
        let synced_height = Height::consensus_decode(d)?;
        let is_enabled = bool::consensus_decode(d)?;

        Ok(PrivacySegment {
            segment,
            filter,
            birth,
            synced_height,
            is_enabled,
        })
    }
}
/// A privacy segment filter cache
pub struct FilterCache<S> {
    filters: NonEmpty<PrivacySegment>,
    filter_store: S,
}
impl<S: Store<PrivacySegment = PrivacySegment>> FilterCache<S> {
    /// loads the [PrivacySegment]
    pub fn load(filter_store: S) -> Result<Self, Error> {
        Self::load_with(filter_store, |_| ControlFlow::Continue(()))
    }
    /// called from [FilterCache::load]
    pub fn load_with(
        filter_store: S,
        progress: impl Fn(Height) -> ControlFlow<()>,
    ) -> Result<Self, Error> {
        let mut filters = NonEmpty::new(filter_store.default());

        for (segment, result) in filter_store.iter().enumerate() {
            let (_, bloom_filter) = result?;
            filters.push(bloom_filter);

            if progress(segment as Height).is_break() {
                return Err(Error::Interrupted);
            }
        }

        Ok(Self {
            filter_store,
            filters,
        })
    }
    /// update segment state to disk
    pub fn update_segments(mut filter_store: S) -> Result<(), Error> {
        if filter_store.sync().is_ok() {
            Ok(())
        } else {
            Err(Error::Corruption)
        }
    }
}

// impl<S: Store<PrivacySegment = PrivacySegment>> Store for FilterCache<S> {
//     fn check(&self) -> Result<(), Error> {}
//     fn default(&self) -> Self::PrivacySegment {}
//     fn get(&self, segment_id: u32) -> Result<Self::PrivacySegment, Error> {}
//     fn heal(&self) -> Result<(), Error> {}
//     fn iter(&self) -> Box<dyn Iterator<Item = Result<(u32, Self::PrivacySegment), Error>>> {}
//     fn len(&self) -> Result<usize, Error> {}
//     fn put<I: Iterator<Item = Self::PrivacySegment>>(&mut self, headers: I) -> Result<u32, Error> {}
//     fn sync(&mut self) -> Result<(), Error> {}
// }
