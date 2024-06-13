//! Ephemeral storage backend for filters.

// use nakamoto_common::block::Height;
use crate::bloom::store::{Error, Store};
use crate::nonempty::NonEmpty;

/// In-memory block store.
#[derive(Debug, Clone)]
pub struct Memory<F>(NonEmpty<F>);

impl<F> Memory<F> {
    /// Create a new in-memory block store.
    pub fn new(chain: NonEmpty<F>) -> Self {
        Self(chain)
    }
}

impl<F: Default> Default for Memory<F> {
    fn default() -> Self {
        Self(NonEmpty::new(F::default()))
    }
}

// impl<H: Default> Memory<H> {
//     /// Create a memory store with only the genesis.
//     pub fn default(&self) -> Self {NonEmpty::new()}
// }

impl<F: 'static + Copy + Clone> Store for Memory<F> {
    type PrivacySegment = F;

    /// Get the default unset bloom filter.
    fn default(&self) -> F {
        *self.0.first()
    }

    /// Append a batch of consecutive block headers to the end of the chain.
    fn put<I: Iterator<Item = F>>(&mut self, filters: I) -> Result<u32, Error> {
        self.0.tail.extend(filters);
        Ok(self.0.len() as u32 - 1)
    }

    /// Get the block at the given height.
    fn get(&self, segment: u32) -> Result<F, Error> {
        match self.0.get(segment as usize) {
            Some(filter) => Ok(*filter),
            None => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected end of file",
            ))),
        }
    }

    /// Synchronize the changes to disk.
    fn sync(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Iterate over all headers in the store.
    fn iter(&self) -> Box<dyn Iterator<Item = Result<(u32, F), Error>>> {
        Box::new(
            self.0
                .clone()
                .into_iter()
                .enumerate()
                .map(|(i, h)| Ok((i as u32, h))),
        )
    }

    /// Return the number of headers in the store.
    fn len(&self) -> Result<usize, Error> {
        Ok(self.0.len())
    }

    /// Check data integrity.
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }

    /// Heal data corruption.
    fn heal(&self) -> Result<(), Error> {
        Ok(())
    }
}
