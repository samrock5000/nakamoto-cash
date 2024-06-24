// use bitcoincash::consensus::encode;
// pub mod cache;
// /// bloom store io
// pub mod io;
// pub mod memory;

// pub use io::File;
// pub use memory::Memory;

// /// Represents objects that can store bloom filter segments.
// use thiserror::Error;

// /// A block storage error.
// #[derive(Debug, Error)]
// pub enum Error {
//     /// An I/O error.
//     #[error("i/o error: {0}")]
//     Io(#[from] std::io::Error),
//     /// An error decoding block data.
//     #[error("error decoding header: {0}")]
//     Decoding(#[from] encode::Error),
//     /// A data-corruption error.
//     #[error("error: the store data is corrupt")]
//     Corruption,
//     /// Operation was interrupted.
//     #[error("the operation was interrupted")]
//     Interrupted,
// }
// /// Bloomfilter cache trait
// pub trait Store {
//     /// The type used in the store.
//     type PrivacySegment: Sized;
//     /// default bloom
//     fn default(&self) -> Self::PrivacySegment;
//     /// Append a batch of consecutive bloom filters to the end of the .
//     fn put<I: Iterator<Item = Self::PrivacySegment>>(&mut self, headers: I) -> Result<u32, Error>;
//     /// Get the filter for a script.
//     fn get(&self, segment_id: u32) -> Result<Self::PrivacySegment, Error>;
//     /// Synchronize the changes to disk.
//     fn sync(&mut self) -> Result<(), Error>;
//     /// Iterate over all headers in the store.
//     fn iter(&self) -> Box<dyn Iterator<Item = Result<(u32, Self::PrivacySegment), Error>>>;
//     /// Return the number of headers in the store.
//     fn len(&self) -> Result<usize, Error>;
//     /// Check the store integrity.
//     fn check(&self) -> Result<(), Error>;
//     /// Heal data corruption.
//     fn heal(&self) -> Result<(), Error>;
// }
