// //! Persistent storage backend for blocks.
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::iter;
use std::mem;
use std::path::Path;

use crate::bitcoin::consensus::{Decodable, Encodable};
use crate::bloom::store::{Error, Store};
// use bitcoincash::ScriptHash;

/// Append a filter to the end of the stream.
fn put<F: Sized + Encodable, S: Seek + Write, I: Iterator<Item = F>>(
    mut stream: S,
    filters: I,
) -> Result<u32, Error> {
    let mut pos = stream.seek(io::SeekFrom::End(0))?;
    let size = std::mem::size_of::<F>();

    for filter in filters {
        pos += filter.consensus_encode(&mut stream)? as u64;
    }
    Ok(pos as u32 / size as u32)
}

/// Get a filter from the stream.
fn get<F: Decodable, S: Seek + Read>(mut stream: S, ix: u32) -> Result<F, Error> {
    let size = std::mem::size_of::<F>();
    let mut buf = vec![0; size]; // TODO: Use an array when rust has const-generics.

    stream.seek(io::SeekFrom::Start(ix as u64 * size as u64))?;
    stream.read_exact(&mut buf)?;

    F::consensus_decode(&mut buf.as_slice()).map_err(Error::from)
}

/// Reads from a file in an I/O optmized way.
#[derive(Debug)]
struct FileReader<F> {
    file: fs::File,
    queue: VecDeque<F>,
    index: u64,
}

impl<F: Decodable> FileReader<F> {
    const BATCH_SIZE: usize = 16;

    fn new(file: fs::File) -> Self {
        Self {
            file,
            queue: VecDeque::new(),
            index: 0,
        }
    }

    fn next(&mut self) -> Result<Option<F>, Error> {
        let size = std::mem::size_of::<F>();

        if self.queue.is_empty() {
            let mut buf = vec![0; size * Self::BATCH_SIZE];
            let from = self.file.seek(io::SeekFrom::Start(self.index))?;

            match self.file.read_exact(&mut buf) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    self.file.seek(io::SeekFrom::Start(from))?;
                    let n = self.file.read_to_end(&mut buf)?;
                    buf.truncate(n);
                }
                Err(err) => return Err(err.into()),
            }
            self.index += buf.len() as u64;

            let items = buf.len() / size;
            let mut cursor = io::Cursor::new(buf);
            let mut item = vec![0; size];

            for _ in 0..items {
                cursor.read_exact(&mut item)?;

                let item = F::consensus_decode(&mut item.as_slice())?;
                self.queue.push_back(item);
            }
        }
        Ok(self.queue.pop_front())
    }
}

/// An iterator over bloom filters file.
#[derive(Debug)]
pub struct Iter<F> {
    segment_id: u32,
    file: FileReader<F>,
}

impl<F: Decodable> Iter<F> {
    fn new(file: fs::File, segment_id: u32) -> Self {
        Self {
            file: FileReader::new(file),
            segment_id,
        }
    }
}

impl<F: Decodable> Iterator for Iter<F> {
    type Item = Result<(u32, F), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let segment = self.segment_id;

        assert!(segment > 0);

        match self.file.next() {
            // If we hit this branch, it's because we're trying to read passed the end
            // of the file, which means there are no further headers remaining.
            Err(Error::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof => None,
            // If another kind of error occurs, we want to yield it to the caller, so
            // that it can be propagated.
            Err(err) => Some(Err(err)),
            Ok(Some(h)) => {
                self.segment_id += 1;
                Some(Ok((self.segment_id, h)))
            }
            Ok(None) => None,
        }
    }
}

/// A `Store` backed by a single file.
#[derive(Debug)]
pub struct File<PrivacySegment> {
    file: fs::File,
    segment: PrivacySegment,
}

impl<F> File<F> {
    /// Open a new file store from the given path and bloom segment.
    pub fn open<P: AsRef<Path>>(path: P, segment: F) -> io::Result<Self> {
        fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map(|file| Self { file, segment })
    }

    /// Create a new file store at the given path, with the provided segment.
    pub fn create<P: AsRef<Path>>(path: P, segment: F) -> Result<Self, Error> {
        let file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .append(true)
            .open(path)?;

        Ok(Self { file, segment })
    }
}

impl<F: 'static + Clone + Encodable + Decodable> Store for File<F> {
    type PrivacySegment = F;

    fn default(&self) -> F {
        self.clone().segment.clone()
    }

    /// Append a block to the end of the file.
    fn put<I: Iterator<Item = Self::PrivacySegment>>(&mut self, segment: I) -> Result<u32, Error> {
        self::put(&mut self.file, segment)
    }

    /// Get the block at the given height. Returns `io::ErrorKind::UnexpectedEof` if
    /// the height is not found.
    fn get(&self, segment_id: u32) -> Result<F, Error> {
        if let Some(ix) = segment_id.checked_sub(1) {
            // Clone so this function doesn't have to take a `&mut self`.
            let mut file = self.file.try_clone()?;
            get(&mut file, ix)
        } else {
            Ok(self.segment.clone())
        }
    }

    /// Flush changes to disk.
    fn sync(&mut self) -> Result<(), Error> {
        self.file.sync_data().map_err(Error::from)
    }

    /// Iterate over all headers in the store.
    // fn iter(&self) -> Box<dyn Iterator<Item = Result<(F, F), Error>>> {
    fn iter(&self) -> Box<dyn Iterator<Item = Result<(u32, F), Error>>> {
        // Clone so this function doesn't have to take a `&mut self`.
        match self.file.try_clone() {
            Ok(file) => {
                Box::new(iter::once(Ok((0, self.segment.clone()))).chain(Iter::new(file, 0)))
            }
            Err(err) => Box::new(iter::once(Err(Error::Io(err)))),
        }
    }

    /// Return the number of headers in the store.
    fn len(&self) -> Result<usize, Error> {
        let meta = self.file.metadata()?;
        let len = meta.len();
        let size = mem::size_of::<F>();

        assert!(len <= usize::MAX as u64);

        if len as usize % size != 0 {
            return Err(Error::Corruption);
        }
        Ok(len as usize / size + 1)
    }

    //     /// Return the block height of the store.
    //     fn height(&self) -> Result<Height, Error> {
    //         self.len().map(|n| n as Height - 1)
    //     }

    /// Check the file store integrity.
    fn check(&self) -> Result<(), Error> {
        self.len().map(|_| ())
    }

    /// Attempt to heal data corruption.
    fn heal(&self) -> Result<(), Error> {
        let meta = self.file.metadata()?;
        let len = meta.len();
        let size = mem::size_of::<F>();

        assert!(len <= usize::MAX as u64);

        let extraneous = len as usize % size;
        if extraneous != 0 {
            self.file.set_len(len - extraneous as u64)?;
        }

        Ok(())
    }
}

// #[cfg(test)]
mod test {
    // use std::{io, iter};

    // use nakamoto_common::bitcoin::TxMerkleNode;
    // use nakamoto_common::bitcoin_hashes::Hash;
    // use nakamoto_common::block::BlockHash;
    // // use tempfile::*

    // use super::{Error, File, Height, Store};
    // use crate::block::BlockHeader;

    // const HEADER_SIZE: usize = 80;

    // use nakamoto_common::bitcoin::util::bloom::BloomFilter;

    // fn store(path: &str) -> File<BlockHeader> {
    //     let tmp = tempfile::tempdir().unwrap();
    //     let mut bloom_filter = BloomFilter::new(1000, 0.0001, 987987, 0);

    //     File::open(tmp.path().join(path), genesis).unwrap()
    // }

    //     #[test]
    //     fn test_put_get() {
    //         let mut store = store("bloomfilters.db");

    //         let header = BlockHeader {
    //             version: 1,
    //             prev_blockhash: store.genesis.block_hash(),
    //             merkle_root: TxMerkleNode::all_zeros(),
    //             bits: 0x2ffffff,
    //             time: 1842918273,
    //             nonce: 312143,
    //         };

    //         assert_eq!(
    //             store.get(0).unwrap(),
    //             store.genesis,
    //             "when the store is empty, we can `get` the genesis"
    //         );
    //         assert!(
    //             store.get(1).is_err(),
    //             "when the store is empty, we can't get height `1`"
    //         );

    //         let height = store.put(iter::once(header)).unwrap();
    //         store.sync().unwrap();

    //         assert_eq!(height, 1);
    //         assert_eq!(store.get(height).unwrap(), header);
    //     }

    //     #[test]
    //     fn test_put_get_batch() {
    //         let mut store = store("headers.db");

    //         assert_eq!(store.len().unwrap(), 1);

    //         let count = 32;
    //         let header = BlockHeader {
    //             version: 1,
    //             prev_blockhash: store.genesis().block_hash(),
    //             merkle_root: TxMerkleNode::all_zeros(),
    //             bits: 0x2ffffff,
    //             time: 1842918273,
    //             nonce: 0,
    //         };
    //         let iter = (0..count).map(|i| BlockHeader { nonce: i, ..header });
    //         let headers = iter.clone().collect::<Vec<_>>();

    //         // Put all headers into the store and check that we can retrieve them.
    //         {
    //             let height = store.put(iter).unwrap();

    //             assert_eq!(height, headers.len() as Height);
    //             assert_eq!(store.len().unwrap(), headers.len() + 1); // Account for genesis.

    //             for (i, h) in headers.iter().enumerate() {
    //                 assert_eq!(&store.get(i as Height + 1).unwrap(), h);
    //             }

    //             assert!(&store.get(32 + 1).is_err());
    //         }

    //         // Rollback and overwrite the history.
    //         {
    //             let h = headers.len() as Height / 2; // Some point `h` in the past.

    //             assert!(&store.get(h + 1).is_ok());
    //             assert_eq!(store.get(h + 1).unwrap(), headers[h as usize]);

    //             store.rollback(h).unwrap();

    //             assert!(
    //                 &store.get(h + 1).is_err(),
    //                 "after the rollback, we can't access blocks passed `h`"
    //             );
    //             assert_eq!(store.len().unwrap(), h as usize + 1);

    //             // We can now overwrite the block at position `h + 1`.
    //             let header = BlockHeader {
    //                 nonce: 49219374,
    //                 ..header
    //             };
    //             let height = store.put(iter::once(header)).unwrap();

    //             assert!(header != headers[height as usize]);

    //             assert_eq!(height, h + 1);
    //             assert_eq!(store.get(height).unwrap(), header);

    //             // Blocks up to and including `h` are unaffected by the rollback.
    //             assert_eq!(store.get(0).unwrap(), store.genesis);
    //             assert_eq!(store.get(1).unwrap(), headers[0]);
    //             assert_eq!(store.get(h).unwrap(), headers[h as usize - 1]);
    //         }
    //     }

    //     #[test]
    //     fn test_iter() {
    //         let mut store = store("bloomfilters.db");

    //         let count = 32;
    //         let header = BlockHeader {
    //             version: 1,
    //             prev_blockhash: store.genesis().block_hash(),
    //             merkle_root: TxMerkleNode::all_zeros(),
    //             bits: 0x2ffffff,
    //             time: 1842918273,
    //             nonce: 0,
    //         };
    //         let iter = (0..count).map(|i| BlockHeader { nonce: i, ..header });
    //         let headers = iter.clone().collect::<Vec<_>>();

    //         store.put(iter).unwrap();

    //         let mut iter = store.iter();
    //         assert_eq!(iter.next().unwrap().unwrap(), (0, store.genesis));

    //         for (i, result) in iter.enumerate() {
    //             let (height, header) = result.unwrap();

    //             assert_eq!(i as u64 + 1, height);
    //             assert_eq!(header, headers[height as usize - 1]);
    //         }
    //     }

    //     #[test]
    //     fn test_corrupt_file() {
    //         let mut store = store("bloomfilters.db");

    //         store.check().expect("checking always works");
    //         store.heal().expect("healing when there is no corruption");

    //         let headers = &[
    //             BlockHeader {
    //                 version: 1,
    //                 prev_blockhash: store.genesis().block_hash(),
    //                 merkle_root: TxMerkleNode::all_zeros(),
    //                 bits: 0x2ffffff,
    //                 time: 1842918273,
    //                 nonce: 312143,
    //             },
    //             BlockHeader {
    //                 version: 1,
    //                 prev_blockhash: BlockHash::all_zeros(),
    //                 merkle_root: TxMerkleNode::all_zeros(),
    //                 bits: 0x1ffffff,
    //                 time: 1842918920,
    //                 nonce: 913716378,
    //             },
    //         ];
    //         store.put(headers.iter().cloned()).unwrap();
    //         store.check().unwrap();

    //         assert_eq!(store.len().unwrap(), 3);

    //         let size = std::mem::size_of::<BlockHeader>();
    //         assert_eq!(size, HEADER_SIZE);

    //         // Intentionally corrupt the file, by truncating it by 32 bytes.
    //         store
    //             .file
    //             .set_len(headers.len() as u64 * size as u64 - 32)
    //             .unwrap();

    //         assert_eq!(
    //             store.get(1).unwrap(),
    //             headers[0],
    //             "the first header is intact"
    //         );

    //         matches! {
    //             store
    //                 .get(2)
    //                 .expect_err("the second header has been corrupted"),
    //             Error::Io(err) if err.kind() == io::ErrorKind::UnexpectedEof
    //         };

    //         store.len().expect_err("data is corrupted");
    //         store.check().expect_err("data is corrupted");

    //         store.heal().unwrap();
    //         store.check().unwrap();

    //         assert_eq!(
    //             store.len().unwrap(),
    //             2,
    //             "the last (corrupted) header was removed"
    //         );
    //     }
}
