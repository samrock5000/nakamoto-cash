//! Types and functions relating to block trees.
#![warn(missing_docs)]
use std::collections::BTreeMap;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::params::Params;
use bitcoin::hash_types::BlockHash;
use bitcoin::pow::Target as PowTarget;
use bitcoin::pow::U256;
use bitcoin::util::uint::Uint256;
// use bitcoin::{Block, Network};
use bitcoincash as bitcoin;

use thiserror::Error;

use crate::block::store;
use crate::block::time::Clock;
use crate::block::{Bits, BlockTime, Height, Target, Work};
use crate::nonempty::NonEmpty;

/// An error related to the block tree.
#[derive(Debug, Error)]
pub enum Error {
    /// The block's proof-of-work is invalid.
    #[error("invalid block proof-of-work")]
    InvalidBlockPoW,

    /// The block's difficulty target is invalid.
    #[error("invalid block difficulty target: {0}, expected {1}")]
    InvalidBlockTarget(Target, Target),

    /// The block's hash doesn't match the checkpoint.
    #[error("invalid checkpoint block hash {0} at height {1}")]
    InvalidBlockHash(BlockHash, Height),

    /// The block forks off the main chain prior to the last checkpoint.
    #[error("block height {0} is prior to last checkpoint")]
    InvalidBlockHeight(Height),

    /// The block timestamp is invalid.
    #[error("block timestamp {0} is invalid")]
    InvalidBlockTime(BlockTime, std::cmp::Ordering),

    /// The block is already known.
    #[error("duplicate block {0}")]
    DuplicateBlock(BlockHash),

    /// The block is orphan.
    #[error("block missing: {0}")]
    BlockMissing(BlockHash),

    /// A block import was aborted. FIXME: Move this error out of here.
    #[error("block import aborted at height {2}: {0} ({1} block(s) imported)")]
    BlockImportAborted(Box<Self>, usize, Height),

    /// Mismatched genesis.
    #[error("stored genesis header doesn't match network genesis")]
    GenesisMismatch,

    /// A storage error occured.
    #[error("storage error: {0}")]
    Store(#[from] store::Error),

    /// The operation was interrupted.
    #[error("the operation was interrupted")]
    Interrupted,
}

/// A generic block header.
pub trait Header {
    /// Return the proof-of-work of this header.
    fn work(&self) -> Work;
}

impl Header for BlockHeader {
    fn work(&self) -> Work {
        self.work()
    }
}

/// The outcome of a successful block header import.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportResult {
    /// A new tip was found. This can happen in either of two scenarios:
    ///
    /// 1. The imported block(s) extended the active chain, or
    /// 2. The imported block(s) caused a chain re-org.
    ///
    TipChanged {
        /// Tip header.
        header: BlockHeader,
        /// Tip hash.
        hash: BlockHash,
        /// Tip height.
        height: Height,
        /// Blocks reverted/disconnected.
        reverted: Vec<(Height, BlockHeader)>,
        /// Blocks added/connected.
        connected: NonEmpty<(Height, BlockHeader)>,
    },
    /// The block headers were imported successfully, but our best block hasn't changed.
    /// This will happen if we imported a duplicate, orphan or stale block.
    TipUnchanged, // TODO: We could add a parameter eg. BlockMissing or DuplicateBlock.
}

/// A chain of block headers that may or may not lead back to genesis.
#[derive(Debug, Clone)]
pub struct Branch<'a, H: Header>(pub &'a [H]);

impl<'a, H: Header> Branch<'a, H> {
    /// Compute the total proof-of-work carried by this branch.
    pub fn work(&self) -> Work {
        let mut work = Work::default();
        for header in self.0.iter() {
            work = work + header.work();
        }
        work
    }
}

/// A representation of all known blocks that keeps track of the longest chain.
pub trait BlockTree: BlockReader {
    /// Import a chain of block headers into the block tree.
    fn import_blocks<I: Iterator<Item = BlockHeader>, C: Clock>(
        &mut self,
        chain: I,
        context: &C,
    ) -> Result<ImportResult, Error>;
    /// Attempts to extend the active chain. Returns `Ok` with `ImportResult::TipUnchanged` if
    /// the block didn't connect, and `Err` if the block was invalid.
    fn extend_tip<C: Clock>(
        &mut self,
        header: BlockHeader,
        context: &C,
    ) -> Result<ImportResult, Error>;
}

/// Read block header state.
pub trait BlockReader {
    /// Get a block by hash.
    fn get_block(&self, hash: &BlockHash) -> Option<(Height, &BlockHeader)>;
    /// Get a block by height.
    fn get_block_by_height(&self, height: Height) -> Option<&BlockHeader>;
    /// Find a path from the active chain to the provided (stale) block hash.
    ///
    /// If a path is found, the height of the start/fork block is returned, along with the
    /// headers up to and including the tip, forming a branch.
    ///
    /// If the given block is on the active chain, its height and header is returned.
    fn find_branch(&self, to: &BlockHash) -> Option<(Height, NonEmpty<BlockHeader>)>;
    /// Iterate over the longest chain, starting from genesis.
    fn chain<'a>(&'a self) -> Box<dyn Iterator<Item = BlockHeader> + 'a> {
        Box::new(self.iter().map(|(_, h)| h))
    }
    /// Get the "chainwork", ie. the total accumulated proof-of-work of the active chain.
    fn chain_work(&self) -> Uint256;
    /// Iterate over the longest chain, starting from genesis, including heights.
    fn iter<'a>(&'a self) -> Box<dyn DoubleEndedIterator<Item = (Height, BlockHeader)> + 'a>;
    /// Iterate over a range of blocks.
    fn range<'a>(
        &'a self,
        range: std::ops::Range<Height>,
    ) -> Box<dyn Iterator<Item = (Height, BlockHash)> + 'a> {
        Box::new(
            self.iter()
                .map(|(height, header)| (height, header.block_hash()))
                .skip(range.start as usize)
                .take((range.end - range.start) as usize),
        )
    }
    /// Return the height of the longest chain.
    fn height(&self) -> Height;
    /// Get the tip of the longest chain.
    fn tip(&self) -> (BlockHash, BlockHeader);
    /// Get the last block of the longest chain.
    fn best_block(&self) -> (Height, &BlockHeader) {
        let height = self.height();
        (
            height,
            self.get_block_by_height(height)
                .expect("the best block is always present"),
        )
    }
    /// Get the height of the last checkpoint block.
    fn last_checkpoint(&self) -> Height;
    /// Known checkpoints.
    fn checkpoints(&self) -> BTreeMap<Height, BlockHash>;
    /// Return the genesis block header.
    fn genesis(&self) -> &BlockHeader {
        self.get_block_by_height(0)
            .expect("the genesis block is always present")
    }
    /// Check whether a block hash is known.
    fn is_known(&self, hash: &BlockHash) -> bool;
    /// Check whether a block hash is part of the active chain.
    fn contains(&self, hash: &BlockHash) -> bool;
    /// Return the headers corresponding to the given locators, up to a maximum.
    fn locate_headers(
        &self,
        locators: &[BlockHash],
        stop_hash: BlockHash,
        max_headers: usize,
    ) -> Vec<BlockHeader>;
    /// Get the locator hashes starting from the given height and going backwards.
    fn locator_hashes(&self, from: Height) -> Vec<BlockHash>;
    /// Get the next difficulty given a block height, time and bits.
    fn next_difficulty_target(
        &self,
        last_height: Height,
        last_time: BlockTime,
        last_target: Target,
        params: &Params,
    ) -> Bits {
        // Only adjust on set intervals. Otherwise return current target.
        // Since the height is 0-indexed, we add `1` to check it against the interval.
        if (last_height + 1) % params.difficulty_adjustment_interval() != 0 {
            return BlockHeader::compact_target_from_u256(&last_target);
        }

        let last_adjustment_height =
            last_height.saturating_sub(params.difficulty_adjustment_interval() - 1);
        let last_adjustment_block = self
            .get_block_by_height(last_adjustment_height)
            .unwrap_or_else(|| self.genesis());
        let last_adjustment_time = last_adjustment_block.time;

        if params.no_pow_retargeting {
            return last_adjustment_block.bits.to_consensus();
        }

        let actual_timespan = last_time - last_adjustment_time;
        let mut adjusted_timespan = actual_timespan;

        if actual_timespan < params.pow_target_timespan as BlockTime / 4 {
            adjusted_timespan = params.pow_target_timespan as BlockTime / 4;
        } else if actual_timespan > params.pow_target_timespan as BlockTime * 4 {
            adjusted_timespan = params.pow_target_timespan as BlockTime * 4;
        }

        let mut target = last_target;

        target = target.mul_u32(adjusted_timespan);
        target = target / Target::from_u64(params.pow_target_timespan).unwrap();

        // Ensure a difficulty floor.
        if target > params.pow_limit {
            target = params.pow_limit;
        }

        BlockHeader::compact_target_from_u256(&target)
    }
    /// ASERT DAA
    fn next_asert_difficulty_target(
        &self,
        last_height: Height,
        last_time: BlockTime,
        last_target: Target,
        params: &Params,
    ) -> Bits {
        let anchor = ASERTAnchor {
            height: last_height as i64,
            nbits: BlockHeader::compact_target_from_u256(&last_target),
            prev_timestamp: last_time as i64,
        };

        const ASERT_HALFLIFE: i64 = 2 * 24 * 60 * 60;
        let pow_limit = params.pow_limit;
        let ref_block_target = Target::from_u64(anchor.nbits as u64).unwrap();

        let time_diff = last_height as i64 - anchor.prev_timestamp;
        let height_diff = last_height as i64 - anchor.height;

        let exponent: i64 = ((time_diff - params.pow_target_spacing as i64 * (height_diff + 1))
            * 65536)
            / ASERT_HALFLIFE;
        let mut shifts = exponent >> 16;
        let frac = u16::try_from(shifts).unwrap() as u64;
        let factor: u32 = 65536
            + ((195766423245049u64 * frac
                + 971821376u64 * frac * frac
                + 5127u64 * frac * frac * frac
                + (1u64 << 47))
                >> 48) as u32;
        let mut next_target = BlockHeader::compact_target_from_u256(&ref_block_target) * factor;
        shifts -= 16;
        if shifts <= 0 {
            next_target >>= -shifts;
        } else {
            let next_target_shifted = next_target << shifts;
            if (next_target_shifted >> shifts) != next_target {
                next_target = BlockHeader::compact_target_from_u256(&pow_limit);
            } else {
                next_target = next_target_shifted;
            }
        }
        next_target
    }
    /// November 13, 2017 hard fork
    fn next_cash_work_difficulty(
        &self,
        height: Height,
        last_time: BlockTime,
        params: &Params,
    ) -> Bits {
        if params.allow_min_difficulty_blocks
            && last_time as u64
                > self.get_block_by_height(height).unwrap().time as u64
                    + params.pow_target_spacing * 2
        {
            return BlockHeader::compact_target_from_u256(&params.pow_limit);
        }
        // _ = last_time;
        // let last_height = height;
        // let first_height = last_height - 144;
        let indexlast = self.get_suitable_blocks(self.tip().1);
        let indexfirst =
            self.get_suitable_blocks(*self.get_block_by_height(self.height() - 144).unwrap());

        self.compute_target(indexfirst, indexlast, &params)
        // next_target
    }
    /// Given a vector of block headers, returns the median block based on their timestamps.
    fn get_suitable_blocks(&self, block: BlockHeader) -> BlockHeader {
        // let mut blocks = self.locate_headers(
        //     &vec![self.get_block_by_height(height - 3).unwrap().block_hash()],
        //     self.get_block_by_height(height).unwrap().block_hash(),
        //     3,
        // );

        let blk2 = *self.get_block(&block.block_hash()).unwrap().1;
        let blk1 = *self.get_block(&block.prev_blockhash).unwrap().1;
        let blk0 = *self.get_block(&blk1.prev_blockhash).unwrap().1;
        let mut blocks: Vec<BlockHeader> = vec![blk0, blk1, blk2];
        assert!(blocks.len() >= 3, "Need at least 3 blocks to find a median");

        if blocks[0].time > blocks[2].time {
            std::mem::swap(&mut blocks[0].clone(), &mut blocks[2]);
        };
        if blocks[0].time > blocks[1].time {
            std::mem::swap(&mut blocks[0].clone(), &mut blocks[1]);
        };
        if blocks[1].time > blocks[2].time {
            std::mem::swap(&mut blocks[1].clone(), &mut blocks[2]);
        };
        return blocks[1];
    }

    /// Compute a target based on the work done between 2 blocks and the time
    /// required to produce that work.
    fn compute_target(
        &self,
        first_height: BlockHeader,
        last_height: BlockHeader,
        params: &Params,
    ) -> Bits {
        assert!(
            self.get_block(&last_height.block_hash()).unwrap().0
                >= self.get_block(&first_height.block_hash()).unwrap().0,
            "Last block must have a higher height than first"
        );
        let target_spacing = params.pow_target_spacing as u128;

        let daa_block_work = self.locate_headers(
            &vec![first_height.block_hash()],
            last_height.block_hash(),
            150,
        );
        // let daa_len = daa_block_work.len().clone();
        let mut daa_work = U256::default();
        for header in daa_block_work {
            daa_work = daa_work + header.get_work().0;
        }
        daa_work = daa_work * U256::from(target_spacing);

        let mut time_span = (last_height.time - first_height.time) as u128;

        if time_span > 288 * target_spacing {
            time_span = 288 * target_spacing;
        } else if time_span < 72 * target_spacing {
            time_span = 72 * target_spacing;
        }

        // let projected_work = daa_work * (U256::from(params.pow_target_spacing));
        let projected_work = daa_work / U256::from(time_span);

        let mut new_target = U256::inverse(&projected_work);
        if new_target > PowTarget::MAX.0 {
            new_target = PowTarget::MAX.0
        }
        PowTarget(new_target).to_compact_lossy().to_consensus()
    }
}

#[derive(Debug, Clone, Copy)]
struct ASERTAnchor {
    pub height: i64,         // 661647,
    pub nbits: u32,          // 0x1804dafe,
    pub prev_timestamp: i64, // 1605447844,
}
impl Default for ASERTAnchor {
    fn default() -> Self {
        ASERTAnchor {
            height: 661647,
            nbits: 0x1804dafe,
            prev_timestamp: 1605447844,
        }
    }
}
