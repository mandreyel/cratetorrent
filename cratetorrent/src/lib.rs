// needed by the `select!` macro reaching the default recursion limit
#![recursion_limit = "256"]

#[macro_use]
extern crate serde_derive;

mod counter;
mod disk;
mod download;
pub mod engine;
pub mod error;
pub mod iovecs;
pub mod metainfo;
mod peer;
mod piece_picker;
mod storage_info;
mod torrent;

use bitvec::prelude::{BitVec, Msb0};

pub use storage_info::FileInfo;

/// The type of a piece's index.
///
/// On the wire all integers are sent as 4-byte big endian integers, but in the
/// source code we use `usize` to be consistent with other index types in Rust.
pub type PieceIndex = usize;

/// The type of a file's index.
pub type FileIndex = usize;

/// Each torrent gets a randomyl assigned ID that is unique within the
/// application.
pub type TorrentId = u32;

/// The peer ID is an arbitrary 20 byte string.
///
/// Guidelines for choosing a peer ID: http://bittorrent.org/beps/bep_0020.html.
pub type PeerId = [u8; 20];

/// A SHA-1 hash digest, 20 bytes long.
pub type Sha1Hash = [u8; 20];

/// The bitfield represents the piece availability of a peer.
///
/// It is a compact bool vector of most significant bits to least significants
/// bits, that is, where the first highest bit represents the first piece, the
/// second highest element the second piece, and so on (e.g. `0b1100_0001` would
/// mean that we have pieces 0, 1, and 7). A truthy boolean value of a piece's
/// position in this vector means that the peer has the piece, while a falsy
/// value means it doesn't have the piece.
pub type Bitfield = BitVec<Msb0, u8>;

/// This is the only block length we're dealing with (except for possibly the
/// last block).  It is the widely used and accepted 16 KiB.
pub(crate) const BLOCK_LEN: u32 = 0x4000;

/// A block is a fixed size chunk of a piece, which in turn is a fixed size
/// chunk of a torrent. Downloading torrents happen at this block level
/// granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BlockInfo {
    /// The index of the piece of which this is a block.
    pub piece_index: PieceIndex,
    /// The zero-based byte offset into the piece.
    pub offset: u32,
    /// The block's length in bytes. Always 16 KiB (0x4000 bytes), for now.
    pub len: u32,
}

impl BlockInfo {
    /// Returns the index of the block within its piece, assuming the default
    /// block length of 16 KiB.
    pub fn index_in_piece(&self) -> PieceIndex {
        // we need to use "lower than or equal" as this may be the last block in
        // which case it may be shorter than the default block length
        debug_assert!(self.len <= BLOCK_LEN);
        debug_assert!(self.len > 0);
        (self.offset / BLOCK_LEN) as PieceIndex
    }
}

/// Returns the length of the block at the index in piece.
///
/// If the piece is not a multiple of the default block length, the returned
/// value is smalled.
///
/// # Panics
///
/// Panics if the index multiplied by the default block length would exceed the
/// piece length.
pub(crate) fn block_len(piece_len: u32, index: usize) -> u32 {
    let index = index as u32;
    let block_offset = index * BLOCK_LEN;
    assert!(piece_len > block_offset);
    std::cmp::min(piece_len - block_offset, BLOCK_LEN)
}

/// Returns the number of blocks in a piece of the given length.
pub(crate) fn block_count(piece_len: u32) -> usize {
    // all but the last piece are a multiple of the block length, but the
    // last piece may be shorter so we need to account for this by rounding
    // up before dividing to get the number of blocks in piece
    (piece_len as usize + (BLOCK_LEN as usize - 1)) / BLOCK_LEN as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    // An arbitrary piece length that is an exact multiple of the canonical
    // block length (16 KiB).
    const BLOCK_LEN_MULTIPLE_PIECE_LEN: u32 = 2 * BLOCK_LEN;

    // An arbitrary piece length that is _not_ a multiple of the canonical block
    // length and the amount with which it overlaps the nearest exact multiple
    // value.
    const OVERLAP: u32 = 234;
    const UNEVEN_PIECE_LEN: u32 = 2 * BLOCK_LEN + OVERLAP;

    #[test]
    fn test_block_len() {
        assert_eq!(block_len(BLOCK_LEN_MULTIPLE_PIECE_LEN, 0), BLOCK_LEN);
        assert_eq!(block_len(BLOCK_LEN_MULTIPLE_PIECE_LEN, 1), BLOCK_LEN);

        assert_eq!(block_len(UNEVEN_PIECE_LEN, 0), BLOCK_LEN);
        assert_eq!(block_len(UNEVEN_PIECE_LEN, 1), BLOCK_LEN);
        assert_eq!(block_len(UNEVEN_PIECE_LEN, 2), OVERLAP);
    }

    #[test]
    #[should_panic]
    fn test_block_len_invalid_index_panic() {
        block_len(BLOCK_LEN_MULTIPLE_PIECE_LEN, 2);
    }

    #[test]
    fn test_block_count() {
        assert_eq!(block_count(BLOCK_LEN_MULTIPLE_PIECE_LEN), 2);

        assert_eq!(block_count(UNEVEN_PIECE_LEN), 3);
    }
}
