use crate::error::*;
use crate::Sha1Hash;
use sha1::{Digest, Sha1};

#[derive(Debug, Deserialize)]
pub struct Metainfo {
    pub info: Info,
}

impl Metainfo {
    /// Parses from a byte buffer a new [`Metainfo`] instance, or aborts with an
    /// error.
    ///
    /// If the encoding itself is correct, the constructor may still fail if the
    /// metadata is not semantically correct (e.g. if the length of the `pieces`
    /// field is not a multiple of 20).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let metainfo: Self = serde_bencode::from_bytes(buf)?;
        // the pieces field is a concatenation of 20 byte SHA-1 hashes, so it
        // must be a multiple of 20
        if metainfo.info.pieces.len() % 20 != 0 {
            return Err(Error::InvalidPieces);
        }
        Ok(metainfo)
    }

    /// Returns the number of pieces in this torrent.
    pub fn piece_count(&self) -> usize {
        self.info.pieces.len() / 20
    }

    /// Returns the total download size in bytes.
    pub fn download_len(&self) -> Result<u64> {
        if let Some(len) = self.info.len {
            Ok(len)
        } else if let Some(files) = &self.info.files {
            let len = files.iter().map(|f| f.len).sum();
            Ok(len)
        } else {
            // this is implies an invalid metainfo
            // but we should check this in the constructor
            Err(Error::InvalidMetainfo)
        }
    }

    /// Creates a SHA-1 hash of the encoded `info` field's value.
    ///
    /// The resulting hash is used to identify a torrent with trackers and
    /// peers.
    pub fn create_info_hash(&self) -> Result<Sha1Hash> {
        let info = serde_bencode::to_bytes(&self.info)?;
        let digest = Sha1::digest(&info);
        let mut info_hash = [0; 20];
        info_hash.copy_from_slice(&digest);
        Ok(info_hash)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub pieces: Vec<u8>,
    #[serde(rename = "piece length")]
    pub piece_len: u32,
    #[serde(rename = "length")]
    pub len: Option<u64>,
    pub files: Option<Vec<File>>,
    pub private: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    pub path: Vec<String>,
    #[serde(rename = "length")]
    pub len: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO(https://github.com/mandreyel/cratetorrent/issues/8): add metainfo
    // parsing tests
}
