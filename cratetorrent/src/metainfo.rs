use crate::Sha1Hash;
use serde_bencode::Error;
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};

#[derive(Debug, Deserialize)]
pub struct Metainfo {
    pub info: Info,
}

impl Metainfo {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        serde_bencode::from_bytes(buf)
    }

    pub fn create_info_hash(&self) -> Result<Sha1Hash, Error> {
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
    pub piece_length: u64,
    pub length: Option<u64>,
    pub files: Option<Vec<File>>,
    pub private: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    pub path: Vec<String>,
    pub length: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
}