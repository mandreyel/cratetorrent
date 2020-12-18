//! This module defines types used to configure the engine and its parts.

use std::{path::PathBuf, time::Duration};

use crate::PeerId;

/// The default cratetorrent client id.
pub const CRATETORRENT_CLIENT_ID: &PeerId = b"cbt-0000000000000000";

/// The global configuration for the torrent engine and all its parts.
#[derive(Clone, Debug)]
pub struct Conf {
    pub engine: EngineConf,
    pub torrent: TorrentConf,
}

impl Conf {
    /// Returns the torrent configuration with reasonable defaults, except for
    /// the download directory, as it is not sensible to guess that for the
    /// user. It uses the default cratetorrent client id,
    /// [`CRATETORRENT_CLIENT_ID`].
    pub fn new(download_dir: impl Into<PathBuf>) -> Self {
        Self {
            engine: EngineConf {
                client_id: *CRATETORRENT_CLIENT_ID,
            },
            torrent: TorrentConf::new(download_dir),
        }
    }
}

/// Configuration related to the engine itself.
#[derive(Clone, Debug)]
pub struct EngineConf {
    /// The ID of the client to announce to trackers and other peers.
    pub client_id: PeerId,
}

/// Configuration for a torrent.
///
/// The engine will have a default instance of this applied to all torrents by
/// default, but individual torrents may override this configuration.
#[derive(Clone, Debug)]
pub struct TorrentConf {
    /// The directory in which a torrent's files are placed upon download and
    /// from which they are seeded.
    pub download_dir: PathBuf,

    /// The minimum number of peers we want to keep in torrent at all times.
    /// This will be configurable later.
    pub min_requested_peer_count: usize,

    /// The max number of connected peers the torrent should have.
    pub max_connected_peer_count: usize,

    /// If the tracker doesn't provide a minimum announce interval, we default
    /// to announcing every 30 seconds.
    pub announce_interval: Duration,

    /// After this many attempts, the torrent stops announcing to a tracker.
    pub tracker_error_threshold: usize,
}

impl TorrentConf {
    /// Returns the torrent configuration with reasonable defaults, except for
    /// the download directory, as it is not sensible to guess that for the
    /// user.
    pub fn new(download_dir: impl Into<PathBuf>) -> Self {
        Self {
            download_dir: download_dir.into(),
            // We always request at least 10 peers as anything less is a waste
            // of network round trip and it allows us to buffer up a bit more
            // than needed.
            min_requested_peer_count: 10,
            // This value is mostly picked for performance while keeping in mind
            // not to overwhelm the host.
            max_connected_peer_count: 50,
            // needs teting
            announce_interval: Duration::from_secs(60 * 60),
            // needs testing
            tracker_error_threshold: 15,
        }
    }
}
