use std::{
    convert::TryInto,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use rand::prelude::*;
use reqwest::{Client, Url};
use serde::de;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::{
    metainfo::{BencodeError, TrackerUrl},
    PeerId, Sha1Hash,
};

pub use reqwest::Error as HttpError;

pub(crate) type Result<T, E = TrackerError> = crate::error::Result<T, E>;

/// The possible errors that may occur when contating the tracker.
#[derive(Debug)]
#[non_exhaustive]
pub enum TrackerError {
    /// Holds bencode serialization or deserialization related errors.
    Bencode(BencodeError),
    /// HTTP related errors when contacting the tracker.
    Http(HttpError),
    ///UDP Specific: The transaction id received doesn't match the one sent
    NonMatchingTransactionId,
}

impl From<BencodeError> for TrackerError {
    fn from(e: BencodeError) -> Self {
        Self::Bencode(e)
    }
}

impl From<HttpError> for TrackerError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}

impl fmt::Display for TrackerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bencode(e) => e.fmt(f),
            Self::Http(e) => e.fmt(f),
            Self::NonMatchingTransactionId => self.fmt(f),
        }
    }
}

/// Parameters for announcing to a tracker.
pub(crate) struct Announce {
    pub info_hash: Sha1Hash,
    pub peer_id: PeerId,

    /// The port on which we are listening.
    pub port: u16,
    /// True IP address of the client in dotted quad format. This is only necessary if
    /// the IP addresss from which the HTTP request originated is not the same as the
    /// client's host address. This happens if the client is communicating through a
    /// proxy, or when the tracker is on the same NAT'd subnet as peer (in which case it
    /// is necessary that tracker not give out an unroutable address to peer).
    pub ip: Option<IpAddr>,

    /// Number of bytes downloaded so far.
    pub downloaded: u64,
    /// Number of bytes uploaded so far.
    pub uploaded: u64,
    /// Number of bytes left to download.
    pub left: u64,

    /// The number of peers the client wishes to receive from the tracker. If omitted and
    /// the tracker is UDP, -1 is sent to signal the tracker to determine the number of
    /// peers, and if it's ommitted and the tracker is HTTP, this is typically swapped
    /// for a value between 30 and 50.
    pub peer_count: Option<usize>,

    /// If previously received from the tracker, we must send it with each
    /// announce.
    pub tracker_id: Option<String>,

    /// Only need be set during the special events defined in [`Event`].
    /// Otherwise when just requesting peers, no event needs to be set.
    pub event: Option<Event>,
}

/// The optional announce event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Event {
    /// The first request to tracker must include this value.
    Started,
    /// Must be sent to the tracker when the client becomes a seeder. Must not be
    /// present if the client started as a seeder.
    Completed,
    /// Must be sent to tracker if the client is shutting down gracefully.
    Stopped,
}

/// The tracker announce response.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Serialize))]
pub(crate) struct Response {
    /// The tracker id. If set, we must send it with each subsequent announce.
    #[serde(rename = "tracker id")]
    pub tracker_id: Option<String>,

    /// If this is not empty, no other fields in response are valid. It contains
    /// a human-readable error message as to why the request was invalid.
    #[serde(rename = "failure reason")]
    pub failure_reason: Option<String>,

    /// Optional. Similar to failure_reason, but the response is still processed.
    #[serde(rename = "warning message")]
    pub warning_message: Option<String>,

    /// The number of seconds the client should wait before recontacting tracker.
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_seconds")]
    pub interval: Option<Duration>,

    /// If present, the client must not reannounce itself before the end of this
    /// interval.
    #[serde(default)]
    #[serde(rename = "min interval")]
    #[serde(deserialize_with = "deserialize_seconds")]
    pub min_interval: Option<Duration>,

    #[serde(rename = "complete")]
    pub seeder_count: Option<usize>,
    #[serde(rename = "incomplete")]
    pub leecher_count: Option<usize>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialize_peers")]
    pub peers: Vec<SocketAddr>,
}

/// The HTTP tracker for a torrent for which we can request peers as well as to
/// announce transfer progress.
pub(crate) struct Tracker {
    /// The HTTP client.
    client: Client,
    /// The URL of the tracker.
    url: Url,
    udp: bool,
}

impl Tracker {
    pub fn new(url_udp: TrackerUrl) -> Self {
        Self {
            client: Client::new(),
            url: url_udp.url,
            udp: url_udp.is_udp,
        }
    }

    ///https://www.bittorrent.org/beps/bep_0015.html
    async fn connect_udp(ip_addr: SocketAddr) -> Option<u64> {
        //Bind to a random port
        let port = thread_rng().gen_range(1025..u16::MAX);

        let mut sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))
            .await
            .unwrap();

        //The magic protocol id number
        let protocol_id: u64 = 0x41727101980;
        let action: u32 = 0;
        let transaction_id: u32 = random();

        let mut bytes_to_send = BytesMut::with_capacity(16);
        bytes_to_send.put_u64(protocol_id);
        bytes_to_send.put_u32(action);
        bytes_to_send.put_u32(transaction_id);

        let bytes_to_send = &bytes_to_send;

        let mut response_buf: [u8; 16] = [0; 16];

        sock.send_to(bytes_to_send, ip_addr).await.unwrap();
        let wait_time = Duration::from_secs(3);

        let could_connect =
            match timeout(wait_time, sock.recv_from(&mut response_buf)).await {
                Ok(_) => true,
                Err(_) => false,
            };

        let transaction_id_recv: u32 =
            u32::from_be_bytes((&response_buf[4..8]).try_into().unwrap());

        let result = if &transaction_id == &transaction_id_recv && could_connect
        {
            let connection_id: u64 =
                u64::from_be_bytes((&response_buf[8..]).try_into().unwrap());

            Some(connection_id)
        } else {
            None
        };

        result
    }

    pub async fn announce(&self, params: Announce) -> Result<Response> {
        match &self.udp {
            true => self.announce_udp(params).await,
            false => self.announce_http(params).await,
        }
    }

    /// Sends an announce request to the tracker with the specified parameters.
    ///
    /// This may be used by a torrent to request peers to download from and to
    /// report statistics to the tracker.
    ///
    /// # Important
    ///
    /// The tracker may not be contacted more often than the minimum interval
    /// returned in the first announce response.
    async fn announce_http(&self, params: Announce) -> Result<Response> {
        // announce parameters are built up in the query string, see:
        // https://www.bittorrent.org/beps/bep_0003.html trackers section
        let mut query = vec![
            ("port", params.port.to_string()),
            ("downloaded", params.downloaded.to_string()),
            ("uploaded", params.uploaded.to_string()),
            ("left", params.left.to_string()),
            // Indicates that client accepts a compact response (each peer takes
            // up only 6 bytes where the first four bytes constitute the IP
            // address and the last 2 the port number, in Network Byte Order).
            // The is always true to save network traffic (many trackers don't
            // consider this and send compact lists anyway).
            ("compact", "1".to_string()),
        ];
        if let Some(peer_count) = params.peer_count {
            query.push(("numwant", peer_count.to_string()));
        }
        if let Some(ip) = &params.ip {
            query.push(("ip", ip.to_string()));
        }

        // hack:
        // reqwest uses serde_urlencoded which doesn't support encoding a raw
        // byte array into a percent encoded string. However, the tracker
        // expects the url encoded form of the raw info hash, so we need to be
        // able to map the raw bytes to its url encoded form. The peer id is
        // also stored as a raw byte array. Using `String::from_utf8_lossy`
        // would cause information loss.
        //
        // We do this using the separate percent_encoding crate, and by
        // "hard-coding" the info hash and the peer id into the url string. This
        // is the only way in which reqwest doesn't url encode again the custom
        // url encoded info hash. All other methods, such as mutating the query
        // parameters on the `Url` object, or by serializing the info hash with
        // `serde_bytes` do not work: they throw an error due to expecting valid
        // utf8.
        //
        // However, this is decidedly _not_ great: we're relying on an
        // undocumented edge case of a third party library (reqwest) that may
        // very well break in a future update.
        let url = format!(
            "{url}\
            ?info_hash={info_hash}\
            &peer_id={peer_id}",
            url = self.url,
            info_hash = percent_encoding::percent_encode(
                &params.info_hash,
                URL_ENCODE_RESERVED
            ),
            peer_id = percent_encoding::percent_encode(
                &params.peer_id,
                URL_ENCODE_RESERVED
            ),
        );

        // send request
        let resp = self
            .client
            .get(&url)
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let resp = serde_bencode::from_bytes(&resp)?;
        Ok(resp)
    }

    pub async fn announce_udp(&self, params: Announce) -> Result<Response> {
        let port = thread_rng().gen_range(1025..u16::MAX);
        let mut sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))
            .await
            .unwrap();

        let mut addr = self.url.socket_addrs(|| None).unwrap_or({
            let mut addr_vec = Vec::new();
            addr_vec.push(SocketAddr::from(([127, 0, 0, 1], random())));
            addr_vec
        });

        addr.shuffle(&mut thread_rng());

        let addr = {
            let mut addr_to_ret = SocketAddr::from(([127, 0, 0, 1], random()));

            for a in addr {
                if a.is_ipv4() {
                    addr_to_ret = a;
                    break;
                }
            }

            addr_to_ret
        };

        let mut failure_reason = None;

        let connection_id: u64 = match Tracker::connect_udp(addr).await {
            Some(id) => id,
            None => 0,
        };

        let action: u32 = 1;
        let transaction_id: u32 = random();
        let key: u32 = random();

        let mut bytes_to_send = BytesMut::with_capacity(150);
        bytes_to_send.put_u64(connection_id);
        bytes_to_send.put_u32(action);
        bytes_to_send.put_u32(transaction_id);
        bytes_to_send.put(&params.info_hash[..]);
        bytes_to_send.put(&params.peer_id[..]);
        bytes_to_send.put_u64(params.downloaded);
        bytes_to_send.put_u64(params.left);
        bytes_to_send.put_u32(match params.event {
            Some(val) => match val {
                crate::tracker::Event::Completed => 1,
                crate::tracker::Event::Started => 2,
                crate::tracker::Event::Stopped => 3,
            },
            None => 0,
        });
        match params.ip {
            Some(ip) => {
                match ip {
                    IpAddr::V4(ip) => {
                        bytes_to_send.put(&(ip.octets()[..]));
                    }

                    //The IP address field must be 32 bits wide, so if the IP given is v6, the field must be set to 0
                    IpAddr::V6(_) => {
                        bytes_to_send.put_u32(0);
                    }
                }
            }
            None => {
                bytes_to_send.put_u32(0);
            }
        };

        bytes_to_send.put_u32(key);
        bytes_to_send.put_i32(match params.peer_count {
            Some(num) => num.try_into().unwrap(),
            None => -1,
        });
        bytes_to_send.put_u16(params.port);

        let bytes_to_send = &bytes_to_send;

        const MAX_NUM_PEERS: usize = 2048;

        //Supporting around a few hundred peers, just for the test

        let mut response_buf: [u8; MAX_NUM_PEERS] = [0; MAX_NUM_PEERS];

        sock.send_to(bytes_to_send, addr).await.unwrap();
        let wait_time = match connection_id {
            0 => Duration::from_secs(0),
            _ => Duration::from_secs(3),
        };

        match timeout(wait_time, sock.recv_from(&mut response_buf)).await {
            Ok(_) => (),
            Err(_) => {
                failure_reason =
                    Some(String::from("Couldn't announce to tracker"))
            }
        };

        let transaction_id_recv: u32 =
            u32::from_be_bytes((&response_buf[4..8]).try_into().unwrap());

        let leechers: u32 =
            u32::from_be_bytes((&response_buf[12..16]).try_into().unwrap());
        let seeders: u32 =
            u32::from_be_bytes((&response_buf[16..20]).try_into().unwrap());

        let mut peer_vec: Vec<SocketAddr> = Vec::new();

        let mut index: usize = 20;

        while index <= response_buf.len() - 6 {
            let peer_ip_bytes: [u8; 4] =
                response_buf[index..index + 4].try_into().unwrap();
            let peer_port_bytes: [u8; 2] =
                response_buf[index + 4..index + 6].try_into().unwrap();

            if peer_ip_bytes != [0; 4] && peer_port_bytes != [0; 2] {
                let peer_ipv4 = Ipv4Addr::from(peer_ip_bytes);
                let peer_string = peer_ipv4.to_string();
                let peer_port_bytes: [u8; 2] =
                    response_buf[index + 4..index + 6].try_into().unwrap();
                let peer_port: u16 = u16::from_be_bytes(peer_port_bytes);
                let peer_string = format!("{}:{}", peer_string, peer_port);
                let peer_sock: SocketAddr = peer_string.parse().unwrap();

                peer_vec.push(peer_sock);

                index += 6;
            } else {
                break;
            }
        }

        if &transaction_id != &transaction_id_recv {
            failure_reason =
                Some(String::from("Transaction ID's did not match"));
        }

        let response = Response {
            tracker_id: Some(transaction_id_recv.to_string()),
            failure_reason,
            warning_message: None,
            min_interval: None,
            interval: Some(Duration::from_secs(9)),
            leecher_count: Some(leechers.try_into().unwrap()),
            seeder_count: Some(seeders.try_into().unwrap()),
            peers: peer_vec,
        };
        if connection_id != 0 && response_buf != [0; MAX_NUM_PEERS] {
            println!("{:?}", response);
        }
        Ok(response)
    }
}

impl fmt::Display for Tracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "'{}'", self.url)
    }
}

/// Peers can be sent in two ways: as a bencoded list of dicts including full
/// peer metadata, or as a single bencoded string that contains only the peer IP
/// and port (compact representation). This helper method deserializes both into
/// the same type, discarding the peer id present in the full representation.
/// This is because most trackers send the compact response by default, and
/// because cratetorrent doesn't make use of the peer id at the stage of
/// receiving a peer list from the tracker, so it is discarded for simplicity.
///
/// https://serde.rs/field-attrs.html#deserialize_with
/// https://users.rust-lang.org/t/need-help-with-serde-deserialize-with/18374/2
fn deserialize_peers<'de, D>(
    deserializer: D,
) -> Result<Vec<SocketAddr>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = Vec<SocketAddr>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or list of dicts representing peers")
        }

        // TODO: we can possibly simplify this by deserializing into an untagged
        // enum where one of the enums has a `serde(with = "serde_bytes")`
        // attribute for the compact list

        /// Deserializes a compact string of peers.
        ///
        /// Each entry is 6 bytes long, where the first 4 bytes are the IPv4
        /// address of the peer, and the last 2 bytes are the port of the peer.
        /// Both are in network byte order.
        fn visit_bytes<E>(self, mut b: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            // in compact representation each peer must be 6 bytes
            // long
            const ENTRY_LEN: usize = 6;
            let buf_len = b.len();

            if buf_len % ENTRY_LEN != 0 {
                return Err(TrackerError::Bencode(BencodeError::InvalidValue(
                    "peers compact string must be a multiple of 6".into(),
                )))
                .map_err(E::custom);
            }

            let buf_len = b.len();
            let mut peers = Vec::with_capacity(buf_len / ENTRY_LEN);

            for _ in (0..buf_len).step_by(ENTRY_LEN) {
                let addr = Ipv4Addr::from(b.get_u32());
                let port = b.get_u16();
                let peer = SocketAddr::new(IpAddr::V4(addr), port);
                peers.push(peer);
            }

            Ok(peers)
        }

        /// Deserializes a list of dicts containing the peer information.
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            #[derive(Debug, Deserialize)]
            struct RawPeer {
                ip: String,
                port: u16,
            }

            let mut peers = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(RawPeer { ip, port }) = seq.next_element()? {
                let ip = if let Ok(ip) = ip.parse() {
                    ip
                } else {
                    continue;
                };
                peers.push(SocketAddr::new(ip, port));
            }

            Ok(peers)
        }
    }

    deserializer.deserialize_any(Visitor)
}

/// Deserializes an integer representing seconds into a `Duration`.
fn deserialize_seconds<'de, D>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: Option<u64> = de::Deserialize::deserialize(deserializer)?;
    Ok(s.map(Duration::from_secs))
}

/// Contains the characters that need to be URL encoded according to:
/// https://en.wikipedia.org/wiki/Percent-encoding#Types_of_URI_characters
const URL_ENCODE_RESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'~')
    .remove(b'.');

#[cfg(test)]
mod tests {
    use mockito::{mock, Matcher};

    use super::*;

    #[derive(Deserialize)]
    struct PeersResponse {
        #[serde(deserialize_with = "deserialize_peers")]
        peers: Vec<SocketAddr>,
    }

    #[test]
    fn should_parse_compact_peer_list() {
        let ip = Ipv4Addr::new(192, 168, 0, 10);
        let port = 49123;

        // build up encoded byte string
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"d5:peers");
        encoded.extend_from_slice(&encode_compact_peers_list(&[(ip, port)]));
        encoded.push(b'e');

        let decoded: PeersResponse = serde_bencode::from_bytes(&encoded)
            .expect("cannot decode bencode string of peers");
        let addr = SocketAddr::new(ip.into(), port);
        assert_eq!(decoded.peers, vec![addr]);
    }

    #[test]
    fn should_parse_full_peer_list() {
        #[derive(Debug, Serialize)]
        struct RawPeer {
            ip: String,
            port: u16,
        }

        #[derive(Debug, Serialize)]
        struct RawPeers {
            peers: Vec<RawPeer>,
        }

        let peers = RawPeers {
            peers: vec![
                RawPeer {
                    ip: "192.168.1.10".into(),
                    port: 55123,
                },
                RawPeer {
                    ip: "1.45.96.2".into(),
                    port: 1234,
                },
                RawPeer {
                    ip: "123.123.123.123".into(),
                    port: 49950,
                },
            ],
        };

        let encoded = serde_bencode::to_string(&peers).unwrap();

        let decoded: PeersResponse = serde_bencode::from_str(&encoded)
            .expect("cannot decode bencode list of peers");
        let expected: Vec<_> = peers
            .peers
            .iter()
            .map(|p| SocketAddr::new(p.ip.parse().unwrap(), p.port))
            .collect();
        assert_eq!(decoded.peers, expected);
    }

    #[tokio::test]
    async fn should_return_peers_on_announce() {
        let addr = mockito::server_url();
        let tracker = Tracker::new((addr.parse().unwrap(), false));

        let info_hash_str = "abcdefghij1234567890";
        let mut info_hash = [0; 20];
        info_hash.copy_from_slice(info_hash_str.as_bytes());

        let peer_id_str = "cbt-2020-03-03-00000";
        let mut peer_id = [0; 20];
        peer_id.copy_from_slice(peer_id_str.as_bytes());

        let announce = Announce {
            info_hash,
            peer_id,
            port: 16,
            downloaded: 1234,
            uploaded: 1234,
            left: 1234,
            peer_count: Some(2),
            ip: None,
            event: None,
            tracker_id: None,
        };
        let peer_ip = Ipv4Addr::new(2, 156, 201, 254);
        let peer_port = 49123;
        let expected_resp = Response {
            tracker_id: None,
            failure_reason: None,
            warning_message: None,
            interval: Some(Duration::from_secs(15)),
            min_interval: Some(Duration::from_secs(10)),
            seeder_count: Some(5),
            leecher_count: Some(3),
            peers: vec![SocketAddr::new(peer_ip.into(), peer_port)],
        };

        let mut encoded_resp = Vec::new();
        // unterminated dict
        encoded_resp.extend_from_slice(
            b"d\
            8:completei5e\
            10:incompletei3e\
            8:intervali15e\
            12:min intervali10e",
        );
        // insert peers field into dict
        encoded_resp.extend_from_slice(b"5:peers");
        encoded_resp.extend_from_slice(&encode_compact_peers_list(&[(
            peer_ip, peer_port,
        )]));
        // terminate dict
        encoded_resp.push(b'e');

        let _m = mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("compact".into(), "1".into()),
                Matcher::UrlEncoded("info_hash".into(), info_hash_str.into()),
                Matcher::UrlEncoded("peer_id".into(), peer_id_str.into()),
                Matcher::UrlEncoded("port".into(), announce.port.to_string()),
                Matcher::UrlEncoded(
                    "downloaded".into(),
                    announce.downloaded.to_string(),
                ),
                Matcher::UrlEncoded(
                    "uploaded".into(),
                    announce.uploaded.to_string(),
                ),
                Matcher::UrlEncoded("left".into(), announce.left.to_string()),
                Matcher::UrlEncoded(
                    "numwant".into(),
                    announce.peer_count.unwrap().to_string(),
                ),
            ]))
            .with_status(200)
            .with_body(encoded_resp)
            .create();

        let resp = tracker.announce(announce).await.unwrap();
        assert_eq!(resp, expected_resp);
    }

    fn encode_compact_peers_list(peers: &[(Ipv4Addr, u16)]) -> Vec<u8> {
        let encoded_peers: Vec<_> = peers
            .into_iter()
            .map(|(ip, port)| {
                ip.octets()
                    .iter()
                    .chain([(port >> 8) as u8, (port & 0xff) as u8].iter())
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect();

        let mut encoded = Vec::new();
        encoded.extend_from_slice(encoded_peers.len().to_string().as_bytes());
        encoded.push(b':');
        encoded.extend_from_slice(&encoded_peers);

        encoded
    }
}
