pub mod codec;

use crate::*;
use codec::*;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::io::Error;
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, FramedParts};

#[derive(Clone, Copy, Debug)]
pub enum State {
    Disconnected,
    Connecting,
    Handshaking,
    AvailabilityExchange,
    Connected,
    Disconnecting,
}

impl Default for State {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Status {
    is_choked: bool,
    is_interested: bool,
    is_peer_choked: bool,
    is_peer_interested: bool,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            is_choked: true,
            is_interested: false,
            is_peer_choked: true,
            is_peer_interested: false,
        }
    }
}

pub struct PeerSession {
    state: State,
    addr: SocketAddr,
    is_outbound: bool,
    socket: Option<TcpStream>,
    peer_id: PeerId,
    info_hash: Sha1Hash,
    status: Status,
}

impl PeerSession {
    pub fn outbound(
        addr: SocketAddr,
        peer_id: PeerId,
        info_hash: Sha1Hash,
    ) -> Self {
        Self {
            state: State::default(),
            addr,
            socket: None,
            is_outbound: true,
            status: Status::default(),
            peer_id,
            info_hash,
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        log::info!("Connecting to peer {}", self.addr);
        self.state = State::Connecting;
        let socket = TcpStream::connect(self.addr).await?;
        log::info!("Connected to peer {}", self.addr);

        let mut socket = Framed::new(socket, HandshakeCodec);

        // this is an outbound connection, so we have to send the first
        // handshake
        self.state = State::Handshaking;
        let handshake = Handshake::new(self.info_hash, self.peer_id);
        log::info!("Sending handshake to peer {}", self.addr);
        socket.send(handshake).await?;

        // receive peer's handshake
        log::info!("Receiving handshake from peer {}", self.addr);
        if let Some(peer_handshake) = socket.next().await {
            let peer_handshake = peer_handshake?;
            log::info!("Received handshake from peer {}", self.addr);
            log::debug!("Peer {} handshake: {:?}", self.addr, peer_handshake);
            // codec should only return handshake if the protocol string in it
            // is valid
            debug_assert_eq!(peer_handshake.prot, PROTOCOL_STRING.as_bytes());

            // verify that the advertised torrent info hash is the same as ours
            if peer_handshake.info_hash != self.info_hash {
                log::info!("Peer {} handshake invalid info hash", self.addr);
                // TODO: abort session, invalid peer id
            }

            // TODO: enter the piece availability exchange state until peer
            // sends a bitfield (we don't send one as we currently only
            // implement downloading so we cannot have piece availability until
            // resuming a torrent is implemented)
            self.state = State::Connected;
            log::info!("Peer {} session state: {:?}", self.addr, self.state);

            // now that we have the handshake, we need to switch to the peer
            // message codec
            let parts = socket.into_parts();
            let mut parts = FramedParts::new(parts.io, PeerCodec);
            // reuse buffers of previous codec
            parts.read_buf = parts.read_buf;
            parts.write_buf = parts.write_buf;
            let mut socket = Framed::from_parts(parts);

            // start receiving and sending messages
            while let Some(msg) = socket.next().await {
                let msg = msg?;
                log::info!(
                    "Received message from peer {}: {:?}",
                    self.addr,
                    msg
                );
            }
        }

        Ok(())
    }
}