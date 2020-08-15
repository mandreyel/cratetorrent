mod codec;

use {
    futures::{
        select,
        stream::{Fuse, SplitSink},
        SinkExt, StreamExt,
    },
    std::{net::SocketAddr, sync::Arc},
    tokio::{
        net::TcpStream,
        sync::{
            mpsc::{self, UnboundedReceiver, UnboundedSender},
            RwLock,
        },
    },
    tokio_util::codec::{Framed, FramedParts},
};

use {
    crate::{
        disk::DiskHandle, download::PieceDownload, error::*,
        piece_picker::PiecePicker, torrent::SharedStatus, Bitfield, BlockInfo,
        PeerId,
    },
    codec::*,
};

pub(crate) struct PeerSession {
    /// Shared information of the torrent.
    torrent: Arc<SharedStatus>,
    /// The piece picker picks the next most optimal piece to download and is
    /// shared by other entities in the same torrent.
    piece_picker: Arc<RwLock<PiecePicker>>,
    /// The entity used to save downloaded file blocks to disk.
    disk: DiskHandle,
    /// The port on which peer session receives commands.
    cmd_port: Fuse<Receiver>,
    /// The remote address of the peer.
    addr: SocketAddr,
    /// Session related information.
    status: Status,
    /// These are the active piece downloads in which this session is
    /// participating.
    downloads: Vec<PieceDownload>,
    /// Our pending requests that we sent to peer. It represents the blocks that
    /// we are expecting. Thus, if we receive a block that is not in this list,
    /// it is dropped. If we receive a block whose request entry is in here, the
    /// entry is removed.
    ///
    /// Since the Fast extension is not supported (yet), this is emptied when
    /// we're choked, as in that case we don't expect outstanding requests to be
    /// served.
    ///
    /// Note that if a reuest for a piece's block is in this queue, there _must_
    /// be a corresponding entry for the piece download in `downloads`.
    // TODO(https://github.com/mandreyel/cratetorrent/issues/11): Can we store
    // this information in just PieceDownload so that we don't have to enforce
    // this invariant (keeping in mind that later PieceDownloads will be shared
    // among PeerSessions)?
    outgoing_requests: Vec<BlockInfo>,
    /// Information about a peer that is set after a successful handshake.
    peer_info: Option<PeerInfo>,
}

impl PeerSession {
    /// Creates a new outbound session with the peer at the given address.
    ///
    /// The peer needs to be a seed in order for us to download a file through
    /// this peer session, otherwise the session is aborted with an error.
    pub fn outbound(
        torrent: Arc<SharedStatus>,
        piece_picker: Arc<RwLock<PiecePicker>>,
        disk: DiskHandle,
        addr: SocketAddr,
    ) -> (Self, Sender) {
        let (cmd_chan, cmd_port) = mpsc::unbounded_channel();
        (
            Self {
                torrent,
                piece_picker,
                disk,
                cmd_port: cmd_port.fuse(),
                addr,
                status: Status::default(),
                downloads: Vec::new(),
                outgoing_requests: Vec::new(),
                peer_info: None,
            },
            cmd_chan,
        )
    }

    /// Starts the peer session and returns if the connection is closed or an
    /// error occurs.
    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting peer {} session", self.addr);

        log::info!("Connecting to peer {}", self.addr);
        self.status.state = State::Connecting;
        let socket = TcpStream::connect(self.addr).await?;
        log::info!("Connected to peer {}", self.addr);

        let mut socket = Framed::new(socket, HandshakeCodec);

        // this is an outbound connection, so we have to send the first
        // handshake
        self.status.state = State::Handshaking;
        let handshake =
            Handshake::new(self.torrent.info_hash, self.torrent.client_id);
        log::info!("Sending handshake to peer {}", self.addr);
        socket.send(handshake).await?;

        // receive peer's handshake
        log::info!("Waiting for peer {} handshake", self.addr);
        if let Some(peer_handshake) = socket.next().await {
            let peer_handshake = peer_handshake?;
            log::info!("Received handshake from peer {}", self.addr);
            log::debug!("Peer {} handshake: {:?}", self.addr, peer_handshake);
            // codec should only return handshake if the protocol string in it
            // is valid
            debug_assert_eq!(peer_handshake.prot, PROTOCOL_STRING.as_bytes());

            // verify that the advertised torrent info hash is the same as ours
            if peer_handshake.info_hash != self.torrent.info_hash {
                log::info!("Peer {} handshake invalid info hash", self.addr);
                // abort session, info hash is invalid
                return Err(Error::InvalidPeerInfoHash);
            }

            // set basic peer information
            self.peer_info = Some(PeerInfo {
                peer_id: handshake.peer_id,
                pieces: None,
            });

            // now that we have the handshake, we need to switch to the peer
            // message codec and save the socket in self (note that we need to
            // keep the buffer from the original codec as it may contain bytes
            // of any potential message the peer may have sent after the
            // handshake)
            let old_parts = socket.into_parts();
            let mut new_parts = FramedParts::new(old_parts.io, PeerCodec);
            // reuse buffers of previous codec
            new_parts.read_buf = old_parts.read_buf;
            new_parts.write_buf = old_parts.write_buf;
            let socket = Framed::from_parts(new_parts);

            // enter the piece availability exchange state until peer sends a
            // bitfield (we don't send one as we currently only implement
            // downloading so we cannot have piece availability until multiple
            // peer connections or resuming a torrent is implemented)
            self.status.state = State::AvailabilityExchange;
            log::info!(
                "Peer {} session state: {:?}",
                self.addr,
                self.status.state
            );

            // run the session
            self.run(socket).await?;
        }
        // TODO(https://github.com/mandreyel/cratetorrent/issues/20): handle
        // not recieving anything with an error rather than an Ok(())

        Ok(())
    }

    /// Runs the session after connection to peer is established.
    ///
    /// This is the main session "loop" and performs the core of the session
    /// logic: exchange of messages, timeout logic, etc.
    async fn run(
        &mut self,
        socket: Framed<TcpStream, PeerCodec>,
    ) -> Result<()> {
        // split the sink and stream so that we can pass the sink while holding
        // a reference to the stream in the loop
        let (mut sink, stream) = socket.split();
        let mut stream = stream.fuse();

        // start the loop for receiving messages from peer and commands from
        // other parts of the engine
        loop {
            select! {
                msg = stream.select_next_some() => {
                    let msg = msg?;
                    log::debug!(
                        "Received message {} from peer {:?}",
                        self.addr,
                        msg.id()
                    );

                    // handle bitfield message separately as it may only be
                    // received directly after the handshake (later once we
                    // implement the FAST extension, there will be other piece
                    // availability related messages to handle)
                    if self.status.state == State::AvailabilityExchange {
                        if let Message::Bitfield(bitfield) = msg {
                            self.handle_bitfield_msg(&mut sink, bitfield).await?;
                        } else {
                            // since we expect peer to be a seed, we *must* get
                            // a bitfield message, as otherwise we assume the
                            // peer to be a leech with no pieces to share (which
                            // is not good for our purposes of downloading
                            // a file)
                            log::warn!(
                                "Peer {} hasn't sent bitfield, cannot download",
                                self.addr
                            );
                            return Err(Error::PeerNotSeed);
                        }

                        // enter connected state
                        self.status.state = State::Connected;
                        log::info!(
                            "Peer {} session state: {:?}",
                            self.addr,
                            self.status.state
                        );
                    } else {
                        self.handle_msg(&mut sink, msg).await?;
                    }
                }
                cmd = self.cmd_port.select_next_some() => {
                    match cmd {
                        Command::Shutdown => {
                            log::info!("Shutting down peer {} session", self.addr);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handles a message expected in the `AvailabilityExchange` state
    /// (currently only the bitfield message).
    async fn handle_bitfield_msg(
        &mut self,
        sink: &mut SplitSink<Framed<TcpStream, PeerCodec>, Message>,
        mut bitfield: Bitfield,
    ) -> Result<()> {
        debug_assert_eq!(self.status.state, State::AvailabilityExchange);
        log::info!("Handling peer {} Bitfield message", self.addr);
        log::trace!("Bitfield: {:?}", bitfield);

        // The bitfield raw data that is sent over the wire may be longer than
        // the logical pieces it represents, if there the number of pieces in
        // torrent is not a multiple of 8. Therefore, we need to slice off the
        // last part of the bitfield.
        bitfield.resize(self.torrent.storage.piece_count, false);

        // if peer is not a seed, we abort the connection as we only
        // support downloading and for that we must be connected to
        // a seed (otherwise we couldn't download the whole torrent)
        if !bitfield.all() {
            log::warn!("Peer {} is not a seed, cannot download", self.addr);
            return Err(Error::PeerNotSeed);
        }

        // register peer's pieces with piece picker
        let mut piece_picker = self.piece_picker.write().await;
        self.status.is_interested =
            piece_picker.register_availability(&bitfield)?;
        debug_assert!(self.status.is_interested);
        if let Some(peer_info) = &mut self.peer_info {
            peer_info.pieces = Some(bitfield);
        }

        // send interested message to peer
        log::info!("Interested in peer {}", self.addr);
        sink.send(Message::Interested).await?;
        // This is the start of the download, so set the request
        // queue size so we can request blocks. Set it
        // optimistically to 4 for now, but later we'll have a TCP
        // like slow start algorithm for quickly finding the ideal
        // request queue size.
        self.status.best_request_queue_len = Some(4);

        Ok(())
    }

    /// Handles messages expected in the `Connected` state.
    async fn handle_msg(
        &mut self,
        sink: &mut SplitSink<Framed<TcpStream, PeerCodec>, Message>,
        msg: Message,
    ) -> Result<()> {
        match msg {
            Message::Bitfield(_) => {
                log::info!(
                    "Peer {} sent bitfield message not after handshake",
                    self.addr
                );
                return Err(Error::BitfieldNotAfterHandshake);
            }
            Message::KeepAlive => {
                log::info!("Peer {} sent keep alive", self.addr);
            }
            Message::Choke => {
                if !self.status.is_choked {
                    log::info!("Peer {} choked us", self.addr);
                    // since we're choked we don't expect to receive blocks
                    // for our pending requests
                    self.outgoing_requests.clear();
                    self.status.is_choked = true;
                }
            }
            Message::Unchoke => {
                if self.status.is_choked {
                    log::info!("Peer {} unchoked us", self.addr);
                    self.status.is_choked = false;
                    // now that we are allowed to request blocks, start the
                    // download pipeline if we're interested
                    self.make_requests(sink).await?;
                }
            }
            Message::Interested => {
                if !self.status.is_peer_interested {
                    log::info!("Peer {} is interested", self.addr);
                    self.status.is_peer_interested = true;
                }
            }
            Message::NotInterested => {
                if self.status.is_peer_interested {
                    log::info!("Peer {} is not interested", self.addr);
                    self.status.is_peer_interested = false;
                }
            }
            Message::Block {
                piece_index,
                offset,
                data,
            } => {
                let block_info = BlockInfo {
                    piece_index,
                    offset,
                    len: data.len() as u32,
                };
                self.handle_block_msg(block_info, data).await?;

                // we may be able to make more requests now that a block has
                // arrived
                self.make_requests(sink).await?;
            }
            // these messages are not expected until seed functionality is added
            Message::Have { .. } => {
                log::warn!(
                    "Seed {} sent unexpected message: {:?}",
                    self.addr,
                    MessageId::Have
                );
            }
            Message::Request(_) => {
                log::warn!(
                    "Seed {} sent unexpected message: {:?}",
                    self.addr,
                    MessageId::Request
                );
            }
            Message::Cancel(_) => {
                log::warn!(
                    "Seed {} sent unexpected message: {:?}",
                    self.addr,
                    MessageId::Cancel
                );
            }
        }

        Ok(())
    }

    /// Fills the session's download pipeline with the optimal number of
    /// requests.
    ///
    /// To see what this means, please refer to the
    /// `Status::best_request_queue_len` or the relevant section in DESIGN.md.
    async fn make_requests(
        &mut self,
        sink: &mut SplitSink<Framed<TcpStream, PeerCodec>, Message>,
    ) -> Result<()> {
        log::trace!("Making requests to peer {}", self.addr);

        // TODO: optimize this by preallocating the vector in self
        let mut blocks = Vec::new();

        // If we have active downloads, prefer to continue those. This will
        // result in less in-progress pieces.
        for download in self.downloads.iter_mut() {
            log::debug!(
                "Peer {} trying to continue download {}",
                self.addr,
                download.piece_index()
            );

            // our outgoing request queue shouldn't exceed the allowed request
            // queue size
            debug_assert!(
                self.status.best_request_queue_len.unwrap_or_default()
                    >= self.outgoing_requests.len()
            );
            // the number of requests we can make now
            let to_request_count =
                self.status.best_request_queue_len.unwrap_or_default()
                    - self.outgoing_requests.len();
            if to_request_count == 0 {
                break;
            }

            // TODO: should we not check first that we aren't already
            // downloading all of the piece's blocks?

            // request blocks and register in our outgoing requests queue
            download.pick_blocks(to_request_count, &mut blocks);
        }

        // while we can make more requests we start new download(s)
        loop {
            // our outgoing request queue shouldn't exceed the allowed request
            // queue size
            debug_assert!(
                self.status.best_request_queue_len.unwrap_or_default()
                    >= self.outgoing_requests.len()
            );
            let request_queue_len =
                self.status.best_request_queue_len.unwrap_or_default()
                    - self.outgoing_requests.len();
            if request_queue_len == 0 {
                break;
            }

            log::debug!("Session {} starting new piece download", self.addr);

            let mut piece_picker = self.piece_picker.write().await;
            if let Some(index) = piece_picker.pick_piece() {
                log::info!("Session {} picked piece {}", self.addr, index);

                let mut download = PieceDownload::new(
                    index,
                    self.torrent.storage.piece_len(index)?,
                );

                // request blocks and register in our outgoing requests queue
                download.pick_blocks(request_queue_len, &mut blocks);
                // save download
                self.downloads.push(download);
            } else {
                log::debug!(
                    "Could not pick more pieces from peer {}",
                    self.addr
                );
                break;
            }
        }

        // save current volley of requests
        self.outgoing_requests.extend_from_slice(&blocks);
        // make the actual requests
        for block in blocks.iter() {
            sink.send(Message::Request(*block)).await?;
        }

        Ok(())
    }

    /// Verifies block validity, registers the download (and finishes a piece
    /// download if this was the last missing block in piece) and updates
    /// statistics about the download.
    async fn handle_block_msg(
        &mut self,
        block_info: BlockInfo,
        data: Vec<u8>,
    ) -> Result<()> {
        log::info!("Received block from peer {}: {:?}", self.addr, block_info);

        // find block in the list of pending requests
        let block_pos = match self
            .outgoing_requests
            .iter()
            .position(|b| *b == block_info)
        {
            Some(pos) => pos,
            None => {
                log::warn!(
                    "Peer {} sent not requested block: {:?}",
                    self.addr,
                    block_info,
                );
                // silently ignore this block if we didn't expected
                // it
                //
                // TODO(https://github.com/mandreyel/cratetorrent/issues/10): In
                // the future we could add logic that accepts blocks within
                // a window after the last request. If not done, peer could DoS
                // us by sending unwanted blocks repeatedly.
                return Ok(());
            }
        };

        // remove block from our pending requests queue
        self.outgoing_requests.remove(block_pos);

        // mark the block as downloaded with its respective piece
        // download instance
        let download_pos = self
            .downloads
            .iter()
            .position(|d| d.piece_index() == block_info.piece_index);
        // this fires as a result of a broken invariant: we
        // shouldn't have an entry in `outgoing_requests` without a
        // corresponding entry in `downloads`
        //
        // TODO(https://github.com/mandreyel/cratetorrent/issues/11): can we
        // handle this without unwrapping?
        debug_assert!(download_pos.is_some());
        let download_pos = download_pos.unwrap();
        let download = &mut self.downloads[download_pos];
        download.received_block(block_info);

        // finish download of piece if this was the last missing block in it
        let missing_blocks_count = download.count_missing_blocks();
        if missing_blocks_count == 0 {
            log::info!(
                "Finished piece {} via peer {}",
                block_info.piece_index,
                self.addr
            );
            // register received piece
            self.piece_picker
                .write()
                .await
                .received_piece(block_info.piece_index);
            // remove piece download from `downloads`
            self.downloads.remove(download_pos);
        }

        // validate and save the block to disk by sending a write command to the
        // disk task
        self.disk.write_block(self.torrent.id, block_info, data)?;

        // adjust request statistics
        self.status.downloaded_block_bytes_count += block_info.len as u64;

        Ok(())
    }
}

/// The channel on which torrent can send a command to the peer session task.
pub(crate) type Sender = UnboundedSender<Command>;
type Receiver = UnboundedReceiver<Command>;

/// The commands peer session can receive.
pub(crate) enum Command {
    /// Eventually shut down the peer session.
    Shutdown,
}

/// The status of a peer session.
///
/// By default, both sides of the connection start off as choked and not
/// interested in the other.
#[derive(Clone, Copy, Debug)]
struct Status {
    /// The current state of the session.
    state: State,
    /// If we're cohked, peer doesn't allow us to download pieces from them.
    is_choked: bool,
    /// If we're interested, peer has pieces that we don't have.
    is_interested: bool,
    /// If peer is choked, we don't allow them to download pieces from us.
    is_peer_choked: bool,
    /// If peer is interested in us, they mean to download pieces that we have.
    is_peer_interested: bool,
    /// The request queue size, which is the number of block requests we keep
    /// outstanding to fully saturate the link.
    ///
    /// Each peer session needs to maintain an "optimal request queue size"
    /// value (approximately the bandwidth-delay product), which is the  number
    /// of block requests it keeps outstanding to fully saturate the link.
    ///
    /// This value is derived by collecting a running average of the downloaded
    /// bytes per second, as well as the average request latency, to arrive at
    /// the bandwidth-delay product B x D. This value is recalculated every time
    /// we receive a block, in order to always keep the link fully saturated.
    ///
    /// See more on
    /// [Wikipedia](https://en.wikipedia.org/wiki/Bandwidth-delay_product).
    ///
    /// Only set once we start downloading.
    best_request_queue_len: Option<usize>,
    /// The total number of bytes downloaded (protocol chatter and downloaded
    /// files).
    downloaded_bytes_count: u64,
    /// The number of piece/block bytes downloaded.
    downloaded_block_bytes_count: u64,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: State::default(),
            is_choked: true,
            is_interested: false,
            is_peer_choked: true,
            is_peer_interested: false,
            best_request_queue_len: None,
            downloaded_bytes_count: 0,
            downloaded_block_bytes_count: 0,
        }
    }
}

/// At any given time, a connection with a peer is in one of the below states.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum State {
    /// The peer connection has not yet been connected or it had been connected
    /// before but has been stopped.
    Disconnected,
    /// The state during which the TCP connection is established.
    Connecting,
    /// The state after establishing the TCP connection and exchanging the
    /// initial BitTorrent handshake.
    Handshaking,
    /// This state is optional, it is used to verify that the bitfield exchange
    /// occurrs after the handshake and not later. It is set once the handshakes
    /// are exchanged and changed as soon as we receive the bitfield or the the
    /// first message that is not a bitfield. Any subsequent bitfield messages
    /// are rejected and the connection is dropped, as per the standard.
    AvailabilityExchange,
    /// This is the normal state of a peer session, in which any messages, apart
    /// from the 'handshake' and 'bitfield', may be exchanged.
    Connected,
}

/// The default (and initial) state of a peer session is `Disconnected`.
impl Default for State {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// Information about the peer we're connected to.
struct PeerInfo {
    /// Peer's 20 byte BitTorrent id.
    peer_id: PeerId,
    /// All pieces peer has, updated when it announces to us a new piece.
    pieces: Option<Bitfield>,
}
