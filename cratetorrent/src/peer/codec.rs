use std::{
    convert::{TryFrom, TryInto},
    io,
};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{Bitfield, BlockData, BlockInfo};

/// The message sent at the beginning of a peer session by both sides of the
/// connection.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Handshake {
    /// The protocol string, which must equal "BitTorrent protocol", as
    /// otherwise the connetion is aborted.
    pub prot: [u8; 19],
    /// A reserved field, currently all zeros. This is where the client's
    /// supported extensions are announced.
    pub reserved: [u8; 8],
    /// The torrent's SHA1 info hash, used to identify the torrent in the
    /// handshake and to verify the peer.
    pub info_hash: [u8; 20],
    /// The arbitrary peer id, usually used to identify the torrent client.
    pub peer_id: [u8; 20],
}

impl Handshake {
    /// Creates a new protocol version 1 handshake with the given info hash and
    /// peer id.
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        let mut prot = [0; 19];
        prot.copy_from_slice(PROTOCOL_STRING.as_bytes());
        Self {
            prot,
            reserved: [0; 8],
            info_hash,
            peer_id,
        }
    }

    /// Returns the length of the handshake, in bytes.
    pub const fn len(&self) -> u64 {
        19 + 8 + 20 + 20
    }
}

/// The protocol version 1 string included in the handshake.
pub(crate) const PROTOCOL_STRING: &str = "BitTorrent protocol";

/// Codec for encoding and decoding handshakes.
///
/// This has to be a separate codec as the handshake has a different structure
/// than the rest of the messages. Moreover, handshakes may only be sent once at
/// the beginning of a connection, preceding all other messages. Thus, after
/// receiving and sending a handshake the codec should be switched to
/// [`PeerCodec`], but care should be taken not to discard the underlying
/// receive and send buffers.
pub(crate) struct HandshakeCodec;

impl Encoder<Handshake> for HandshakeCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        handshake: Handshake,
        buf: &mut BytesMut,
    ) -> io::Result<()> {
        let Handshake {
            prot,
            reserved,
            info_hash,
            peer_id,
        } = handshake;

        // protocol length prefix
        debug_assert_eq!(prot.len(), 19);
        buf.put_u8(prot.len() as u8);
        // we should only be sending the bittorrent protocol string
        debug_assert_eq!(prot, PROTOCOL_STRING.as_bytes());
        // payload
        buf.extend_from_slice(&prot);
        buf.extend_from_slice(&reserved);
        buf.extend_from_slice(&info_hash);
        buf.extend_from_slice(&peer_id);

        Ok(())
    }
}

impl Decoder for HandshakeCodec {
    type Item = Handshake;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Handshake>> {
        if buf.is_empty() {
            return Ok(None);
        }

        // hack:
        // `get_*` integer extractors consume the message bytes by advancing
        // buf's internal cursor. However, we don't want to do this as at this
        // point we aren't sure we have the full message in the buffer, and thus
        // we just want to peek at this value.
        //
        // However, this is not supported by the `bytes` crate API
        // (https://github.com/tokio-rs/bytes/issues/382), so we need to work
        // this around by getting a reference to the underlying buffer and
        // performing the message length extraction on the returned slice, which
        // won't advance `buf`'s cursor
        let mut tmp_buf = buf.bytes();
        let prot_len = tmp_buf.get_u8() as usize;
        if prot_len != PROTOCOL_STRING.as_bytes().len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Handshake must have the string \"BitTorrent protocol\"",
            ));
        }

        // check that we got the full payload in the buffer (NOTE: we need to
        // add the message length prefix's byte count to msg_len since the
        // buffer cursor was not advanced and thus we need to consider the
        // prefix too)
        let payload_len = prot_len + 8 + 20 + 20;
        if buf.remaining() > payload_len {
            // we have the full message in the buffer so advance the buffer
            // cursor past the message length header
            buf.advance(1);
        } else {
            return Ok(None);
        }

        // protocol string
        let mut prot = [0; 19];
        buf.copy_to_slice(&mut prot);
        // reserved field
        let mut reserved = [0; 8];
        buf.copy_to_slice(&mut reserved);
        // info hash
        let mut info_hash = [0; 20];
        buf.copy_to_slice(&mut info_hash);
        // peer id
        let mut peer_id = [0; 20];
        buf.copy_to_slice(&mut peer_id);

        Ok(Some(Handshake {
            prot,
            reserved,
            info_hash,
            peer_id,
        }))
    }
}

/// The actual messages exchanged by peers.
#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub(crate) enum Message {
    KeepAlive,
    Bitfield(Bitfield),
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have {
        piece_index: usize,
    },
    Request(BlockInfo),
    Block {
        piece_index: usize,
        offset: u32,
        data: BlockData,
    },
    Cancel(BlockInfo),
}

impl Message {
    /// Returns the ID of the message, if it has one (e.g. keep alive doesn't).
    pub fn id(&self) -> Option<MessageId> {
        match self {
            Self::KeepAlive => None,
            Self::Bitfield(_) => Some(MessageId::Bitfield),
            Self::Choke => Some(MessageId::Choke),
            Self::Unchoke => Some(MessageId::Unchoke),
            Self::Interested => Some(MessageId::Interested),
            Self::NotInterested => Some(MessageId::NotInterested),
            Self::Have { .. } => Some(MessageId::Have),
            Self::Request(_) => Some(MessageId::Request),
            Self::Block { .. } => Some(MessageId::Block),
            Self::Cancel(_) => Some(MessageId::Cancel),
        }
    }

    /// Returns the length of the part of the message that constitutes the
    /// message header. For all but the block message this is simply the size of
    /// the message. For the block message this is the message header.
    pub fn protocol_len(&self) -> u64 {
        if let Some(id) = self.id() {
            id.header_len()
        } else {
            assert_eq!(*self, Self::KeepAlive);
            1
        }
    }
}

/// The ID of a message, which is included as a prefix in most messages.
///
/// The handshake and keep alive messages don't have explicit IDs.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum MessageId {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Block = 7,
    Cancel = 8,
}

impl MessageId {
    /// Returns the header length of the specific message type.
    ///
    /// Since this is fix size for all messages, it can be determined simply
    /// from the message id.
    pub fn header_len(&self) -> u64 {
        match self {
            Self::Choke => 4 + 1,
            Self::Unchoke => 4 + 1,
            Self::Interested => 4 + 1,
            Self::NotInterested => 4 + 1,
            Self::Have => 4 + 1 + 4,
            Self::Bitfield => 4 + 1,
            Self::Request => 4 + 1 + 3 * 4,
            Self::Block => 4 + 1 + 2 * 4,
            Self::Cancel => 4 + 1 + 3 * 4,
        }
    }
}

impl TryFrom<u8> for MessageId {
    type Error = io::Error;

    fn try_from(k: u8) -> Result<Self, Self::Error> {
        use MessageId::*;
        match k {
            k if k == Choke as u8 => Ok(Choke),
            k if k == Unchoke as u8 => Ok(Unchoke),
            k if k == Interested as u8 => Ok(Interested),
            k if k == NotInterested as u8 => Ok(NotInterested),
            k if k == Have as u8 => Ok(Have),
            k if k == Bitfield as u8 => Ok(Bitfield),
            k if k == Request as u8 => Ok(Request),
            k if k == Block as u8 => Ok(Block),
            k if k == Cancel as u8 => Ok(Cancel),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown message id",
            )),
        }
    }
}

impl BlockInfo {
    /// Encodes the block info in the network binary protocol's format into the
    /// given buffer.
    fn encode(&self, buf: &mut BytesMut) -> io::Result<()> {
        let piece_index = self
            .piece_index
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        buf.put_u32(piece_index);
        buf.put_u32(self.offset);
        buf.put_u32(self.len);
        Ok(())
    }
}

/// Codec for encoding and decoding messages exchanged by peers (other than the
/// handshake).
pub(crate) struct PeerCodec;

impl Encoder<Message> for PeerCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: Message, buf: &mut BytesMut) -> io::Result<()> {
        use Message::*;
        match msg {
            KeepAlive => {
                // message length prefix
                let msg_len = 0;
                buf.put_u32(msg_len);
                // no payload
            }
            Bitfield(bitfield) => {
                // message length prefix: 1 byte message id and n byte bitfield
                //
                // NOTE: take the length of the underlying storage to get the number
                // of _bytes_, as `bitfield.len()` returns the number of _bits_
                let msg_len = 1 + bitfield.as_slice().len();
                buf.put_u32(msg_len as u32);
                // message id
                buf.put_u8(MessageId::Bitfield as u8);
                // payload
                buf.extend_from_slice(bitfield.as_slice());
            }
            Choke => {
                // message length prefix: 1 byte message id
                let msg_len = 1;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Choke as u8);
                // no payload
            }
            Unchoke => {
                // message length prefix: 1 byte message id
                let msg_len = 1;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Unchoke as u8);
                // no payload
            }
            Interested => {
                // message length prefix: 1 byte message id
                let msg_len = 1;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Interested as u8);
                // no payload
            }
            NotInterested => {
                // message length prefix: 1 byte message id
                let msg_len = 1;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::NotInterested as u8);
                // no payload
            }
            Have { piece_index } => {
                // message length prefix:
                // 1 byte message id and 4 byte piece index
                let msg_len = 1 + 4;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Have as u8);
                // payload
                let piece_index = piece_index.try_into().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                buf.put_u32(piece_index);
            }
            Request(block) => {
                // message length prefix:
                // 1 byte message id, 4 byte piece index, 4 byte offset, 4 byte
                // length
                let msg_len = 1 + 4 + 4 + 4;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Request as u8);
                // payload
                block.encode(buf)?;
            }
            Block {
                piece_index,
                offset,
                data,
            } => {
                // message length prefix:
                // 1 byte message id, 4 byte piece index, 4 byte offset, and n byte
                // block
                let msg_len = 1 + 4 + 4 + data.len() as u32;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Block as u8);
                // payload
                let piece_index = piece_index.try_into().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                buf.put_u32(piece_index);
                buf.put_u32(offset);
                buf.put(&data[..]);
            }
            Cancel(block) => {
                // message length prefix:
                // 1 byte message id, 4 byte piece index, 4 byte offset, 4 byte
                // length
                let msg_len = 1 + 4 + 4 + 4;
                buf.put_u32(msg_len);
                // message id
                buf.put_u8(MessageId::Cancel as u8);
                // payload
                block.encode(buf)?;
            }
        }

        Ok(())
    }
}

impl Decoder for PeerCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        log::trace!("Decoder has {} byte(s) remaining", buf.remaining());

        // the message length header must be present at the minimum, otherwise
        // we can't determine the message type
        if buf.remaining() < 4 {
            return Ok(None);
        }

        // hack:
        // `get_*` integer extractors consume the message bytes by advancing
        // buf's internal cursor. However, we don't want to do this as at this
        // point we aren't sure we have the full message in the buffer, and thus
        // we just want to peek at this value.
        //
        // However, this is not supported by the `bytes` crate API
        // (https://github.com/tokio-rs/bytes/issues/382), so we need to work
        // this around by getting a reference to the underlying buffer and
        // performing the message length extraction on the returned slice, which
        // won't advance `buf`'s cursor
        let mut tmp_buf = buf.bytes();
        let msg_len = tmp_buf.get_u32() as usize;

        // check that we got the full payload in the buffer (NOTE: we need to
        // add the message length prefix's byte count to msg_len since the
        // buffer cursor was not advanced and thus we need to consider the
        // prefix too)
        if buf.remaining() >= 4 + msg_len {
            // we have the full message in the buffer so advance the buffer
            // cursor past the message length header
            buf.advance(4);
            // the message length is only 0 if this is a keep alive message (all
            // other message types have at least one more field, the message id)
            if msg_len == 0 {
                return Ok(Some(Message::KeepAlive));
            }
        } else {
            log::trace!(
                "Read buffer is {} bytes long but message is {} bytes long",
                buf.remaining(),
                msg_len
            );
            return Ok(None);
        }

        let msg_id = MessageId::try_from(buf.get_u8())?;
        let msg = match msg_id {
            MessageId::Choke => Message::Choke,
            MessageId::Unchoke => Message::Unchoke,
            MessageId::Interested => Message::Interested,
            MessageId::NotInterested => Message::NotInterested,
            MessageId::Have => {
                let piece_index = buf.get_u32();
                let piece_index = piece_index.try_into().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                Message::Have { piece_index }
            }
            MessageId::Bitfield => {
                // preallocate buffer to the length of bitfield, which is the
                // value gotten by subtracting the id length from the message
                // length
                let mut bitfield = vec![0; msg_len - 1];
                buf.copy_to_slice(&mut bitfield);
                Message::Bitfield(Bitfield::from_vec(bitfield))
            }
            MessageId::Request => {
                let piece_index = buf.get_u32();
                let offset = buf.get_u32();
                let len = buf.get_u32();
                let piece_index = piece_index.try_into().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                Message::Request(BlockInfo {
                    piece_index,
                    offset,
                    len,
                })
            }
            MessageId::Block => {
                // TODO: this shouldn't be a debug asset as we're dealing with
                // unknown input
                debug_assert!(msg_len > 9);
                let piece_index = buf.get_u32();
                let piece_index = piece_index.try_into().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                let offset = buf.get_u32();
                // preallocate the vector to the block length, by subtracting
                // the id, piece index and offset lengths from the message
                // length
                //
                // TODO: here we would want to copy into a pre-allocated buffer
                // rather than create a new buffer, created outside the message
                // codec
                let mut data = vec![0; msg_len - 9];
                buf.copy_to_slice(&mut data);
                Message::Block {
                    piece_index,
                    offset,
                    data: data.into(),
                }
            }
            MessageId::Cancel => {
                let piece_index = buf.get_u32();
                let piece_index = piece_index.try_into().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                let offset = buf.get_u32();
                let len = buf.get_u32();
                Message::Cancel(BlockInfo {
                    piece_index,
                    offset,
                    len,
                })
            }
        };

        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::BLOCK_LEN;

    /// Tests a stream of arbitrary messages to ensure that not only do they
    /// encode and then decode correctly (like the individual test cases
    /// ascertain), but that the buffer cursor is properly advanced by the codec
    /// implementation in both cases.
    #[test]
    fn test_message_stream() {
        let (handshake, encoded_handshake) = make_handshake();
        let msgs = [
            make_choke(),
            make_unchoke(),
            make_keep_alive(),
            make_interested(),
            make_not_interested(),
            make_bitfield(),
            make_have(),
            make_request(),
            make_block(),
            make_block(),
            make_keep_alive(),
            make_interested(),
            make_cancel(),
            make_block(),
            make_not_interested(),
            make_choke(),
            make_choke(),
        ];

        // create byte stream of all above messages
        let msgs_len =
            msgs.iter().fold(0, |acc, (_, encoded)| acc + encoded.len());
        let mut read_buf = BytesMut::with_capacity(msgs_len);
        read_buf.extend_from_slice(&encoded_handshake);
        for (_, encoded) in &msgs {
            read_buf.extend_from_slice(&encoded);
        }

        // decode messages one by one from the byte stream in the same order as
        // they were encoded, starting with the handshake
        let decoded_handshake = HandshakeCodec.decode(&mut read_buf).unwrap();
        assert_eq!(decoded_handshake, Some(handshake));
        for (msg, _) in &msgs {
            let decoded_msg = PeerCodec.decode(&mut read_buf).unwrap();
            assert_eq!(decoded_msg.unwrap(), *msg);
        }
    }

    // This test attempts to simulate a closer to real world use case than
    // `test_test_message_stream`, by progresively loading up the codec's read
    // buffer with the encoded message bytes, asserting that messages are
    // decoded correctly even if their bytes arrives in different chunks.
    //
    // This is a regression test in that there used to be a bug that failed to
    // parse block messages (the largest message type) if the full message
    // couldn't be received (as is often the case).
    #[test]
    fn test_chunked_message_stream() {
        let mut read_buf = BytesMut::new();

        // start with the handshake by adding only the first half of it to the
        // buffer
        let (handshake, encoded_handshake) = make_handshake();
        let handshake_split_pos = encoded_handshake.len() / 2;
        read_buf.extend_from_slice(&encoded_handshake[0..handshake_split_pos]);

        // can't decode the handshake without the full message
        assert!(HandshakeCodec.decode(&mut read_buf).unwrap().is_none());

        // the handshake should successfully decode with the second half added
        read_buf.extend_from_slice(&encoded_handshake[handshake_split_pos..]);
        let decoded_handshake = HandshakeCodec.decode(&mut read_buf).unwrap();
        assert_eq!(decoded_handshake, Some(handshake));

        let msgs = [
            make_choke(),
            make_unchoke(),
            make_interested(),
            make_not_interested(),
            make_bitfield(),
            make_have(),
            make_request(),
            make_block(),
            make_block(),
            make_interested(),
            make_cancel(),
            make_block(),
            make_not_interested(),
            make_choke(),
            make_choke(),
        ];

        // go through all above messages and do the same procedure as with the
        // handshake: add the first half, fail to decode, add the second half,
        // decode successfully
        for (msg, encoded) in &msgs {
            // add the first half of the message
            let split_pos = encoded.len() / 2;
            read_buf.extend_from_slice(&encoded[0..split_pos]);
            // fail to decode
            assert!(PeerCodec.decode(&mut read_buf).unwrap().is_none());
            // add the second half
            read_buf.extend_from_slice(&encoded[split_pos..]);
            let decoded_msg = PeerCodec.decode(&mut read_buf).unwrap();
            assert_eq!(decoded_msg.unwrap(), *msg);
        }
    }

    /// Tests the encoding and subsequent decoding of a valid handshake.
    #[test]
    fn test_handshake_codec() {
        let (handshake, expected_encoded) = make_handshake();

        // encode handshake
        let mut encoded = BytesMut::with_capacity(expected_encoded.len());
        HandshakeCodec.encode(handshake, &mut encoded).unwrap();
        assert_eq!(encoded, expected_encoded);

        // don't decode handshake if there aren't enough bytes in source buffer
        let mut partial_encoded = encoded[0..30].into();
        let decoded = HandshakeCodec.decode(&mut partial_encoded).unwrap();
        assert_eq!(decoded, None);

        // decode same handshake
        let decoded = HandshakeCodec.decode(&mut encoded).unwrap();
        assert_eq!(decoded, Some(handshake));
    }

    /// Tests that the decoding of various invalid handshake messages results in
    /// an error.
    #[test]
    fn test_invalid_handshake_decoding() {
        // try to decode a handshake with an invalid protocol string
        let mut invalid_encoded = {
            let prot = "not the BitTorrent protocol";
            // these buffer values don't matter here as we're only expecting
            // invalid encodings
            let reserved = [0; 8];
            let info_hash = [0; 20];
            let peer_id = [0; 20];

            let buf_len = prot.len() + 49;
            let mut buf = BytesMut::with_capacity(buf_len);
            // the message length prefix is not actually included in the value
            let prot_len = prot.len() as u8;
            buf.put_u8(prot_len);
            buf.extend_from_slice(prot.as_bytes());
            buf.extend_from_slice(&reserved);
            buf.extend_from_slice(&info_hash);
            buf.extend_from_slice(&peer_id);
            buf
        };
        let result = HandshakeCodec.decode(&mut invalid_encoded);
        assert!(result.is_err());
    }

    // Returns a `Handshake` and its expected encoded variant.
    fn make_handshake() -> (Handshake, Bytes) {
        // protocol string
        let mut prot = [0; 19];
        prot.copy_from_slice(PROTOCOL_STRING.as_bytes());

        // the reserved field is all zeros for now as we don't use extensions
        // yet so we're not testing it
        let reserved = [0; 8];

        // this is not a valid info hash but it doesn't matter for the purposes
        // of this test
        const INFO_HASH: &str = "da39a3ee5e6b4b0d3255";
        let mut info_hash = [0; 20];
        info_hash.copy_from_slice(INFO_HASH.as_bytes());

        const PEER_ID: &str = "cbt-2020-03-03-00000";
        let mut peer_id = [0; 20];
        peer_id.copy_from_slice(PEER_ID.as_bytes());

        let handshake = Handshake {
            prot,
            reserved,
            info_hash,
            peer_id,
        };

        // TODO: consider using hard coded bye array for expected value rather
        // than building up result (as that's what the encoder does too and we
        // need to test that it does it correctly)
        let encoded = {
            let buf_len = 68;
            let mut buf = Vec::with_capacity(buf_len);
            // the message length prefix is not actually included in the value
            let prot_len = prot.len() as u8;
            buf.push(prot_len);
            buf.extend_from_slice(&prot);
            buf.extend_from_slice(&reserved);
            buf.extend_from_slice(&info_hash);
            buf.extend_from_slice(&peer_id);
            buf
        };

        (handshake, encoded.into())
    }

    /// Tests the encoding and subsequent decoding of a valid 'choke' message.
    #[test]
    fn test_keep_alive_codec() {
        let (msg, expected_encoded) = make_keep_alive();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'choke' message.
    #[test]
    fn test_choke_codec() {
        let (msg, expected_encoded) = make_choke();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'unchoke' message.
    #[test]
    fn test_unchoke_codec() {
        let (msg, expected_encoded) = make_unchoke();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'interested'
    /// message.
    #[test]
    fn test_interested_codec() {
        let (msg, expected_encoded) = make_interested();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'not interested'
    /// message.
    #[test]
    fn test_not_interested_codec() {
        let (msg, expected_encoded) = make_not_interested();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'bitfield' message.
    #[test]
    fn test_bitfield_codec() {
        let (msg, expected_encoded) = make_bitfield();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'have' message.
    #[test]
    fn test_have_codec() {
        let (msg, expected_encoded) = make_have();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'request' message.
    #[test]
    fn test_request_codec() {
        let (msg, expected_encoded) = make_request();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'block' message.
    #[test]
    fn test_block_codec() {
        let (msg, expected_encoded) = make_block();
        assert_message_codec(msg, expected_encoded);
    }

    /// Tests the encoding and subsequent decoding of a valid 'cancel' message.
    #[test]
    fn test_cancel_codec() {
        let (msg, expected_encoded) = make_cancel();
        assert_message_codec(msg, expected_encoded);
    }

    /// Helper function that asserts that a message is encoded and subsequently
    /// decoded correctly.
    fn assert_message_codec(msg: Message, expected_encoded: Bytes) {
        // encode message
        let mut encoded = BytesMut::with_capacity(expected_encoded.len());
        PeerCodec.encode(msg.clone(), &mut encoded).unwrap();
        assert_eq!(encoded, expected_encoded);

        // don't decode message if there aren't enough bytes in source buffer
        let mut partial_encoded = encoded[0..encoded.len() - 1].into();
        let decoded = PeerCodec.decode(&mut partial_encoded).unwrap();
        assert_eq!(decoded, None);

        // decode same message
        let decoded = PeerCodec.decode(&mut encoded).unwrap();
        assert_eq!(decoded, Some(msg));
    }

    fn make_keep_alive() -> (Message, Bytes) {
        (Message::KeepAlive, Bytes::from_static(&[0; 4]))
    }

    // Returns `Choke` and its expected encoded variant.
    fn make_choke() -> (Message, Bytes) {
        (
            Message::Choke,
            make_empty_msg_encoded_payload(MessageId::Choke),
        )
    }

    /// Returns `Unchoke` and its expected encoded variant.
    fn make_unchoke() -> (Message, Bytes) {
        (
            Message::Unchoke,
            make_empty_msg_encoded_payload(MessageId::Unchoke),
        )
    }

    /// Returns `Interested` and its expected encoded variant.
    fn make_interested() -> (Message, Bytes) {
        (
            Message::Interested,
            make_empty_msg_encoded_payload(MessageId::Interested),
        )
    }

    /// Returns `NotInterested` and its expected encoded variant.
    fn make_not_interested() -> (Message, Bytes) {
        (
            Message::NotInterested,
            make_empty_msg_encoded_payload(MessageId::NotInterested),
        )
    }

    /// Helper used to create 'choke', 'unchoke', 'interested', and 'not
    /// interested' encoded messages that all have the same format.
    fn make_empty_msg_encoded_payload(id: MessageId) -> Bytes {
        // 1 byte message id
        let msg_len = 1;
        // 4 byte message length prefix and message length
        let buf_len = 4 + msg_len as usize;
        let mut buf = BytesMut::with_capacity(buf_len);
        buf.put_u32(msg_len);
        buf.put_u8(id as u8);
        buf.into()
    }

    /// Returns `Bitfield` and its expected encoded variant.
    fn make_bitfield() -> (Message, Bytes) {
        let bitfield =
            Bitfield::from_vec(vec![0b11001001, 0b10000011, 0b11111011]);
        let encoded = {
            // 1 byte message id and n byte f bitfield
            //
            // NOTE: take the length of the underlying storage to get the number
            // of _bytes_, as `bitfield.len()` returns the number of _bits_
            let msg_len = 1 + bitfield.as_slice().len();
            // 4 byte message length prefix and message length
            let buf_len = 4 + msg_len;
            let mut buf = BytesMut::with_capacity(buf_len);
            buf.put_u32(msg_len as u32);
            buf.put_u8(MessageId::Bitfield as u8);
            buf.extend_from_slice(bitfield.as_slice());
            buf
        };
        let msg = Message::Bitfield(bitfield);
        (msg, encoded.into())
    }

    /// Returns `Have` and its expected encoded variant.
    fn make_have() -> (Message, Bytes) {
        let piece_index = 42;
        let msg = Message::Have { piece_index };
        let encoded = {
            // 1 byte message id and 4 byte piece index
            let msg_len = 1 + 4;
            // 4 byte message length prefix and message length
            let buf_len = 4 + msg_len;
            let mut buf = BytesMut::with_capacity(buf_len);
            buf.put_u32(msg_len as u32);
            buf.put_u8(MessageId::Have as u8);
            // ok to unwrap, only used in tests
            buf.put_u32(piece_index.try_into().unwrap());
            buf
        };
        (msg, encoded.into())
    }

    /// Returns `Request` and its expected encoded variant.
    fn make_request() -> (Message, Bytes) {
        let piece_index = 42;
        let offset = 0x4000;
        let len = BLOCK_LEN;
        let msg = Message::Request(BlockInfo {
            piece_index,
            offset,
            len,
        });
        let encoded = make_block_info_encoded_msg_payload(
            MessageId::Request,
            piece_index,
            offset,
            len,
        );
        (msg, encoded)
    }

    /// Returns `Block` and its expected encoded variant.
    fn make_block() -> (Message, Bytes) {
        let piece_index = 42;
        let offset = 0x4000;
        let data = vec![0; 0x4000];
        // TODO: fill the block with random values
        let encoded = {
            // 1 byte message id, 4 byte piece index, 4 byte offset, and n byte
            // block
            let msg_len = 1 + 4 + 4 + data.len();
            // 4 byte message length prefix and message length
            let buf_len = 4 + msg_len;
            let mut buf = BytesMut::with_capacity(buf_len);
            buf.put_u32(msg_len as u32);
            buf.put_u8(MessageId::Block as u8);
            // ok to unwrap, only used in tests
            buf.put_u32(piece_index.try_into().unwrap());
            buf.put_u32(offset);
            buf.extend_from_slice(&data);
            buf
        };
        let msg = Message::Block {
            piece_index,
            offset,
            data: data.into(),
        };
        (msg, encoded.into())
    }

    /// Returns `Cancel` and its expected encoded variant.
    fn make_cancel() -> (Message, Bytes) {
        let piece_index = 42;
        let offset = 0x4000;
        let len = BLOCK_LEN;
        let msg = Message::Cancel(BlockInfo {
            piece_index,
            offset,
            len,
        });
        let encoded = make_block_info_encoded_msg_payload(
            MessageId::Cancel,
            piece_index,
            offset,
            len,
        );
        (msg, encoded)
    }

    /// Helper used to create 'request' and 'cancel' encoded messages that have
    /// the same format.
    fn make_block_info_encoded_msg_payload(
        id: MessageId,
        piece_index: usize,
        offset: u32,
        len: u32,
    ) -> Bytes {
        // 1 byte message id, 4 byte piece index, 4 byte offset, 4 byte
        // length
        let msg_len = 1 + 4 + 4 + 4;
        // 4 byte message length prefix and message length
        let buf_len = 4 + msg_len as usize;
        let mut buf = BytesMut::with_capacity(buf_len);
        buf.put_u32(msg_len);
        buf.put_u8(id as u8);
        // ok to unwrap, only used in tests
        buf.put_u32(piece_index.try_into().unwrap());
        buf.put_u32(offset);
        buf.put_u32(len);
        buf.into()
    }
}
