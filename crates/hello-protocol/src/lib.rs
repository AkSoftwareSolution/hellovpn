pub mod handshake;
use std::fmt;

pub const MAGIC: [u8; 4] = *b"HVPN";
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 26;
pub const MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Hello = 1,
    Handshake = 2,
    Data = 3,
    Keepalive = 4,
    Close = 5,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Handshake),
            3 => Ok(Self::Data),
            4 => Ok(Self::Keepalive),
            5 => Ok(Self::Close),
            _ => Err(ProtocolError::InvalidPacketType),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: PacketType,
    pub flags: u16,
    pub session_id: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidPacketType,
    InvalidLength,
    PayloadTooLarge,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

impl From<ProtocolError> for hello_core::ProtocolError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidMagic => hello_core::ProtocolError::InvalidMagic,
            ProtocolError::UnsupportedVersion => hello_core::ProtocolError::UnsupportedVersion(1),
            ProtocolError::InvalidPacketType => hello_core::ProtocolError::InvalidPacketType(0),
            ProtocolError::InvalidLength => hello_core::ProtocolError::InvalidLength,
            ProtocolError::PayloadTooLarge => hello_core::ProtocolError::PayloadTooLarge {
                size: 0,
                max: 65535,
            },
        }
    }
}

impl From<ProtocolError> for hello_core::HvpnError {
    fn from(err: ProtocolError) -> Self {
        hello_core::HvpnError::Protocol(err.into())
    }
}

impl Packet {
    /// Encode packet into bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload_len =
            u16::try_from(self.payload.len()).map_err(|_| ProtocolError::PayloadTooLarge)?;

        let mut buffer = Vec::with_capacity(HEADER_SIZE + self.payload.len());

        // Magic
        buffer.extend_from_slice(&MAGIC);

        // Version
        buffer.push(VERSION);

        // Packet type
        buffer.push(self.packet_type as u8);

        // Flags
        buffer.extend_from_slice(&self.flags.to_be_bytes());

        // Session ID
        buffer.extend_from_slice(&self.session_id.to_be_bytes());

        // Sequence number
        buffer.extend_from_slice(&self.sequence.to_be_bytes());

        // Payload length
        buffer.extend_from_slice(&payload_len.to_be_bytes());

        // Payload
        buffer.extend_from_slice(&self.payload);

        Ok(buffer)
    }

    /// Decode bytes into packet.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::InvalidLength);
        }

        // Validate magic
        if data[0..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        // Validate version
        if data[4] != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }

        // Packet type
        let packet_type = PacketType::try_from(data[5])?;

        // Flags
        let flags = u16::from_be_bytes([data[6], data[7]]);

        // Session ID
        let session_id = u64::from_be_bytes(data[8..16].try_into().unwrap());

        // Sequence
        let sequence = u64::from_be_bytes(data[16..24].try_into().unwrap());

        // Payload length
        let payload_len = u16::from_be_bytes([data[24], data[25]]) as usize;

        // Validate exact packet length
        if data.len() != HEADER_SIZE + payload_len {
            return Err(ProtocolError::InvalidLength);
        }

        let payload = data[HEADER_SIZE..].to_vec();

        Ok(Packet {
            packet_type,
            flags,
            session_id,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_encode_decode() {
        let packet = Packet {
            packet_type: PacketType::Data,
            flags: 0,
            session_id: 12345,
            sequence: 1,
            payload: b"HelloVPN".to_vec(),
        };

        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(packet, decoded);
    }

    #[test]
    fn reject_invalid_magic() {
        let packet = Packet {
            packet_type: PacketType::Hello,
            flags: 0,
            session_id: 1,
            sequence: 1,
            payload: vec![],
        };

        let mut encoded = packet.encode().unwrap();
        encoded[0] = 0;

        assert_eq!(Packet::decode(&encoded), Err(ProtocolError::InvalidMagic));
    }

    #[test]
    fn reject_invalid_version() {
        let packet = Packet {
            packet_type: PacketType::Hello,
            flags: 0,
            session_id: 1,
            sequence: 1,
            payload: vec![],
        };

        let mut encoded = packet.encode().unwrap();
        encoded[4] = 99;

        assert_eq!(
            Packet::decode(&encoded),
            Err(ProtocolError::UnsupportedVersion)
        );
    }

    #[test]
    fn reject_invalid_packet_type() {
        let packet = Packet {
            packet_type: PacketType::Hello,
            flags: 0,
            session_id: 1,
            sequence: 1,
            payload: vec![],
        };

        let mut encoded = packet.encode().unwrap();
        encoded[5] = 99;

        assert_eq!(
            Packet::decode(&encoded),
            Err(ProtocolError::InvalidPacketType)
        );
    }

    #[test]
    fn reject_incomplete_packet() {
        let result = Packet::decode(&[0, 1, 2]);

        assert_eq!(result, Err(ProtocolError::InvalidLength));
    }

    #[test]
    fn reject_wrong_payload_length() {
        let packet = Packet {
            packet_type: PacketType::Data,
            flags: 0,
            session_id: 1,
            sequence: 1,
            payload: b"Hello".to_vec(),
        };

        let mut encoded = packet.encode().unwrap();
        encoded.pop();

        assert_eq!(Packet::decode(&encoded), Err(ProtocolError::InvalidLength));
    }

    #[test]
    fn check_header_size() {
        let packet = Packet {
            packet_type: PacketType::Hello,
            flags: 0,
            session_id: 1,
            sequence: 1,
            payload: vec![],
        };

        let encoded = packet.encode().unwrap();

        assert_eq!(encoded.len(), HEADER_SIZE);
    }
}
