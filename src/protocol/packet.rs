// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use bytes::{Buf, BufMut, BytesMut};
use std::net::SocketAddr;

use crate::error::{ProtocolError, TftpErrorCode};

/// TFTP opcodes defined by RFC 1350 and RFC 2347.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    /// Read request.
    Rrq = 1,
    /// Write request.
    Wrq = 2,
    /// Data payload.
    Data = 3,
    /// Data acknowledgement.
    Ack = 4,
    /// Error response.
    Error = 5,
    /// RFC 2347 option acknowledgement.
    Oack = 6,
}

impl TryFrom<u16> for Opcode {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Rrq),
            2 => Ok(Self::Wrq),
            3 => Ok(Self::Data),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Error),
            6 => Ok(Self::Oack),
            _ => Err(ProtocolError::InvalidOpcode(value)),
        }
    }
}

/// TFTP transfer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// Binary transfer with bytes preserved exactly.
    Octet,
    /// RFC 1350 text transfer mode; parsed but not served by the core.
    Netascii,
}

impl TransferMode {
    /// Parse a mode without allocating a normalized string.
    pub fn parse(s: &str) -> Result<Self, ProtocolError> {
        if s.eq_ignore_ascii_case("octet") {
            Ok(Self::Octet)
        } else if s.eq_ignore_ascii_case("netascii") {
            Ok(Self::Netascii)
        } else {
            Err(ProtocolError::UnsupportedMode(s.to_string()))
        }
    }

    /// Returns the lowercase RFC wire name for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Octet => "octet",
            Self::Netascii => "netascii",
        }
    }
}

/// Parsed TFTP packet
#[derive(Debug, Clone)]
pub enum TftpPacket {
    /// Read request and its requested options.
    Rrq(RequestPacket),
    /// Write request and its requested options.
    Wrq(RequestPacket),
    /// File payload block.
    Data(DataPacket),
    /// Acknowledgement of a data block.
    Ack(AckPacket),
    /// Protocol error code and safe peer-facing message.
    Error(ErrorPacket),
    /// Negotiated RFC option values.
    Oack(OackPacket),
}

/// Parsed RRQ or WRQ fields.
#[derive(Debug, Clone)]
pub struct RequestPacket {
    /// Client-supplied relative artifact name, validated during parsing.
    pub filename: String,
    /// Requested RFC transfer mode.
    pub mode: TransferMode,
    /// Case-preserving option name/value pairs, bounded to 20 pairs.
    pub options: Vec<(String, String)>,
}

/// Parsed DATA packet.
#[derive(Debug, Clone)]
pub struct DataPacket {
    /// Wrapping 16-bit RFC block number.
    pub block: u16,
    /// Payload bytes following the four-byte TFTP header.
    pub data: Vec<u8>,
}

/// Parsed ACK packet.
#[derive(Debug, Clone)]
pub struct AckPacket {
    /// Wrapping 16-bit block number being acknowledged.
    pub block: u16,
}

/// Parsed ERROR packet.
#[derive(Debug, Clone)]
pub struct ErrorPacket {
    /// RFC error code encoded on the wire.
    pub code: u16,
    /// Null-terminated, UTF-8 peer-facing error description.
    pub message: String,
}

/// Parsed option acknowledgement.
#[derive(Debug, Clone)]
pub struct OackPacket {
    /// Negotiated option name/value pairs in wire order.
    pub options: Vec<(String, String)>,
}

impl TftpPacket {
    const MAX_OPTION_PAIRS: usize = 20;
    const MAX_STRING_FIELDS: usize = 2 + (Self::MAX_OPTION_PAIRS * 2);

    /// Parse one bounded TFTP packet from wire bytes.
    #[inline]
    pub fn parse(data: &[u8], addr: SocketAddr) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "packet too short".into(),
            });
        }

        // Reject before parsing or allocating from attacker-controlled fields.
        const MAX_PACKET_SIZE: usize = 65536;
        if data.len() > MAX_PACKET_SIZE {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "packet exceeds maximum allowed size".into(),
            });
        }

        let mut buf = data;
        let opcode = buf.get_u16();
        let opcode = Opcode::try_from(opcode)?;

        match opcode {
            Opcode::Rrq => Ok(TftpPacket::Rrq(Self::parse_request(buf, addr)?)),
            Opcode::Wrq => Ok(TftpPacket::Wrq(Self::parse_request(buf, addr)?)),
            Opcode::Data => Self::parse_data(buf, addr),
            Opcode::Ack => Self::parse_ack(buf, addr),
            Opcode::Error => Self::parse_error(buf, addr),
            Opcode::Oack => Self::parse_oack(buf, addr),
        }
    }

    /// Parses a bounded RRQ or WRQ body into its filename, mode, and options.
    fn parse_request(data: &[u8], addr: SocketAddr) -> Result<RequestPacket, ProtocolError> {
        let mut offset = 0;
        let filename =
            Self::next_null_terminated_str(data, &mut offset, addr)?.ok_or_else(|| {
                ProtocolError::MalformedPacket {
                    addr,
                    reason: "RRQ/WRQ missing filename or mode".into(),
                }
            })?;
        let mode = Self::next_null_terminated_str(data, &mut offset, addr)?.ok_or_else(|| {
            ProtocolError::MalformedPacket {
                addr,
                reason: "RRQ/WRQ missing filename or mode".into(),
            }
        })?;

        // Validate filename length and characters
        if filename.is_empty() || filename.len() > 255 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "filename length out of range (1-255)".into(),
            });
        }
        // Match audit validation before admitting any transfer work.
        if filename.chars().any(char::is_control) {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "filename contains control characters".into(),
            });
        }

        let mode = TransferMode::parse(mode)?;
        let mut options = Vec::with_capacity(4);
        while offset < data.len() {
            if options.len() >= Self::MAX_OPTION_PAIRS {
                return Err(ProtocolError::MalformedPacket {
                    addr,
                    reason: "RRQ/WRQ contains too many options".into(),
                });
            }
            let key = Self::next_null_terminated_str(data, &mut offset, addr)?
                .expect("offset below packet length must yield a field");
            let value =
                Self::next_null_terminated_str(data, &mut offset, addr)?.ok_or_else(|| {
                    ProtocolError::MalformedPacket {
                        addr,
                        reason: "RRQ/WRQ contains dangling option key".into(),
                    }
                })?;
            options.push((key.to_ascii_lowercase(), value.to_owned()));
        }

        Ok(RequestPacket {
            filename: filename.to_owned(),
            mode,
            options,
        })
    }

    /// Returns the next bounded wire string without allocating an intermediate.
    fn next_null_terminated_str<'a>(
        data: &'a [u8],
        offset: &mut usize,
        addr: SocketAddr,
    ) -> Result<Option<&'a str>, ProtocolError> {
        if *offset == data.len() {
            return Ok(None);
        }
        let remaining = &data[*offset..];
        let length = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| ProtocolError::MalformedPacket {
                addr,
                reason: "unterminated string field in packet".into(),
            })?;
        if length > 512 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "option value too long".into(),
            });
        }
        let field = std::str::from_utf8(&remaining[..length]).map_err(|_| {
            ProtocolError::MalformedPacket {
                addr,
                reason: "invalid UTF-8 in packet".into(),
            }
        })?;
        *offset += length + 1;
        Ok(Some(field))
    }

    /// Parses a DATA body and enforces the maximum payload size.
    fn parse_data(data: &[u8], addr: SocketAddr) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "DATA packet too short".into(),
            });
        }
        // Limit DATA payload size to max block size (65464) + margin
        const MAX_DATA_PAYLOAD: usize = 65464 + 16;
        if data.len() - 2 > MAX_DATA_PAYLOAD {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "DATA payload exceeds maximum allowed size".into(),
            });
        }
        let mut buf = data;
        let block = buf.get_u16();
        Ok(TftpPacket::Data(DataPacket {
            block,
            data: buf.to_vec(),
        }))
    }

    /// Parses an ACK body containing exactly one block number.
    fn parse_ack(data: &[u8], addr: SocketAddr) -> Result<Self, ProtocolError> {
        if data.len() != 2 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "ACK packet must be exactly 4 bytes".into(),
            });
        }
        let mut buf = data;
        let block = buf.get_u16();
        Ok(TftpPacket::Ack(AckPacket { block }))
    }

    /// Parses an ERROR body into its code and optional peer message.
    fn parse_error(data: &[u8], addr: SocketAddr) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "ERROR packet too short".into(),
            });
        }
        let mut buf = data;
        let code = buf.get_u16();
        let message = Self::extract_null_terminated_string(buf).unwrap_or_default();
        Ok(TftpPacket::Error(ErrorPacket { code, message }))
    }

    /// Parses a bounded OACK body into option name/value pairs.
    fn parse_oack(data: &[u8], addr: SocketAddr) -> Result<Self, ProtocolError> {
        let strings = Self::extract_null_terminated_strings(data, addr)?;
        if strings.len() % 2 != 0 {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "OACK contains dangling option key".into(),
            });
        }
        if strings.len() / 2 > Self::MAX_OPTION_PAIRS {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "OACK contains too many options".into(),
            });
        }
        let mut options = Vec::with_capacity(strings.len() / 2);
        let mut i = 0;
        while i + 1 < strings.len() {
            options.push((strings[i].to_ascii_lowercase(), strings[i + 1].clone()));
            i += 2;
        }
        Ok(TftpPacket::Oack(OackPacket { options }))
    }

    /// Extracts and bounds all null-terminated strings in a packet body.
    fn extract_null_terminated_strings(
        data: &[u8],
        addr: SocketAddr,
    ) -> Result<Vec<String>, ProtocolError> {
        let mut strings = Vec::with_capacity(8); // Most packets have 2-8 strings
        let mut start = 0;
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0 {
                // Reject individual strings longer than 512 bytes
                if i - start > 512 {
                    return Err(ProtocolError::MalformedPacket {
                        addr,
                        reason: "option value too long".into(),
                    });
                }
                let s = std::str::from_utf8(&data[start..i]).map_err(|_| {
                    ProtocolError::MalformedPacket {
                        addr,
                        reason: "invalid UTF-8 in packet".into(),
                    }
                })?;
                if strings.len() >= Self::MAX_STRING_FIELDS {
                    return Err(ProtocolError::MalformedPacket {
                        addr,
                        reason: "too many string fields in packet".into(),
                    });
                }
                strings.push(s.to_string());
                start = i + 1;
            }
        }

        if start != data.len() {
            return Err(ProtocolError::MalformedPacket {
                addr,
                reason: "unterminated string field in packet".into(),
            });
        }

        Ok(strings)
    }

    /// Extracts and sanitizes one bounded null-terminated string.
    fn extract_null_terminated_string(data: &[u8]) -> Option<String> {
        // Limit to 512 bytes to prevent allocation-based DoS.
        const MAX_LEN: usize = 512;
        let data = if data.len() > MAX_LEN {
            &data[..MAX_LEN]
        } else {
            data
        };
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        // ERROR text is safe to log only after control characters are removed.
        std::str::from_utf8(&data[..end]).ok().map(|s| {
            s.chars()
                .map(|c| if c.is_control() { '_' } else { c })
                .collect()
        })
    }

    /// Serialize an RRQ packet
    #[inline]
    pub fn rrq(filename: &str, mode: &str) -> BytesMut {
        let mut buf = BytesMut::with_capacity(2 + filename.len() + 1 + mode.len() + 1);
        buf.put_u16(Opcode::Rrq as u16);
        buf.put_slice(filename.as_bytes());
        buf.put_u8(0);
        buf.put_slice(mode.as_bytes());
        buf.put_u8(0);
        buf
    }

    /// Serialize an RRQ packet with explicitly negotiated options.
    pub fn rrq_with_options(filename: &str, mode: &str, options: &[(String, String)]) -> BytesMut {
        let estimated_size = 2
            + filename.len()
            + mode.len()
            + 2
            + options
                .iter()
                .map(|(key, value)| key.len() + value.len() + 2)
                .sum::<usize>();
        let mut buf = BytesMut::with_capacity(estimated_size);
        buf.put_u16(Opcode::Rrq as u16);
        buf.put_slice(filename.as_bytes());
        buf.put_u8(0);
        buf.put_slice(mode.as_bytes());
        buf.put_u8(0);
        for (key, value) in options {
            buf.put_slice(key.as_bytes());
            buf.put_u8(0);
            buf.put_slice(value.as_bytes());
            buf.put_u8(0);
        }
        buf
    }

    /// Serialize a DATA packet
    #[inline]
    pub fn data(block: u16, payload: &[u8]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(4 + payload.len());
        Self::data_into(&mut buf, block, payload);
        buf
    }

    /// Serialize a DATA packet into reusable transfer-owned storage.
    #[inline]
    pub(crate) fn data_into(buf: &mut BytesMut, block: u16, payload: &[u8]) {
        buf.clear();
        buf.reserve(4 + payload.len());
        buf.put_u16(Opcode::Data as u16);
        buf.put_u16(block);
        buf.put_slice(payload);
    }

    /// Serialize an ACK packet
    #[inline]
    pub fn ack(block: u16) -> BytesMut {
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u16(Opcode::Ack as u16);
        buf.put_u16(block);
        buf
    }

    /// Serialize an OACK packet
    #[inline]
    pub fn oack(options: &[(String, String)]) -> BytesMut {
        // Pre-allocate with estimated size
        let estimated_size = 2 + options
            .iter()
            .map(|(k, v)| k.len() + v.len() + 2)
            .sum::<usize>();
        let mut buf = BytesMut::with_capacity(estimated_size);
        buf.put_u16(Opcode::Oack as u16);
        for (key, value) in options {
            buf.put_slice(key.as_bytes());
            buf.put_u8(0);
            buf.put_slice(value.as_bytes());
            buf.put_u8(0);
        }
        buf
    }

    /// Serialize an ERROR packet
    #[inline]
    pub fn error(code: TftpErrorCode, message: &str) -> BytesMut {
        let mut buf = BytesMut::with_capacity(5 + message.len());
        buf.put_u16(Opcode::Error as u16);
        buf.put_u16(code.into());
        buf.put_slice(message.as_bytes());
        buf.put_u8(0);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234))
    }

    #[test]
    fn test_request_rejects_empty_filename() {
        // RRQ with empty filename: opcode(2) + \0 + "octet" + \0
        let mut pkt = vec![0u8, 1]; // RRQ opcode
        pkt.push(0); // empty filename
        pkt.extend_from_slice(b"octet\0");
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_request_rejects_long_filename() {
        let mut pkt = vec![0u8, 1]; // RRQ opcode
        pkt.extend_from_slice(&[b'A'; 300]); // 300-char filename
        pkt.push(0);
        pkt.extend_from_slice(b"octet\0");
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_request_rejects_control_chars_in_filename() {
        for opcode in [1, 2] {
            for control in ['\t', '\n', '\r', '\x01', '\x7f', '\u{85}', '\u{9f}'] {
                let mut pkt = vec![0u8, opcode];
                pkt.extend_from_slice(format!("test{control}file\0octet\0").as_bytes());
                assert!(TftpPacket::parse(&pkt, test_addr()).is_err(), "{control:?}");
            }
        }
    }

    #[test]
    fn test_request_accepts_valid_filename() {
        let mut pkt = vec![0u8, 1]; // RRQ opcode
        pkt.extend_from_slice(b"vmlinuz-5.15.0\0octet\0");
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(matches!(result, Ok(TftpPacket::Rrq(_))));
        if let Ok(TftpPacket::Rrq(req)) = result {
            assert_eq!(req.filename, "vmlinuz-5.15.0");
        }
    }

    #[test]
    fn test_request_rejects_excess_option_count() {
        let mut pkt = vec![0u8, 1]; // RRQ opcode
        pkt.extend_from_slice(b"file\0octet\0");
        for i in 0..21 {
            pkt.extend_from_slice(format!("opt{i}\0val{i}\0").as_bytes());
        }
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_request_rejects_oversized_option_string() {
        let mut data = vec![b'A'; 600]; // 600-byte string
        data.push(0);
        let result = TftpPacket::extract_null_terminated_strings(&data, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_request_rejects_unterminated_string() {
        let mut pkt = vec![0u8, 1]; // RRQ opcode
        pkt.extend_from_slice(b"file\0octet");
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_request_rejects_dangling_option() {
        let mut pkt = vec![0u8, 1]; // RRQ opcode
        pkt.extend_from_slice(b"file\0octet\0blksize\0");
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_data_packet_roundtrip() {
        let payload = b"hello world";
        let pkt = TftpPacket::data(42, payload);
        let parsed = TftpPacket::parse(&pkt, test_addr()).unwrap();
        if let TftpPacket::Data(data) = parsed {
            assert_eq!(data.block, 42);
            assert_eq!(data.data, payload);
        } else {
            panic!("Expected Data packet");
        }
    }

    #[test]
    fn test_ack_packet_roundtrip() {
        let pkt = TftpPacket::ack(100);
        let parsed = TftpPacket::parse(&pkt, test_addr()).unwrap();
        if let TftpPacket::Ack(ack) = parsed {
            assert_eq!(ack.block, 100);
        } else {
            panic!("Expected Ack packet");
        }
    }

    #[test]
    fn test_ack_rejects_trailing_data() {
        let mut pkt = TftpPacket::ack(100).to_vec();
        pkt.push(0);
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_error_packet_roundtrip() {
        let pkt = TftpPacket::error(TftpErrorCode::FileNotFound, "not found");
        let parsed = TftpPacket::parse(&pkt, test_addr()).unwrap();
        if let TftpPacket::Error(err) = parsed {
            assert_eq!(err.code, 1);
            assert_eq!(err.message, "not found");
        } else {
            panic!("Expected Error packet");
        }
    }

    #[test]
    fn test_invalid_opcode() {
        let pkt = vec![0u8, 99]; // Invalid opcode 99
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short_packet() {
        let pkt = vec![0u8]; // Only 1 byte
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_data_rejects_oversized_payload() {
        let mut pkt = vec![0u8, 3]; // DATA opcode
        pkt.extend_from_slice(&1u16.to_be_bytes()); // block 1
        pkt.extend(vec![0xAA; 70000]); // >65464+16 byte payload
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_data_accepts_maximum_payload() {
        let mut pkt = vec![0u8, 3]; // DATA opcode
        pkt.extend_from_slice(&1u16.to_be_bytes()); // block 1
        pkt.extend(vec![0xBB; 65464]); // exactly max block size
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_ok());
        if let Ok(TftpPacket::Data(data)) = result {
            assert_eq!(data.block, 1);
            assert_eq!(data.data.len(), 65464);
        }
    }

    #[test]
    fn test_oack_rejects_excess_option_count() {
        let mut pkt = vec![0u8, 6]; // OACK opcode
        for i in 0..21 {
            pkt.extend_from_slice(format!("opt{i}\0val{i}\0").as_bytes());
        }
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_oack_rejects_dangling_option() {
        let mut pkt = vec![0u8, 6]; // OACK opcode
        pkt.extend_from_slice(b"blksize\0");
        let result = TftpPacket::parse(&pkt, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_mode_parse_case_insensitive() {
        assert_eq!(TransferMode::parse("OCTET").unwrap(), TransferMode::Octet);
        assert_eq!(TransferMode::parse("Octet").unwrap(), TransferMode::Octet);
        assert_eq!(TransferMode::parse("octet").unwrap(), TransferMode::Octet);
        assert_eq!(
            TransferMode::parse("NETASCII").unwrap(),
            TransferMode::Netascii
        );
        assert_eq!(
            TransferMode::parse("NetAscii").unwrap(),
            TransferMode::Netascii
        );
        assert!(TransferMode::parse("binary").is_err());
    }

    #[test]
    fn test_extract_strings_pre_allocated() {
        let data = b"hello\0world\0test\0";
        let result = TftpPacket::extract_null_terminated_strings(data, test_addr()).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "hello");
        assert_eq!(result[1], "world");
        assert_eq!(result[2], "test");
    }

    #[test]
    fn test_oack_serialization_roundtrip() {
        let options = vec![
            ("blksize".to_string(), "1468".to_string()),
            ("windowsize".to_string(), "4".to_string()),
        ];
        let pkt = TftpPacket::oack(&options);
        let parsed = TftpPacket::parse(&pkt, test_addr()).unwrap();
        if let TftpPacket::Oack(oack) = parsed {
            assert_eq!(oack.options.len(), 2);
            assert_eq!(oack.options[0], ("blksize".to_string(), "1468".to_string()));
        } else {
            panic!("Expected OACK packet");
        }
    }

    #[test]
    fn test_error_packet_preallocated() {
        let msg = "A".repeat(200);
        let pkt = TftpPacket::error(TftpErrorCode::NotDefined, &msg);
        let parsed = TftpPacket::parse(&pkt, test_addr()).unwrap();
        if let TftpPacket::Error(err) = parsed {
            assert_eq!(err.message, msg);
        } else {
            panic!("Expected Error packet");
        }
    }

    #[test]
    fn test_extract_null_terminated_string_limits_length() {
        let long_string = vec![b'A'; 1000];
        let result = TftpPacket::extract_null_terminated_string(&long_string);
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(
            s.len() <= 512,
            "extracted string exceeded 512 bytes: {}",
            s.len()
        );
    }

    #[test]
    fn test_extract_null_terminated_string_normal() {
        let data = b"hello\x00world";
        let result = TftpPacket::extract_null_terminated_string(data);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_extract_null_terminated_string_empty() {
        let data = b"\x00";
        let result = TftpPacket::extract_null_terminated_string(data);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_rejects_oversized_packet() {
        let data = vec![0u8; 70_000]; // > 65536
        let result = TftpPacket::parse(&data, test_addr());
        assert!(result.is_err());
    }

    #[test]
    fn test_error_message_control_chars_sanitized() {
        let data = b"test\x01\x02\nmessage\x00";
        let result = TftpPacket::extract_null_terminated_string(data);
        if let Some(s) = result {
            assert!(!s.contains('\x01'));
            assert!(!s.contains('\n'));
            assert!(s.contains("test"));
        }
    }

    #[test]
    fn test_oack_serialization_with_many_options() {
        let options = vec![
            ("blksize".into(), "8192".into()),
            ("windowsize".into(), "16".into()),
            ("timeout".into(), "10".into()),
            ("x-example-a".into(), "one".into()),
            ("x-example-b".into(), "two".into()),
        ];
        let pkt = TftpPacket::oack(&options);
        let parsed = TftpPacket::parse(&pkt, test_addr()).unwrap();
        if let TftpPacket::Oack(oack) = parsed {
            assert_eq!(oack.options.len(), 5);
        }
    }

    #[test]
    fn test_rrq_serializer_roundtrip() {
        let buf = TftpPacket::rrq("vmlinuz", "octet");
        let parsed = TftpPacket::parse(&buf, test_addr()).unwrap();
        match parsed {
            TftpPacket::Rrq(req) => {
                assert_eq!(req.filename, "vmlinuz");
                assert_eq!(req.mode, TransferMode::Octet);
                assert!(req.options.is_empty());
            }
            _ => panic!("Expected Rrq variant"),
        }
    }

    #[test]
    fn test_rrq_with_options_serializer_roundtrip() {
        let packet = TftpPacket::rrq_with_options(
            "kernel",
            "octet",
            &[("x-tempest-protocol-version".into(), "1".into())],
        );
        let TftpPacket::Rrq(request) = TftpPacket::parse(&packet, test_addr()).unwrap() else {
            panic!("expected RRQ");
        };
        assert_eq!(request.filename, "kernel");
        assert_eq!(
            request.options,
            vec![("x-tempest-protocol-version".into(), "1".into())]
        );
    }

    #[test]
    fn test_rrq_serializer_netascii() {
        let buf = TftpPacket::rrq("readme.txt", "netascii");
        let parsed = TftpPacket::parse(&buf, test_addr()).unwrap();
        match parsed {
            TftpPacket::Rrq(req) => {
                assert_eq!(req.filename, "readme.txt");
                assert_eq!(req.mode, TransferMode::Netascii);
            }
            _ => panic!("Expected Rrq variant"),
        }
    }
}
