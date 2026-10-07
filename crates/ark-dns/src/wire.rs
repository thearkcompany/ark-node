//! RFC 1035 wire format parser and serializer for DNS datagrams.
//!
//! Supports parsing queries and building responses for:
//! - Type A (IPv4)
//! - Type AAAA (IPv6)
//! - Type TXT (Text strings)
//! - Header flags (QR, Opcode, AA, TC, RD, RA, RCODE)
//! - RFC 1035 label compression handling for robust name extraction.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::error::{DnsError, Result};

/// DNS Record Types supported according to RFC 1035 & RFC 3596.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    AAAA,
    TXT,
    Unknown(u16),
}

impl From<u16> for DnsRecordType {
    fn from(val: u16) -> Self {
        match val {
            1 => DnsRecordType::A,
            28 => DnsRecordType::AAAA,
            16 => DnsRecordType::TXT,
            other => DnsRecordType::Unknown(other),
        }
    }
}

impl From<DnsRecordType> for u16 {
    fn from(val: DnsRecordType) -> Self {
        match val {
            DnsRecordType::A => 1,
            DnsRecordType::AAAA => 28,
            DnsRecordType::TXT => 16,
            DnsRecordType::Unknown(code) => code,
        }
    }
}

/// DNS Query Class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    IN,
    Unknown(u16),
}

impl From<u16> for DnsClass {
    fn from(val: u16) -> Self {
        match val {
            1 => DnsClass::IN,
            other => DnsClass::Unknown(other),
        }
    }
}

impl From<DnsClass> for u16 {
    fn from(val: DnsClass) -> Self {
        match val {
            DnsClass::IN => 1,
            DnsClass::Unknown(code) => code,
        }
    }
}

/// DNS Opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode {
    Query,
    IQuery,
    Status,
    Unknown(u8),
}

impl From<u8> for DnsOpcode {
    fn from(val: u8) -> Self {
        match val {
            0 => DnsOpcode::Query,
            1 => DnsOpcode::IQuery,
            2 => DnsOpcode::Status,
            other => DnsOpcode::Unknown(other),
        }
    }
}

impl From<DnsOpcode> for u8 {
    fn from(val: DnsOpcode) -> Self {
        match val {
            DnsOpcode::Query => 0,
            DnsOpcode::IQuery => 1,
            DnsOpcode::Status => 2,
            DnsOpcode::Unknown(code) => code,
        }
    }
}

/// DNS Response Code (RCODE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError, // NXDOMAIN
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl From<u8> for DnsRcode {
    fn from(val: u8) -> Self {
        match val {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormatError,
            2 => DnsRcode::ServerFailure,
            3 => DnsRcode::NameError,
            4 => DnsRcode::NotImplemented,
            5 => DnsRcode::Refused,
            other => DnsRcode::Unknown(other),
        }
    }
}

impl From<DnsRcode> for u8 {
    fn from(val: DnsRcode) -> Self {
        match val {
            DnsRcode::NoError => 0,
            DnsRcode::FormatError => 1,
            DnsRcode::ServerFailure => 2,
            DnsRcode::NameError => 3,
            DnsRcode::NotImplemented => 4,
            DnsRcode::Refused => 5,
            DnsRcode::Unknown(code) => code,
        }
    }
}

/// DNS Message Header (12 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: DnsOpcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: DnsRcode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            is_response: false,
            opcode: DnsOpcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            rcode: DnsRcode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn new_response(id: u16, rcode: DnsRcode) -> Self {
        Self {
            id,
            is_response: true,
            opcode: DnsOpcode::Query,
            authoritative: true,
            truncated: false,
            recursion_desired: false,
            recursion_available: true,
            rcode,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(DnsError::Serialization("Packet too short for DNS header".to_string()));
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);

        let is_response = (flags & 0x8000) != 0;
        let opcode = DnsOpcode::from(((flags >> 11) & 0x0F) as u8);
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = DnsRcode::from((flags & 0x000F) as u8);

        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
        let authority_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]);

        Ok(Self {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            rcode,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags: u16 = 0;
        if self.is_response {
            flags |= 0x8000;
        }
        let op_byte: u8 = self.opcode.into();
        flags |= ((op_byte as u16) & 0x0F) << 11;
        if self.authoritative {
            flags |= 0x0400;
        }
        if self.truncated {
            flags |= 0x0200;
        }
        if self.recursion_desired {
            flags |= 0x0100;
        }
        if self.recursion_available {
            flags |= 0x0080;
        }
        let rc_byte: u8 = self.rcode.into();
        flags |= (rc_byte as u16) & 0x000F;

        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.question_count.to_be_bytes());
        buf.extend_from_slice(&self.answer_count.to_be_bytes());
        buf.extend_from_slice(&self.authority_count.to_be_bytes());
        buf.extend_from_slice(&self.additional_count.to_be_bytes());
    }
}

/// DNS Question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: DnsRecordType,
    pub qclass: DnsClass,
}

/// DNS Resource Record Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    TXT(Vec<String>),
    Raw(Vec<u8>),
}

/// DNS Resource Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsRecordType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub rdata: DnsRecordData,
}

/// Complete DNS Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new_response(id: u16, rcode: DnsRcode) -> Self {
        Self {
            header: DnsHeader::new_response(id, rcode),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_wire(buf: &[u8]) -> Result<Self> {
        let header = DnsHeader::parse(buf)?;
        let mut offset = 12;

        let mut questions = Vec::with_capacity(header.question_count as usize);
        for _ in 0..header.question_count {
            let (qname, new_offset) = parse_name(buf, offset)?;
            offset = new_offset;
            if offset + 4 > buf.len() {
                return Err(DnsError::Serialization("Unexpected EOF reading Question".to_string()));
            }
            let qtype = DnsRecordType::from(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
            let qclass = DnsClass::from(u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]));
            offset += 4;
            questions.push(DnsQuestion { qname, qtype, qclass });
        }

        let mut answers = Vec::with_capacity(header.answer_count as usize);
        for _ in 0..header.answer_count {
            let (rec, new_offset) = parse_record(buf, offset)?;
            offset = new_offset;
            answers.push(rec);
        }

        let mut authorities = Vec::with_capacity(header.authority_count as usize);
        for _ in 0..header.authority_count {
            let (rec, new_offset) = parse_record(buf, offset)?;
            offset = new_offset;
            authorities.push(rec);
        }

        let mut additionals = Vec::with_capacity(header.additional_count as usize);
        for _ in 0..header.additional_count {
            let (rec, new_offset) = parse_record(buf, offset)?;
            offset = new_offset;
            additionals.push(rec);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        let mut header = self.header.clone();
        header.question_count = self.questions.len() as u16;
        header.answer_count = self.answers.len() as u16;
        header.authority_count = self.authorities.len() as u16;
        header.additional_count = self.additionals.len() as u16;

        header.serialize(&mut buf);

        // Name compression dictionary: name -> offset
        let mut label_offsets: HashMap<String, usize> = HashMap::new();

        for q in &self.questions {
            serialize_name(&q.qname, &mut buf, &mut label_offsets);
            buf.extend_from_slice(&u16::from(q.qtype).to_be_bytes());
            buf.extend_from_slice(&u16::from(q.qclass).to_be_bytes());
        }

        for ans in &self.answers {
            serialize_record(ans, &mut buf, &mut label_offsets)?;
        }

        for auth in &self.authorities {
            serialize_record(auth, &mut buf, &mut label_offsets)?;
        }

        for add in &self.additionals {
            serialize_record(add, &mut buf, &mut label_offsets)?;
        }

        Ok(buf)
    }
}

/// Helper function to parse a domain name with compression pointer following.
fn parse_name(buf: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;
    let mut jumps_performed = 0;
    const MAX_JUMPS: usize = 16;

    loop {
        if offset >= buf.len() {
            return Err(DnsError::Serialization("Unexpected EOF reading name".to_string()));
        }
        let len = buf[offset];
        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Pointer (11xxxxxx)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buf.len() {
                return Err(DnsError::Serialization("Malformed pointer in name".to_string()));
            }
            let pointer_target = (((len & 0x3F) as usize) << 8) | (buf[offset + 1] as usize);
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            jumps_performed += 1;
            if jumps_performed > MAX_JUMPS {
                return Err(DnsError::Serialization("Compression pointer loop detected".to_string()));
            }
            offset = pointer_target;
            continue;
        }

        // Standard label
        let label_len = len as usize;
        offset += 1;
        if offset + label_len > buf.len() {
            return Err(DnsError::Serialization("Label length exceeds packet bounds".to_string()));
        }
        let label = std::str::from_utf8(&buf[offset..offset + label_len])
            .map_err(|e| DnsError::Serialization(format!("Invalid UTF-8 in label: {}", e)))?;
        labels.push(label.to_string());
        offset += label_len;
    }

    let fqdn = labels.join(".");
    Ok((fqdn, return_offset))
}

fn parse_record(buf: &[u8], offset: usize) -> Result<(DnsRecord, usize)> {
    let (name, mut current_offset) = parse_name(buf, offset)?;
    if current_offset + 10 > buf.len() {
        return Err(DnsError::Serialization("Unexpected EOF reading resource record header".to_string()));
    }

    let rtype = DnsRecordType::from(u16::from_be_bytes([buf[current_offset], buf[current_offset + 1]]));
    let rclass = DnsClass::from(u16::from_be_bytes([buf[current_offset + 2], buf[current_offset + 3]]));
    let ttl = u32::from_be_bytes([
        buf[current_offset + 4],
        buf[current_offset + 5],
        buf[current_offset + 6],
        buf[current_offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([buf[current_offset + 8], buf[current_offset + 9]]) as usize;
    current_offset += 10;

    if current_offset + rdlength > buf.len() {
        return Err(DnsError::Serialization("RDATA length exceeds buffer bounds".to_string()));
    }
    let rdata_bytes = &buf[current_offset..current_offset + rdlength];

    let rdata = match rtype {
        DnsRecordType::A => {
            if rdlength != 4 {
                return Err(DnsError::Serialization("Invalid A record length".to_string()));
            }
            let ip = Ipv4Addr::new(rdata_bytes[0], rdata_bytes[1], rdata_bytes[2], rdata_bytes[3]);
            DnsRecordData::A(ip)
        }
        DnsRecordType::AAAA => {
            if rdlength != 16 {
                return Err(DnsError::Serialization("Invalid AAAA record length".to_string()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata_bytes);
            DnsRecordData::AAAA(Ipv6Addr::from(octets))
        }
        DnsRecordType::TXT => {
            let mut txts = Vec::new();
            let mut txt_offset = 0;
            while txt_offset < rdlength {
                let slen = rdata_bytes[txt_offset] as usize;
                txt_offset += 1;
                if txt_offset + slen > rdlength {
                    return Err(DnsError::Serialization("Malformed TXT record chunk".to_string()));
                }
                let s = std::str::from_utf8(&rdata_bytes[txt_offset..txt_offset + slen])
                    .map_err(|e| DnsError::Serialization(format!("Invalid UTF-8 in TXT record: {}", e)))?;
                txts.push(s.to_string());
                txt_offset += slen;
            }
            DnsRecordData::TXT(txts)
        }
        _ => DnsRecordData::Raw(rdata_bytes.to_vec()),
    };

    current_offset += rdlength;

    Ok((
        DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        current_offset,
    ))
}

fn serialize_name(name: &str, buf: &mut Vec<u8>, _label_offsets: &mut HashMap<String, usize>) {
    // Standard label sequence ending with 0
    let trimmed = name.trim_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0);
}

fn serialize_record(
    record: &DnsRecord,
    buf: &mut Vec<u8>,
    label_offsets: &mut HashMap<String, usize>,
) -> Result<()> {
    serialize_name(&record.name, buf, label_offsets);
    buf.extend_from_slice(&u16::from(record.rtype).to_be_bytes());
    buf.extend_from_slice(&u16::from(record.rclass).to_be_bytes());
    buf.extend_from_slice(&record.ttl.to_be_bytes());

    match &record.rdata {
        DnsRecordData::A(ip) => {
            buf.extend_from_slice(&4u16.to_be_bytes()); // RDLength
            buf.extend_from_slice(&ip.octets());
        }
        DnsRecordData::AAAA(ip) => {
            buf.extend_from_slice(&16u16.to_be_bytes()); // RDLength
            buf.extend_from_slice(&ip.octets());
        }
        DnsRecordData::TXT(strings) => {
            let mut total_len = 0;
            for s in strings {
                total_len += 1 + s.len();
            }
            if total_len > u16::MAX as usize {
                return Err(DnsError::Serialization("TXT rdata exceeds maximum length".to_string()));
            }
            buf.extend_from_slice(&(total_len as u16).to_be_bytes());
            for s in strings {
                buf.push(s.len() as u8);
                buf.extend_from_slice(s.as_bytes());
            }
        }
        DnsRecordData::Raw(bytes) => {
            buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(bytes);
        }
    }

    Ok(())
}
