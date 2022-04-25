use crate::error;
use crate::error::Error;
use crate::utils::prelude::*;
use crate::utils::{
    self, all_bytes_from_stream, var_bytes_from_stream, var_int_from_stream, var_u160_from_stream,
};

#[derive(Debug)]
struct EcnCounts {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
}

impl EcnCounts {
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let ect0_count = var_int_from_stream(datagram)?;
        let ect1_count = var_int_from_stream(datagram)?;
        let ecn_ce_count = var_int_from_stream(datagram)?;
        Ok(Self {
            ect0_count,
            ect1_count,
            ecn_ce_count,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &utils::encode_var_int(self.ect0_count)?[..],
            &utils::encode_var_int(self.ect1_count)?[..],
            &utils::encode_var_int(self.ecn_ce_count)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
struct AckRange {
    gap: u64,
    ack_range_length: u64,
}

impl AckRange {
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let gap = var_int_from_stream(datagram)?;
        let ack_range_length = var_int_from_stream(datagram)?;
        Ok(Self {
            gap,
            ack_range_length,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &utils::encode_var_int(self.gap)?[..],
            &utils::encode_var_int(self.ack_range_length)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameAck {
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    ack_range: Vec<AckRange>,
    ecn_counts: Option<EcnCounts>,
}

impl FrameAck {
    pub fn new() -> Self {
        todo!();
    }
    fn from_datagram<T>(datagram: &mut T, type_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let largest_acknowledged = var_int_from_stream(datagram)?;
        let ack_delay = var_int_from_stream(datagram)?;
        let ack_range_count = var_int_from_stream(datagram)?;
        let first_ack_range = var_int_from_stream(datagram)?;
        // dynamic to avoid malicious allocation
        let mut ack_range = Vec::<AckRange>::new();
        for _ in 0..ack_range_count {
            ack_range.push(AckRange::from_datagram(datagram)?);
        }
        let ecn_counts = if type_byte & 0x1 == 1 {
            Some(EcnCounts::from_datagram(datagram)?)
        } else {
            None
        };
        Ok(Self {
            largest_acknowledged,
            ack_delay,
            ack_range_count,
            first_ack_range,
            ack_range,
            ecn_counts,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        let mut tp_ack_range_bytes = Vec::<Vec<u8>>::new();
        let mut ack_range_iter = self.ack_range.iter();
        while let Some(x) = ack_range_iter.next() {
            tp_ack_range_bytes.push(x.to_bytes()?);
        }
        let ack_range_bytes = tp_ack_range_bytes.into_iter().flatten().collect::<Vec<_>>();
        let (enc_counts_bytes, type_byte) = match self.ecn_counts {
            Some(ref x) => (x.to_bytes()?, 0x03u8),
            None => (vec![], 0x02u8),
        };
        Ok([
            &[type_byte][..],
            &utils::encode_var_int(self.largest_acknowledged)?[..],
            &utils::encode_var_int(self.ack_delay)?[..],
            &utils::encode_var_int(self.ack_range_count)?[..],
            &utils::encode_var_int(self.first_ack_range)?[..],
            &ack_range_bytes[..],
            &enc_counts_bytes[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameResetStream {
    stream_id: u64,
    application_protocol_error_code: u64,
    final_size: u64,
}

impl FrameResetStream {
    pub fn new(stream_id: u64, application_protocol_error_code: u64, final_size: u64) -> Self {
        Self {
            stream_id,
            application_protocol_error_code,
            final_size,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let stream_id = var_int_from_stream(datagram)?;
        let application_protocol_error_code = var_int_from_stream(datagram)?;
        let final_size = var_int_from_stream(datagram)?;
        Ok(Self {
            stream_id,
            application_protocol_error_code,
            final_size,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x04u8][..],
            &utils::encode_var_int(self.stream_id)?[..],
            &utils::encode_var_int(self.application_protocol_error_code)?[..],
            &utils::encode_var_int(self.final_size)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameStopSending {
    stream_id: u64,
    application_protocol_error_code: u64,
}

impl FrameStopSending {
    pub fn new(stream_id: u64, application_protocol_error_code: u64) -> Self {
        Self {
            stream_id,
            application_protocol_error_code,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let stream_id = var_int_from_stream(datagram)?;
        let application_protocol_error_code = var_int_from_stream(datagram)?;
        Ok(Self {
            stream_id,
            application_protocol_error_code,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x05u8],
            &utils::encode_var_int(self.stream_id)?[..],
            &utils::encode_var_int(self.application_protocol_error_code)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameCrypto {
    offset: u64,
    length: u64,
    crypto_data: Vec<u8>,
}

impl FrameCrypto {
    pub fn new(crypto_data: Vec<u8>) -> Self {
        Self {
            offset: 0u64,
            length: crypto_data.len() as u64,
            crypto_data,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let offset = var_int_from_stream(datagram)?;
        let length = var_int_from_stream(datagram)?;
        let total_size = (length + offset) as usize;
        let crypto_data = var_bytes_from_stream(datagram, total_size)?;
        Ok(Self {
            offset,
            length,
            crypto_data,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x06][..],
            &utils::encode_var_int(self.offset)?[..],
            &utils::encode_var_int(self.length)?[..],
            &self.crypto_data[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameNewToken {
    token_length: u64,
    token: Vec<u8>,
}

impl FrameNewToken {
    pub fn new(token: Vec<u8>) -> Self {
        Self {
            token_length: token.len() as u64,
            token,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let token_length = var_int_from_stream(datagram)?;
        let token = var_bytes_from_stream(datagram, token_length as usize)?;
        Ok(Self {
            token_length,
            token,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x07u8][..],
            &utils::encode_var_int(self.token_length)?[..],
            &self.token[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameStream {
    stream_id: u64,
    offset: u64,
    length: u64,
    stream_data: Vec<u8>,
    is_fin: bool,
}

impl FrameStream {
    pub fn new(stream_id: u64, stream_data: Vec<u8>, is_fin: bool) -> Self {
        Self {
            stream_id,
            offset: 0,
            length: stream_data.len() as u64,
            stream_data,
            is_fin,
        }
    }
    fn from_datagram<T>(datagram: &mut T, type_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let has_offset = type_byte & 0x04 == 1;
        let has_length = type_byte & 0x02 == 1;
        let is_fin = type_byte & 0x01 == 1;
        let stream_id = var_int_from_stream(datagram)?;
        let offset = if has_offset {
            var_int_from_stream(datagram)?
        } else {
            0
        };
        let tp_length = if has_length {
            Some(var_int_from_stream(datagram)?)
        } else {
            None
        };
        let stream_data = match tp_length {
            Some(x) => var_bytes_from_stream(datagram, x as usize),
            None => all_bytes_from_stream(datagram),
        }?;
        Ok(Self {
            stream_id,
            offset,
            length: stream_data.len() as u64,
            stream_data,
            is_fin,
        })
    }
    fn to_bytes(&self, include_len: bool) -> error::Result<Vec<u8>> {
        let has_offset = self.offset != 0;
        let type_byte = 0x08u8
            | if has_offset { 0x04u8 } else { 0x00u8 }
            | if include_len { 0x02u8 } else { 0x00u8 }
            | if self.is_fin { 0x01u8 } else { 0x00u8 };
        let offset_bytes = if has_offset {
            utils::encode_var_int(self.offset)?
        } else {
            vec![]
        };
        let len_bytes = if include_len {
            utils::encode_var_int(self.length)?
        } else {
            vec![]
        };
        Ok([
            &[type_byte][..],
            &offset_bytes[..],
            &len_bytes[..],
            &self.stream_data[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameMaxData {
    maximum_data: u64,
}

impl FrameMaxData {
    pub fn new(maximum_data: u64) -> Self {
        Self { maximum_data }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let maximum_data = var_int_from_stream(datagram)?;
        Ok(Self { maximum_data })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x10u8][..],
            &utils::encode_var_int(self.maximum_data)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameMaxStreamData {
    stream_id: u64,
    maximum_stream_data: u64,
}

impl FrameMaxStreamData {
    pub fn new(stream_id: u64, maximum_stream_data: u64) -> Self {
        Self {
            stream_id,
            maximum_stream_data,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let stream_id = var_int_from_stream(datagram)?;
        let maximum_stream_data = var_int_from_stream(datagram)?;
        Ok(Self {
            stream_id,
            maximum_stream_data,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x11u8][..],
            &utils::encode_var_int(self.stream_id)?[..],
            &utils::encode_var_int(self.maximum_stream_data)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameMaxStreams {
    maximum_streams: u64,
    is_unidirectional: bool,
}

impl FrameMaxStreams {
    pub fn new(maximum_streams: u64, is_unidirectional: bool) -> Self {
        Self {
            maximum_streams,
            is_unidirectional,
        }
    }
    fn from_datagram<T>(datagram: &mut T, type_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let maximum_streams = var_int_from_stream(datagram)?;
        let is_unidirectional = type_byte & 0x01 == 1;
        Ok(Self {
            maximum_streams,
            is_unidirectional,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        let type_byte = 0x12u8
            | if self.is_unidirectional {
                0x01u8
            } else {
                0x00u8
            };
        Ok([
            &[type_byte][..],
            &utils::encode_var_int(self.maximum_streams)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameDataBlocked {
    maximum_data: u64,
}

impl FrameDataBlocked {
    pub fn new(maximum_data: u64) -> Self {
        Self { maximum_data }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let maximum_data = var_int_from_stream(datagram)?;
        Ok(Self { maximum_data })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x14u8][..],
            &utils::encode_var_int(self.maximum_data)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameStreamDataBlocked {
    stream_id: u64,
    maximum_stream_data: u64,
}

impl FrameStreamDataBlocked {
    pub fn new(stream_id: u64, maximum_stream_data: u64) -> Self {
        Self {
            stream_id,
            maximum_stream_data,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let stream_id = var_int_from_stream(datagram)?;
        let maximum_stream_data = var_int_from_stream(datagram)?;
        Ok(Self {
            stream_id,
            maximum_stream_data,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x15u8][..],
            &utils::encode_var_int(self.stream_id)?[..],
            &utils::encode_var_int(self.maximum_stream_data)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameStreamsBlocked {
    maximum_streams: u64,
    is_unidirectional_limit: bool,
}

impl FrameStreamsBlocked {
    pub fn new(maximum_streams: u64, is_unidirectional_limit: bool) -> Self {
        Self {
            maximum_streams,
            is_unidirectional_limit,
        }
    }
    fn from_datagram<T>(datagram: &mut T, type_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let maximum_streams = var_int_from_stream(datagram)?;
        let is_unidirectional_limit = type_byte & 0x01 == 1;
        Ok(Self {
            maximum_streams,
            is_unidirectional_limit,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        let type_byte = 0x16u8
            | if self.is_unidirectional_limit {
                0x01u8
            } else {
                0x00u8
            };
        Ok([
            &[type_byte][..],
            &utils::encode_var_int(self.maximum_streams)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameNewConnectionId {
    sequence_number: u64,
    retire_prior_to: u64,
    length: u8,
    connection_id: U160,
    stateless_reset_token: u128,
}

impl FrameNewConnectionId {
    pub fn new(
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: U160,
        stateless_reset_token: u128,
    ) -> Self {
        Self {
            sequence_number,
            retire_prior_to,
            length: 8u8,
            connection_id,
            stateless_reset_token,
        }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let sequence_number = var_int_from_stream(datagram)?;
        let retire_prior_to = var_int_from_stream(datagram)?;
        let length = u8::from_datagram(datagram)?;
        if 1 > length || length > 20 {
            return Err(Error::InternalError("invalid connection id length"));
        }
        let connection_id = var_u160_from_stream(datagram, length)?;
        let stateless_reset_token = u128::from_datagram(datagram)?;
        Ok(Self {
            sequence_number,
            retire_prior_to,
            length,
            connection_id,
            stateless_reset_token,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x18u8][..],
            &utils::encode_var_int(self.sequence_number)?[..],
            &utils::encode_var_int(self.retire_prior_to)?[..],
            &[self.length][..],
            &self.connection_id.to_bytes()[..],
            &self.stateless_reset_token.to_be_bytes()[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FrameRetireConnectionId {
    sequence_number: u64,
}

impl FrameRetireConnectionId {
    pub fn new(sequence_number: u64) -> Self {
        Self { sequence_number }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let sequence_number = var_int_from_stream(datagram)?;
        Ok(Self { sequence_number })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        Ok([
            &[0x19u8][..],
            &utils::encode_var_int(self.sequence_number)?[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub struct FramePathChallenge {
    data: u64,
}

impl FramePathChallenge {
    pub fn new(data: u64) -> Self {
        Self { data }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let data = u64::from_datagram(datagram)?;
        Ok(Self { data })
    }
    fn to_bytes(&self) -> Vec<u8> {
        [&[0x1au8][..], &self.data.to_be_bytes()[..]].concat()
    }
}

#[derive(Debug)]
pub struct FramePathResponse {
    data: u64,
}

impl FramePathResponse {
    pub fn new(data: u64) -> Self {
        Self { data }
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let data = u64::from_datagram(datagram)?;
        Ok(Self { data })
    }
    fn to_bytes(&self) -> Vec<u8> {
        [&[0x1bu8][..], &self.data.to_be_bytes()[..]].concat()
    }
}

#[derive(Debug)]
pub struct FrameConnectionClose {
    error_code: u64,
    frame_type: Option<u64>,
    reason_phrase_length: u64,
    reason_phrase: Vec<u8>,
    is_application_error: bool,
}

impl FrameConnectionClose {
    pub fn new_application_error(error_code: u64, frame_type: u64, reason_phrase: Vec<u8>) -> Self {
        Self {
            error_code,
            frame_type: Some(frame_type),
            reason_phrase_length: reason_phrase.len() as u64,
            reason_phrase,
            is_application_error: true,
        }
    }
    pub fn new_error(error_code: u64, reason_phrase: Vec<u8>) -> Self {
        Self {
            error_code,
            frame_type: None,
            reason_phrase_length: reason_phrase.len() as u64,
            reason_phrase,
            is_application_error: false,
        }
    }
    fn from_datagram<T>(datagram: &mut T, type_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let is_application_error = type_byte & 0x1 == 1;
        let error_code = var_int_from_stream(datagram)?;
        let frame_type = if !is_application_error {
            Some(var_int_from_stream(datagram)?)
        } else {
            None
        };
        let reason_phrase_length = var_int_from_stream(datagram)?;
        let reason_phrase = var_bytes_from_stream(datagram, reason_phrase_length as usize)?;
        Ok(Self {
            error_code,
            frame_type,
            reason_phrase_length,
            reason_phrase,
            is_application_error,
        })
    }
    fn to_bytes(&self) -> error::Result<Vec<u8>> {
        let type_byte = 0x1cu8
            | if self.is_application_error {
                0x01u8
            } else {
                0x00u8
            };
        let frame_type_bytes = match self.frame_type {
            Some(x) => utils::encode_var_int(x)?,
            None => vec![],
        };
        Ok([
            &[type_byte][..],
            &frame_type_bytes[..],
            &utils::encode_var_int(self.reason_phrase_length)?[..],
            &self.reason_phrase[..],
        ]
        .concat())
    }
}

#[derive(Debug)]
pub enum Frame {
    Padding,
    Ping,
    Ack(FrameAck),
    ResetStream(FrameResetStream),
    StopSending(FrameStopSending),
    Crypto(FrameCrypto),
    NewToken(FrameNewToken),
    Stream(FrameStream),
    MaxData(FrameMaxData),
    MaxStreamData(FrameMaxStreamData),
    MaxStreams(FrameMaxStreams),
    DataBlocked(FrameDataBlocked),
    StreamDataBlocked(FrameStreamDataBlocked),
    StreamsBlocked(FrameStreamsBlocked),
    NewConnectionId(FrameNewConnectionId),
    RetireConnectionId(FrameRetireConnectionId),
    PathChallenge(FramePathChallenge),
    PathResponse(FramePathResponse),
    ConnectionClose(FrameConnectionClose),
    HandshakeDone,
}

impl Frame {
    fn to_bytes(&self, is_df_end: bool) -> error::Result<Vec<u8>> {
        Ok(match self {
            Self::Padding => vec![0x00],
            Self::Ping => vec![0x01],
            Self::Ack(ref x) => x.to_bytes()?,
            Self::ResetStream(ref x) => x.to_bytes()?,
            Self::StopSending(ref x) => x.to_bytes()?,
            Self::Crypto(ref x) => x.to_bytes()?,
            Self::NewToken(ref x) => x.to_bytes()?,
            Self::Stream(ref x) => x.to_bytes(!is_df_end)?,
            Self::MaxData(ref x) => x.to_bytes()?,
            Self::MaxStreamData(ref x) => x.to_bytes()?,
            Self::MaxStreams(ref x) => x.to_bytes()?,
            Self::DataBlocked(ref x) => x.to_bytes()?,
            Self::StreamDataBlocked(ref x) => x.to_bytes()?,
            Self::StreamsBlocked(ref x) => x.to_bytes()?,
            Self::NewConnectionId(ref x) => x.to_bytes()?,
            Self::RetireConnectionId(ref x) => x.to_bytes()?,
            Self::PathChallenge(ref x) => x.to_bytes(),
            Self::PathResponse(ref x) => x.to_bytes(),
            Self::ConnectionClose(ref x) => x.to_bytes()?,
            Self::HandshakeDone => vec![0x1e],
        })
    }
}

pub fn deserialize_frame<T>(datagram: &mut T) -> error::Result<Frame>
where
    T: Iterator<Item = error::Result<u8>>,
{
    let type_byte = var_int_from_stream(datagram)?;
    let type_byte = (type_byte & (1 << 8) - 1) as u8;
    match type_byte {
        0x00 => Ok(Frame::Padding),
        0x01 => Ok(Frame::Ping),
        0x02..=0x03 => Ok(Frame::Ack(FrameAck::from_datagram(datagram, type_byte)?)),
        0x04 => Ok(Frame::ResetStream(FrameResetStream::from_datagram(
            datagram,
        )?)),
        0x05 => Ok(Frame::StopSending(FrameStopSending::from_datagram(
            datagram,
        )?)),
        0x06 => Ok(Frame::Crypto(FrameCrypto::from_datagram(datagram)?)),
        0x07 => Ok(Frame::NewToken(FrameNewToken::from_datagram(datagram)?)),
        0x08..=0x0f => Ok(Frame::Stream(FrameStream::from_datagram(
            datagram, type_byte,
        )?)),
        0x10 => Ok(Frame::MaxData(FrameMaxData::from_datagram(datagram)?)),
        0x11 => Ok(Frame::MaxStreamData(FrameMaxStreamData::from_datagram(
            datagram,
        )?)),
        0x12..=0x13 => Ok(Frame::MaxStreams(FrameMaxStreams::from_datagram(
            datagram, type_byte,
        )?)),
        0x14 => Ok(Frame::DataBlocked(FrameDataBlocked::from_datagram(
            datagram,
        )?)),
        0x15 => Ok(Frame::StreamDataBlocked(
            FrameStreamDataBlocked::from_datagram(datagram)?,
        )),
        0x16..=0x17 => Ok(Frame::StreamsBlocked(FrameStreamsBlocked::from_datagram(
            datagram, type_byte,
        )?)),
        0x18 => Ok(Frame::NewConnectionId(FrameNewConnectionId::from_datagram(
            datagram,
        )?)),
        0x19 => Ok(Frame::RetireConnectionId(
            FrameRetireConnectionId::from_datagram(datagram)?,
        )),
        0x1a => Ok(Frame::PathChallenge(FramePathChallenge::from_datagram(
            datagram,
        )?)),
        0x1b => Ok(Frame::PathResponse(FramePathResponse::from_datagram(
            datagram,
        )?)),
        0x1c..=0x1d => Ok(Frame::ConnectionClose(FrameConnectionClose::from_datagram(
            datagram, type_byte,
        )?)),
        0x1e => Ok(Frame::HandshakeDone),
        _ => Err(Error::InternalError("Invalid type byte")),
    }
}

pub fn deserialize_frames<T>(dataframe: &mut T) -> error::Result<Vec<Frame>>
where
    T: Iterator<Item = error::Result<u8>>,
{
    let mut rv = Vec::<Frame>::new();
    let mut peekable_df = dataframe.peekable();
    while peekable_df.peek().is_some() {
        let frame = deserialize_frame(&mut peekable_df)?;
        rv.push(frame);
    }
    Ok(rv)
}

pub fn serialize_frames(frames: &[Frame], is_df_end: bool) -> error::Result<Vec<u8>> {
    let frames_len = frames.len();
    let mut results = frames
        .iter()
        .enumerate()
        .map(|(idx, frame)| frame.to_bytes(is_df_end && idx == frames_len - 1));
    let mut bytes_vec = Vec::<Vec<u8>>::with_capacity(results.len());
    while let Some(bytes) = results.next() {
        bytes_vec.push(bytes?);
    }
    Ok(bytes_vec.into_iter().flatten().collect::<Vec<_>>())
}
