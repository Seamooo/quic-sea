use crate::error;
use crate::error::Error;
use crate::utils::prelude::*;
use crate::utils::{
    all_bytes_from_stream, decode_bytes, decode_var_int, var_bytes_from_stream,
    var_int_from_stream, var_u160_from_stream,
};
use std::io::{self, Write};

#[derive(Debug)]
struct EcnCounts {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
}

impl EcnCounts {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (ect0_count, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (ect1_count, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (ecn_ce_count, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                ect0_count,
                ect1_count,
                ecn_ce_count,
            },
            inc,
        ))
    }
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
}

#[derive(Debug)]
struct AckRange {
    gap: u64,
    ack_range_length: u64,
}

impl AckRange {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (gap, tp) = decode_var_int(data)?;
        inc += tp;
        let (ack_range_length, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                gap,
                ack_range_length,
            },
            inc,
        ))
    }
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
    fn from_bytes(data: &[u8], type_byte: u8) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (largest_acknowledged, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (ack_delay, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (ack_range_count, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (first_ack_range, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        // NOTE below converts from u64 to usize (assumes u32 max range)
        // FIXME need to bounds check before allocation
        let mut ack_range = Vec::with_capacity(ack_range_count as usize);
        for _ in 0..ack_range_count {
            let (tp_result, tp_inc) = AckRange::from_bytes(&data[inc..])?;
            ack_range.push(tp_result);
            inc += tp_inc;
        }
        let ecn_counts = if type_byte & 0x1 == 1 {
            let (tp_result, tp_inc) = EcnCounts::from_bytes(&data[inc..])?;
            inc += tp_inc;
            Some(tp_result)
        } else {
            None
        };
        Ok((
            Self {
                largest_acknowledged,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ack_range,
                ecn_counts,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameResetStream {
    stream_id: u64,
    application_protocol_error_code: u64,
    final_size: u64,
}

impl FrameResetStream {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (stream_id, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (application_protocol_error_code, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (final_size, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                stream_id,
                application_protocol_error_code,
                final_size,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameStopSending {
    stream_id: u64,
    application_protocol_error_code: u64,
}

impl FrameStopSending {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (stream_id, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (application_protocol_error_code, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                stream_id,
                application_protocol_error_code,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameCrypto {
    offset: u64,
    length: u64,
    crypto_data: Vec<u8>,
}

impl FrameCrypto {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (offset, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (length, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let total_size = (length + offset) as usize;
        let (crypto_data, tp) = decode_bytes(&data[inc..], total_size)?;
        inc += tp;
        Ok((
            Self {
                offset,
                length,
                crypto_data,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameNewToken {
    token_length: u64,
    token: Vec<u8>,
}

impl FrameNewToken {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (token_length, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        // TODO handle overflow below for 32-bit implementations
        let token_length_usize = token_length as usize;
        let (token, tp) = decode_bytes(&data[inc..], token_length_usize)?;
        inc += tp;
        Ok((
            Self {
                token_length,
                token,
            },
            inc,
        ))
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
    fn from_bytes(data: &[u8], type_byte: u8) -> Result<(Self, usize), Error> {
        // WARNING below expects that the length of the slice view sent contains
        // exclusively the view from the second byte of the frame to the end of the packet
        // any additional padding will break this function
        let has_offset = type_byte & 0x04 == 1;
        let has_length = type_byte & 0x02 == 1;
        let is_fin = type_byte & 0x01 == 1;
        let mut inc = 0;
        let (stream_id, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let offset = if has_offset {
            let (tp_result, tp_inc) = decode_var_int(&data[inc..])?;
            inc += tp_inc;
            tp_result
        } else {
            0
        };
        let length = if has_length {
            let (tp_result, tp_inc) = decode_var_int(&data[inc..])?;
            inc += tp_inc;
            tp_result
        } else {
            (data.len() - inc) as u64
        };
        // TODO uncomfortable with below typecast
        let length_usize = length as usize;
        let (stream_data, tp) = decode_bytes(&data[inc..], length_usize)?;
        Ok((
            Self {
                stream_id,
                offset,
                length,
                stream_data,
                is_fin,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameMaxData {
    maximum_data: u64,
}

impl FrameMaxData {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let (maximum_data, inc) = decode_var_int(data)?;
        Ok((Self { maximum_data }, inc))
    }
    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let maximum_data = var_int_from_stream(datagram)?;
        Ok(Self { maximum_data })
    }
}

#[derive(Debug)]
pub struct FrameMaxStreamData {
    stream_id: u64,
    maximum_stream_data: u64,
}

impl FrameMaxStreamData {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (stream_id, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (maximum_stream_data, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                stream_id,
                maximum_stream_data,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameMaxStreams {
    maximum_streams: u64,
    is_unidirectional: bool,
}

impl FrameMaxStreams {
    fn from_bytes(data: &[u8], type_byte: u8) -> Result<(Self, usize), Error> {
        let (maximum_streams, inc) = decode_var_int(data)?;
        let is_unidirectional = type_byte & 0x01 == 1;
        Ok((
            Self {
                maximum_streams,
                is_unidirectional,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameDataBlocked {
    maximum_data: u64,
}

impl FrameDataBlocked {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let (maximum_data, inc) = decode_var_int(data)?;
        Ok((Self { maximum_data }, inc))
    }

    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let maximum_data = var_int_from_stream(datagram)?;
        Ok(Self { maximum_data })
    }
}

#[derive(Debug)]
pub struct FrameStreamDataBlocked {
    stream_id: u64,
    maximum_stream_data: u64,
}

impl FrameStreamDataBlocked {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (stream_id, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (maximum_stream_data, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                stream_id,
                maximum_stream_data,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameStreamsBlocked {
    maximum_streams: u64,
    is_unidirectional_limit: bool,
}

impl FrameStreamsBlocked {
    fn from_bytes(data: &[u8], type_byte: u8) -> Result<(Self, usize), Error> {
        let (maximum_streams, inc) = decode_var_int(data)?;
        let is_unidirectional_limit = type_byte & 0x01 == 1;
        Ok((
            Self {
                maximum_streams,
                is_unidirectional_limit,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameNewConnectionId {
    sequence_number: u64,
    retire_prior_to: u64,
    length: u8,
    connection_id: U160, // 160 bit field
    stateless_reset_token: u128,
}

impl FrameNewConnectionId {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut inc = 0;
        let (sequence_number, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (retire_prior_to, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let length = data[inc];
        inc += 1;
        if 1 > length || length > 20 {
            return Err(Error::FrameEncodingError);
        }
        let mut idx0 = 0u32;
        let mut idx1 = 0u128;
        for _ in 0..length {
            idx0 <<= 8;
            idx0 |= (idx1 >> 120) as u32;
            // mask to prevent overflow
            idx1 &= (1 << 120) - 1;
            idx1 <<= 8;
            idx1 |= u128::from(data[inc]);
            inc += 1;
        }
        let (stateless_reset_token, tp) = u128::decode_from_bytes(&data[inc..])?;
        inc += tp;
        Ok((
            Self {
                sequence_number,
                retire_prior_to,
                length,
                connection_id: U160 { idx0, idx1 },
                stateless_reset_token,
            },
            inc,
        ))
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
}

#[derive(Debug)]
pub struct FrameRetireConnectionId {
    sequence_number: u64,
}

impl FrameRetireConnectionId {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let (sequence_number, inc) = decode_var_int(data)?;
        Ok((Self { sequence_number }, inc))
    }

    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let sequence_number = var_int_from_stream(datagram)?;
        Ok(Self { sequence_number })
    }
}

#[derive(Debug)]
pub struct FramePathChallenge {
    data: u64,
}

impl FramePathChallenge {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let (data, inc) = u64::decode_from_bytes(data)?;
        Ok((Self { data }, inc))
    }

    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let data = u64::from_datagram(datagram)?;
        Ok(Self { data })
    }
}

#[derive(Debug)]
pub struct FramePathResponse {
    data: u64,
}

impl FramePathResponse {
    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        let (data, inc) = u64::decode_from_bytes(data)?;
        Ok((Self { data }, inc))
    }

    fn from_datagram<T>(datagram: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let data = u64::from_datagram(datagram)?;
        Ok(Self { data })
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
    fn from_bytes(data: &[u8], type_byte: u8) -> Result<(Self, usize), Error> {
        let is_application_error = type_byte & 1 == 1;
        let mut inc = 0;
        let (error_code, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let frame_type = if !is_application_error {
            let (tp_res, tp_inc) = decode_var_int(&data[inc..])?;
            inc += tp_inc;
            Some(tp_res)
        } else {
            None
        };
        let (reason_phrase_length, tp) = decode_var_int(&data[inc..])?;
        inc += tp;
        let (reason_phrase, tp) = decode_bytes(&data[inc..], reason_phrase_length as usize)?;
        inc += tp;
        Ok((
            Self {
                error_code,
                frame_type,
                reason_phrase_length,
                reason_phrase,
                is_application_error,
            },
            inc,
        ))
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
