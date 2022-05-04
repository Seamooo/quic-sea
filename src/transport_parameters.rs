use crate::error;
use crate::utils;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct PreferredAddress {
    ipv4_address: Ipv4Addr,
    ipv4_port: u16,
    ipv6_address: Ipv6Addr,
    ipv6_port: u16,
    connection_id: Vec<u8>,
}

impl PreferredAddress {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.ipv4_address.octets()[..],
            &self.ipv4_port.to_be_bytes()[..],
            &self.ipv6_address.octets()[..],
            &self.ipv6_port.to_be_bytes()[..],
            &self.connection_id[..],
        ]
        .concat()
    }
}

pub enum TransportParameter {
    OriginalDestinationConnectionId(Vec<u8>),
    MaxIdleTimeout(u64),
    StatelessResetToken([u8; 16]),
    MaxUdpPayloadSize(u64),
    InitialMaxData(u64),
    InitialMaxStreamDataBidiLocal(u64),
    InitialMaxStreamDataBidiRemote(u64),
    InitialMaxStreamDataUni(u64),
    InitialMaxStreamsBidi(u64),
    InitialMaxStreamsUni(u64),
    AckDelayExponent(u64),
    MaxAckDelay(u64),
    DisableActiveMigration,
    PreferredAddress(PreferredAddress),
    ActiveConnectionIdLimit(u64),
    InitialSourceConnectionId(Vec<u8>),
    RetrySourceConnectionId(Vec<u8>),
}

impl TransportParameter {
    pub fn identifier_val(&self) -> u64 {
        match self {
            Self::OriginalDestinationConnectionId(_) => 0x00u64,
            Self::MaxIdleTimeout(_) => 0x01u64,
            Self::StatelessResetToken(_) => 0x02u64,
            Self::MaxUdpPayloadSize(_) => 0x03u64,
            Self::InitialMaxData(_) => 0x04u64,
            Self::InitialMaxStreamDataBidiLocal(_) => 0x05u64,
            Self::InitialMaxStreamDataBidiRemote(_) => 0x06u64,
            Self::InitialMaxStreamDataUni(_) => 0x07u64,
            Self::InitialMaxStreamsBidi(_) => 0x08u64,
            Self::InitialMaxStreamsUni(_) => 0x09u64,
            Self::AckDelayExponent(_) => 0x0au64,
            Self::MaxAckDelay(_) => 0x0bu64,
            Self::DisableActiveMigration => 0x0cu64,
            Self::PreferredAddress(_) => 0x0du64,
            Self::ActiveConnectionIdLimit(_) => 0x0eu64,
            Self::InitialSourceConnectionId(_) => 0x0fu64,
            Self::RetrySourceConnectionId(_) => 0x10u64,
        }
    }
    pub fn serialize(&self) -> error::Result<Vec<u8>> {
        let identifier_bytes = utils::encode_var_int(self.identifier_val())?;
        let value_bytes = match self {
            Self::OriginalDestinationConnectionId(x) => x.clone(),
            Self::MaxIdleTimeout(x) => utils::encode_var_int(*x)?,
            Self::StatelessResetToken(x) => x.to_vec(),
            Self::MaxUdpPayloadSize(x) => utils::encode_var_int(*x)?,
            Self::InitialMaxData(x) => utils::encode_var_int(*x)?,
            Self::InitialMaxStreamDataBidiLocal(x) => utils::encode_var_int(*x)?,
            Self::InitialMaxStreamDataBidiRemote(x) => utils::encode_var_int(*x)?,
            Self::InitialMaxStreamDataUni(x) => utils::encode_var_int(*x)?,
            Self::InitialMaxStreamsBidi(x) => utils::encode_var_int(*x)?,
            Self::InitialMaxStreamsUni(x) => utils::encode_var_int(*x)?,
            Self::AckDelayExponent(x) => utils::encode_var_int(*x)?,
            Self::MaxAckDelay(x) => utils::encode_var_int(*x)?,
            Self::DisableActiveMigration => vec![],
            Self::PreferredAddress(x) => x.to_bytes(),
            Self::ActiveConnectionIdLimit(x) => utils::encode_var_int(*x)?,
            Self::InitialSourceConnectionId(x) => x.clone(),
            Self::RetrySourceConnectionId(x) => x.clone(),
        };
        let length_bytes = utils::encode_var_int(value_bytes.len() as u64)?;
        Ok([&identifier_bytes[..], &length_bytes[..], &value_bytes[..]].concat())
    }
}
