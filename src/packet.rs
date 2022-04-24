use crate::connection::Connection;
use crate::error::{self, Error};
use crate::frame::{deserialize_frames, Frame};
use crate::utils::prelude::*;
use crate::utils::{
    self, fixed_len_dcid_from_stream, var_bytes_from_stream, var_u160_from_stream,
    var_u32_from_stream,
};

const VERSION_NEGOTIATION_VERSION_VALUE: u32 = 0;

#[derive(Debug)]
pub struct VersionNegotiationHeaderUnionFields {
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
}

#[derive(Debug)]
pub struct LongPacketHeader {
    header_byte: u8,
    pub version: u32,
    pub destination_connection_id_length: u8,
    pub destination_connection_id: U160,
    pub source_connection_id_length: u8,
    pub source_connection_id: U160,
    version_negotiation: Option<VersionNegotiationHeaderUnionFields>,
    is_protected: bool,
}

fn remove_pn_protection(pn_bytes: &mut [u8], mask: &[u8; 5]) -> error::Result<()> {
    if pn_bytes.len() > 4 {
        Err(Error::InternalError("too many bytes for packet number"))
    } else {
        for i in 0..pn_bytes.len() {
            pn_bytes[i] ^= mask[i + 1];
        }
        Ok(())
    }
}

impl LongPacketHeader {
    pub fn from_stream<T>(stream: &mut T, header_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let version = u32::from_datagram(stream)?;
        let is_version_negotiation = version == VERSION_NEGOTIATION_VERSION_VALUE;
        let (
            version_negotiation,
            destination_connection_id_length,
            destination_connection_id,
            source_connection_id_length,
            source_connection_id,
        ) = if !is_version_negotiation {
            let dcid_len = u8::from_datagram(stream)?;
            if dcid_len > 20 {
                return Err(Error::InternalError(
                    "invalid destination connection id length",
                ));
            }
            let dcid = var_u160_from_stream(stream, dcid_len)?;
            let scid_len = u8::from_datagram(stream)?;
            // version negotiation must not be limited to the supported version's id length rules
            if scid_len > 20 {
                return Err(Error::InternalError("invalid source connection id length"));
            }
            let scid = var_u160_from_stream(stream, scid_len)?;
            (None, dcid_len, dcid, scid_len, scid)
        } else {
            // version negotiation must not be limited to the supported version's id length rules
            let dcid_len = u8::from_datagram(stream)?;
            let dcid = U160::zero();
            let destination_connection_id = var_bytes_from_stream(stream, dcid_len as usize)?;
            let scid_len = u8::from_datagram(stream)?;
            let scid = U160::zero();
            let source_connection_id = var_bytes_from_stream(stream, scid_len as usize)?;
            (
                Some(VersionNegotiationHeaderUnionFields {
                    destination_connection_id,
                    source_connection_id,
                }),
                dcid_len,
                dcid,
                scid_len,
                scid,
            )
        };
        let mut rv = Self {
            header_byte,
            version,
            destination_connection_id_length,
            destination_connection_id,
            source_connection_id_length,
            source_connection_id,
            version_negotiation,
            is_protected: true,
        };
        // explicitly handle retry and version negotiation packets being unprotected
        let is_protected = match rv.packet_type() {
            PacketType::Retry => false,
            PacketType::VersionNegotiation => false,
            _ => true,
        };
        rv.is_protected = is_protected;
        Ok(rv)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            &[self.header_byte][..],
            &self.version.to_be_bytes(),
            &[self.destination_connection_id_length][..],
            &self
                .destination_connection_id
                .to_var_bytes(self.destination_connection_id_length as usize)[..],
            &[self.source_connection_id_length][..],
            &self
                .source_connection_id
                .to_var_bytes(self.source_connection_id_length as usize)[..],
        ]
        .concat()
    }
    fn pn_length_from_header_byte(header_byte: u8) -> u8 {
        (header_byte & 0x03) + 1
    }

    pub fn remove_protection(&mut self, mask: &[u8; 5]) {
        if self.is_protected {
            self.header_byte ^= mask[0] & 0x0f;
            self.is_protected = false;
        }
    }

    pub fn packet_number_length(&self) -> error::Result<usize> {
        if self.is_protected {
            Err(Error::InternalError(
                "attempted to read protected packet number",
            ))
        } else {
            Ok((self.header_byte & 0x03) as usize + 1)
        }
    }

    pub fn packet_type(&self) -> PacketType {
        match self.version {
            VERSION_NEGOTIATION_VERSION_VALUE => PacketType::VersionNegotiation,
            _ => {
                let type_bits = (self.header_byte & ((1 << 6) - 1)) >> 4;
                match type_bits {
                    0x00 => PacketType::Initial,
                    0x01 => PacketType::ZeroRtt,
                    0x02 => PacketType::Handshake,
                    0x03 => PacketType::Retry,
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct PacketVersionNegotiation {
    header: LongPacketHeader,
    supported_versions: Vec<u32>,
}

impl PacketVersionNegotiation {
    pub fn from_stream<T>(stream: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>> + Clone,
    {
        let header_byte = u8::from_datagram(stream)?;
        let header = LongPacketHeader::from_stream(stream, header_byte)?;
        let supported_versions_bytes = utils::all_bytes_from_stream(stream)?;
        if supported_versions_bytes.len() & 0x03 != 0x00 {
            return Err(Error::InternalError(
                "\"supported versions\" is not qword aligned",
            ));
        }
        let mut supported_versions_results = supported_versions_bytes
            .chunks(4)
            .map(|x| u32::from_datagram(&mut utils::make_result_stream(x)));
        let mut supported_versions = Vec::<u32>::with_capacity(supported_versions_results.len());
        while let Some(x) = supported_versions_results.next() {
            supported_versions.push(x?);
        }
        Ok(Self {
            header,
            supported_versions,
        })
    }
}

#[derive(Debug)]
pub struct PacketInitial {
    header: LongPacketHeader,
    token_length: u64,
    token: Vec<u8>,
    length: u64,
    packet_number_bytes: Vec<u8>,
    packet_number: u64,
    packet_payload: Vec<Frame>,
}

impl PacketInitial {
    pub fn from_stream<T>(stream: &mut T, connection: &Connection) -> Result<Self, Error>
    where
        T: Iterator<Item = error::Result<u8>> + Clone,
    {
        let header_byte = u8::from_datagram(stream)?;
        let mut header = LongPacketHeader::from_stream(stream, header_byte)?;
        let (token_length, token_length_bytes) = utils::var_int_with_bytes_from_stream(stream)?;
        let token = var_bytes_from_stream(stream, token_length as usize)?;
        let (length, length_bytes) = utils::var_int_with_bytes_from_stream(stream)?;
        // get largest potential packet number
        let mut packet_number_bytes_protected = var_bytes_from_stream(stream, 4)?;
        let mut offset_stream = stream.clone();
        let mask = connection.get_remote_hp_mask(&mut offset_stream)?;
        header.remove_protection(&mask);
        let packet_number_length = header.packet_number_length()?;
        remove_pn_protection(&mut packet_number_bytes_protected, &mask)?;
        let packet_number_bytes = packet_number_bytes_protected[..packet_number_length].to_vec();
        let packet_number_lsb = var_u32_from_stream(
            &mut utils::make_result_stream(&packet_number_bytes[..]),
            packet_number_length,
        )?;
        let packet_number = connection.reconstruct_pn_initial(packet_number_lsb);
        let protected_frame_data =
            var_bytes_from_stream(stream, length as usize - packet_number_length)?;
        // create associated data
        let associated_data = [
            &header.to_bytes()[..],
            &token_length_bytes[..],
            &token[..],
            &length_bytes[..],
            &packet_number_bytes[..],
        ]
        .concat();
        let frame_data = connection.decrypt_remote_payload(
            &protected_frame_data[..],
            &associated_data[..],
            packet_number,
        )?;
        let packet_payload = deserialize_frames(&mut utils::make_result_stream(&frame_data[..]))?;
        Ok(Self {
            header,
            token_length,
            token,
            length,
            packet_number_bytes,
            packet_number,
            packet_payload,
        })
    }
}

#[derive(Debug)]
pub struct PacketZeroRtt {
    header: LongPacketHeader,
    length: u64,
    packet_number_bytes: Vec<u8>,
    packet_number: u64,
    packet_payload: Vec<Frame>,
}

impl PacketZeroRtt {
    pub fn from_stream<T>(stream: &mut T, connection: &Connection) -> error::Result<Self>
    where
        T: Iterator<Item = Result<u8, Error>> + Clone,
    {
        let header_byte = u8::from_datagram(stream)?;
        let mut header = LongPacketHeader::from_stream(stream, header_byte)?;
        let (length, length_bytes) = utils::var_int_with_bytes_from_stream(stream)?;
        let mut packet_number_bytes_protected = var_bytes_from_stream(stream, 4)?;
        let mut offset_stream = stream.clone();
        let mask = connection.get_remote_hp_mask(&mut offset_stream)?;
        header.remove_protection(&mask);
        let packet_number_length = header.packet_number_length()?;
        remove_pn_protection(&mut packet_number_bytes_protected, &mask)?;
        let packet_number_bytes = packet_number_bytes_protected[..packet_number_length].to_vec();
        let packet_number_lsb = var_u32_from_stream(
            &mut utils::make_result_stream(&packet_number_bytes[..]),
            packet_number_length,
        )?;
        let packet_number = connection.reconstruct_pn_initial(packet_number_lsb);
        let protected_frame_data =
            var_bytes_from_stream(stream, length as usize - packet_number_length)?;
        // create associated data
        let associated_data = [
            &header.to_bytes()[..],
            &length_bytes[..],
            &packet_number_bytes[..packet_number_length],
        ]
        .concat();
        let frame_data = connection.decrypt_remote_payload(
            &protected_frame_data[..],
            &associated_data[..],
            packet_number,
        )?;
        let packet_payload = deserialize_frames(&mut utils::make_result_stream(&frame_data[..]))?;
        Ok(Self {
            header,
            length,
            packet_number_bytes,
            packet_number,
            packet_payload,
        })
    }
}

#[derive(Debug)]
pub struct PacketHandshake {
    header: LongPacketHeader,
    length: u64,
    packet_number_bytes: Vec<u8>,
    packet_number: u64,
    packet_payload: Vec<Frame>,
}

impl PacketHandshake {
    pub fn from_stream<T>(stream: &mut T, connection: &Connection) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>> + Clone,
    {
        let header_byte = u8::from_datagram(stream)?;
        let mut header = LongPacketHeader::from_stream(stream, header_byte)?;
        let (length, length_bytes) = utils::var_int_with_bytes_from_stream(stream)?;
        let mut packet_number_bytes = var_bytes_from_stream(stream, 4)?;
        let mut offset_stream = stream.clone();
        // assumes packet is encoded by the remote
        let mask = connection.get_remote_hp_mask(&mut offset_stream)?;
        header.remove_protection(&mask);
        let packet_number_length = header.packet_number_length()?;
        remove_pn_protection(&mut packet_number_bytes, &mask)?;
        let packet_number_vec = packet_number_bytes[..packet_number_length].to_vec();
        let packet_number_lsb = var_u32_from_stream(
            &mut utils::make_result_stream(&packet_number_vec[..]),
            packet_number_length,
        )?;
        let packet_number = connection.reconstruct_pn_initial(packet_number_lsb);
        let protected_frame_data =
            var_bytes_from_stream(stream, length as usize - packet_number_length)?;
        // create associated data
        let associated_data = [
            &header.to_bytes()[..],
            &length_bytes[..],
            &packet_number_vec[..],
        ]
        .concat();
        let frame_data = connection.decrypt_remote_payload(
            &protected_frame_data[..],
            &associated_data[..],
            packet_number,
        )?;
        let packet_payload = deserialize_frames(&mut utils::make_result_stream(&frame_data[..]))?;
        Ok(Self {
            header,
            length,
            packet_number_bytes: packet_number_vec,
            packet_number,
            packet_payload,
        })
    }
}

#[derive(Debug)]
pub struct PacketRetry {
    version: u32,
    destination_connection_id_length: u8,
    destination_connection_id: U160,
    source_connection_id_length: u8,
    source_connection_id: U160,
    retry_token: Vec<u8>,
    retry_integrity_tag: u128,
}

impl PacketRetry {
    pub fn from_stream<T>(_stream: &mut T) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        // TODO implement this after retry packet integrity implemented
        todo!();
        // let version = u32::from_datagram(stream)?;
        // let destination_connection_id_length = u8::from_datagram(stream)?;
        // if destination_connection_id_length > 20 {
        //     return Err(Error::InternalError(
        //         "invalid destination connection id length",
        //     ));
        // }
        // let destination_connection_id =
        //     var_u160_from_stream(stream, destination_connection_id_length)?;
        // let source_connection_id_length = u8::from_datagram(stream)?;
        // if source_connection_id_length > 20 {
        //     return Err(Error::InternalError("Invalid source connection id length"));
        // }
        // let source_connection_id = var_u160_from_stream(stream, source_connection_id_length)?;
        // let remaining_results = stream.collect::<Vec<_>>();
        // let errs = remaining_results
        //     .iter()
        //     .filter(|x| x.is_err())
        //     .map(|x| x.clone().err().unwrap())
        //     .collect::<Vec<_>>();
        // if errs.len() > 0 {
        //     return Err(errs[0].clone());
        // }
        // let mut retry_token = remaining_results.into_iter().flatten().collect::<Vec<_>>();
        // // check if there's room for integrity tag
        // if retry_token.len() < 16 {
        //     return Err(Error::InternalError("Invalid retry token length"));
        // }
        // let mut retry_integrity_bytes = [0u8; 16];
        // for i in 0..16 {
        //     let tp = match retry_token.pop() {
        //         Some(x) => Ok(x),
        //         None => Err(Error::InternalError("missing retry integrity")),
        //     }?;
        //     retry_integrity_bytes[15 - i] = tp;
        // }
        // let (retry_integrity_tag, _) = u128::decode_from_bytes(&retry_integrity_bytes)?;
        // Ok(Self {
        //     version,
        //     destination_connection_id_length,
        //     destination_connection_id,
        //     source_connection_id_length,
        //     source_connection_id,
        //     retry_token,
        //     retry_integrity_tag,
        // })
    }
}

#[derive(Debug)]
pub struct ShortPacketHeader {
    header_byte: u8,
    pub destination_connection_id: U160,
    is_protected: bool,
}

impl ShortPacketHeader {
    pub fn from_stream<T>(stream: &mut T, header_byte: u8) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let destination_connection_id = fixed_len_dcid_from_stream(stream)?;
        Ok(Self {
            header_byte,
            destination_connection_id,
            is_protected: true,
        })
    }
    pub fn spin_bit(&self) -> error::Result<bool> {
        if self.is_protected {
            Err(Error::InternalError(
                "attempting to read protected spin bit",
            ))
        } else {
            Ok(self.header_byte & 0x20 == 0x20)
        }
    }
    pub fn reserved_bits(&self) -> error::Result<u8> {
        if self.is_protected {
            Err(Error::InternalError(
                "attempting to read protected reserved bits",
            ))
        } else {
            Ok((self.header_byte & 0x18) >> 3)
        }
    }
    pub fn key_phase(&self) -> error::Result<bool> {
        if self.is_protected {
            Err(Error::InternalError(
                "attempting to read protected key phase",
            ))
        } else {
            Ok(self.header_byte & 0x04 == 0x04)
        }
    }
    pub fn packet_number_length(&self) -> error::Result<usize> {
        if self.is_protected {
            Err(Error::InternalError(
                "attempting to read protected packet nuber length",
            ))
        } else {
            Ok((self.header_byte & 0x03) as usize + 1)
        }
    }
    pub fn packet_type(&self) -> PacketType {
        // FIXME stateless reset packets can also get to this path
        PacketType::OneRtt
    }
    pub fn remove_protection(&mut self, mask: &[u8; 5]) {
        if self.is_protected {
            self.header_byte ^= mask[0] & 0x1f;
            self.is_protected = false;
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            &[self.header_byte][..],
            &self.destination_connection_id.to_var_bytes(8),
        ]
        .concat()
    }
}

#[derive(Debug)]
pub struct PacketOneRtt {
    header: ShortPacketHeader,
    packet_number_bytes: Vec<u8>,
    packet_number: u64,
    packet_payload: Vec<Frame>,
}

impl PacketOneRtt {
    pub fn from_stream<T>(stream: &mut T, connection: &Connection) -> error::Result<Self>
    where
        T: Iterator<Item = error::Result<u8>> + Clone,
    {
        let header_byte = u8::from_datagram(stream)?;
        let mut header = ShortPacketHeader::from_stream(stream, header_byte)?;
        // get largest potential packet number
        let mut packet_number_bytes_protected = var_bytes_from_stream(stream, 4)?;
        let mut offset_stream = stream.clone();
        let mask = connection.get_remote_hp_mask(&mut offset_stream)?;
        header.remove_protection(&mask);
        let packet_number_length = header.packet_number_length()?;
        remove_pn_protection(&mut packet_number_bytes_protected, &mask)?;
        let packet_number_bytes = packet_number_bytes_protected[..packet_number_length].to_vec();
        let packet_number_lsb = var_u32_from_stream(
            &mut utils::make_result_stream(&packet_number_bytes[..]),
            packet_number_length,
        )?;
        let packet_number = connection.reconstruct_pn_initial(packet_number_lsb);
        let protected_frame_data = utils::all_bytes_from_stream(stream)?;
        let associated_data = [&header.to_bytes(), &packet_number_bytes[..]].concat();
        let frame_data = connection.decrypt_remote_payload(
            &protected_frame_data[..],
            &associated_data[..],
            packet_number,
        )?;
        let packet_payload = deserialize_frames(&mut utils::make_result_stream(&frame_data[..]))?;
        Ok(Self {
            header,
            packet_number_bytes,
            packet_number,
            packet_payload,
        })
    }
}

#[derive(Debug)]
pub enum PacketHeader {
    Short(ShortPacketHeader),
    Long(LongPacketHeader),
}

impl PacketHeader {
    pub fn get_destination_id(&self) -> U160 {
        match self {
            PacketHeader::Short(ref x) => x.destination_connection_id,
            PacketHeader::Long(ref x) => x.destination_connection_id,
        }
    }
    pub fn get_destination_id_length(&self) -> u8 {
        match self {
            PacketHeader::Short(_) => 8,
            PacketHeader::Long(ref x) => x.destination_connection_id_length,
        }
    }
    pub fn get_packet_type(&self) -> PacketType {
        match self {
            PacketHeader::Short(ref x) => x.packet_type(),
            PacketHeader::Long(ref x) => x.packet_type(),
        }
    }
}

#[derive(Debug)]
pub enum PacketType {
    VersionNegotiation,
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    StatelessReset,
}

#[derive(Debug)]
pub enum Packet {
    VersionNegotiation(PacketVersionNegotiation),
    Initial(PacketInitial),
    ZeroRtt(PacketZeroRtt),
    Handshake(PacketHandshake),
    Retry(PacketRetry),
    OneRtt(PacketOneRtt),
}

pub fn next_header_from_stream<T>(stream: &mut T) -> error::Result<PacketHeader>
where
    T: Iterator<Item = error::Result<u8>>,
{
    let header_byte = stream
        .next()
        .unwrap_or(Err(Error::InternalError("no header byte found")))?;
    if header_byte & 0x80 == 0x80 {
        let res = LongPacketHeader::from_stream(stream, header_byte)?;
        Ok(PacketHeader::Long(res))
    } else {
        let res = ShortPacketHeader::from_stream(stream, header_byte)?;
        Ok(PacketHeader::Short(res))
    }
}

pub fn decode_next_packet<T>(stream: &mut T, connection: &Connection) -> error::Result<Packet>
where
    T: Iterator<Item = error::Result<u8>> + Clone,
{
    let mut header_stream = stream.clone();
    let header = next_header_from_stream(&mut header_stream).unwrap();
    match header {
        PacketHeader::Short(_) => {
            let res = PacketOneRtt::from_stream(stream, connection)?;
            Ok(Packet::OneRtt(res))
        }
        PacketHeader::Long(x) => match x.packet_type() {
            PacketType::Handshake => {
                let res = PacketHandshake::from_stream(stream, connection)?;
                Ok(Packet::Handshake(res))
            }
            PacketType::Initial => {
                let res = PacketInitial::from_stream(stream, connection)?;
                Ok(Packet::Initial(res))
            }
            PacketType::ZeroRtt => {
                let res = PacketZeroRtt::from_stream(stream, connection)?;
                Ok(Packet::ZeroRtt(res))
            }
            PacketType::Retry => {
                let res = PacketRetry::from_stream(stream)?;
                Ok(Packet::Retry(res))
            }
            PacketType::VersionNegotiation => {
                let res = PacketVersionNegotiation::from_stream(stream)?;
                Ok(Packet::VersionNegotiation(res))
            }
            _ => unreachable!(),
        },
    }
}

pub fn decode_packets<T>(stream: &mut T, connection: &Connection) -> error::Result<Vec<Packet>>
where
    T: Iterator<Item = error::Result<u8>> + Clone,
{
    let mut rv = Vec::<Packet>::new();
    while !stream.clone().next().is_none() {
        rv.push(decode_next_packet(stream, connection)?);
    }
    Ok(rv)
}

#[cfg(test)]
mod test {
    use crate::connection::Connection;
    use crate::utils;
    use hex_literal::hex;

    const SAMPLE_PACKET_DATA: [u8; 1200] = hex!(
        "
        c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
        d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
        1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
        8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
        30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
        457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
        4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
        4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
        485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
        059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
        7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
        9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
        be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
        68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
        c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
        f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
        291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
        25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
        14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
        ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
        e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
        c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
        203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
        cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
        fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
        a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
        90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
        162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
        40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
        6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
        8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
        be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
        54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
        760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
        f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
        056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
        7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
        e221af44860018ab0856972e194cd934
        "
    );

    fn test_packet_initial(packet_data: &[u8]) -> super::PacketInitial {
        let mut stream = utils::make_result_stream(packet_data);
        let mut header_stream = stream.clone();
        let header = super::next_header_from_stream(&mut header_stream).unwrap();
        let connection = Connection::new(
            true,
            crate::version::Version::V1,
            header.get_destination_id(),
            header.get_destination_id_length() as usize,
        )
        .unwrap();
        super::PacketInitial::from_stream(&mut stream, &connection).unwrap()
    }

    #[test]
    fn sample_initial_packet() {
        test_packet_initial(&SAMPLE_PACKET_DATA);
    }

    use ring::aead::quic as ring_quic;

    #[test]
    fn test_ring_protection() {
        // this test passing gave me far too much joy
        let key = hex!("9f50449e04a0e810283a1e9933adedd2");
        let sample = hex!("d1b1c98dd7689fb8ec11d242b123dc9b");
        let expected_mask = hex!("437b9aec36");
        let ring_key = ring_quic::HeaderProtectionKey::new(&ring_quic::AES_128, &key).unwrap();
        let mask = ring_key.new_mask(&sample).unwrap();
        assert_eq!(
            mask, expected_mask,
            "\nmask: {:X?},\nexpected_mask: {:X?}",
            mask, expected_mask
        );
    }

    #[test]
    fn test_long_packet_header() {}
}
