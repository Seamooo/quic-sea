use crate::error::{self, Error};
use crate::tls;
use crate::utils::{self, prelude::*};
use crate::version;

#[derive(Debug)]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    Application,
}

#[derive(Debug)]
struct PacketNumberSpaceInfo {
    largest_remote_ack: Option<u64>,
    largest_local_ack: Option<u64>,
    next_pn: u64,
    tls_secrets: Option<tls::Secrets>,
}

impl PacketNumberSpaceInfo {
    pub fn new() -> Self {
        Self {
            largest_remote_ack: None,
            largest_local_ack: None,
            next_pn: 0,
            tls_secrets: None,
        }
    }
}

fn truncate_pn(pn: u64, largest_ack: Option<u64>) -> error::Result<Vec<u8>> {
    match largest_ack {
        None => {
            if pn > u32::MAX as u64 {
                return Err(Error::InternalError(
                    "too few bytes to encode truncated packet number",
                ));
            }
            Ok((pn as u32).to_be_bytes().to_vec())
        }
        Some(x) => {
            if pn <= x {
                return Err(Error::InternalError(
                    "Cannot truncate packet number smaller than largest acknowledged packet number",
                ));
            }
            let diff = pn - x;
            let bit_len = diff.floor_log2()?;
            let byte_len = bit_len / 8 + if bit_len % 8 == 0 { 0 } else { 1 };
            Ok(pn.to_be_bytes()[(8 - byte_len)..].to_vec())
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    version: version::Version,
    initial_pn_info: PacketNumberSpaceInfo,
    handshake_pn_info: PacketNumberSpaceInfo,
    application_pn_info: PacketNumberSpaceInfo,
    dcid: (U160, usize),
    // issued connection ids issued will always be u64
    // but stored in U160, these cannot be issued during
    // construction due to blocking for random bytes while holding a lock,
    // as such it may be uninitialised
    scid: Option<(U160, usize)>,
}

impl Connection {
    pub fn new(
        is_server: bool,
        version: version::Version,
        dcid: U160,
        dcid_len: usize,
    ) -> error::Result<Self> {
        let initial_tls_secrets =
            tls::Secrets::from_initial(is_server, &dcid.to_var_bytes(dcid_len)[..], &version)?;
        let mut initial_pn_info = PacketNumberSpaceInfo::new();
        initial_pn_info.tls_secrets = Some(initial_tls_secrets);
        Ok(Self {
            version,
            initial_pn_info,
            handshake_pn_info: PacketNumberSpaceInfo::new(),
            application_pn_info: PacketNumberSpaceInfo::new(),
            dcid: (dcid, dcid_len),
            scid: None,
        })
    }

    fn borrow_pn_info(&self, pn_space: PacketNumberSpace) -> &PacketNumberSpaceInfo {
        match pn_space {
            PacketNumberSpace::Initial => &self.initial_pn_info,
            PacketNumberSpace::Handshake => &self.handshake_pn_info,
            PacketNumberSpace::Application => &self.application_pn_info,
        }
    }

    fn borrow_mut_pn_info(&mut self, pn_space: PacketNumberSpace) -> &mut PacketNumberSpaceInfo {
        match pn_space {
            PacketNumberSpace::Initial => &mut self.initial_pn_info,
            PacketNumberSpace::Handshake => &mut self.handshake_pn_info,
            PacketNumberSpace::Application => &mut self.application_pn_info,
        }
    }

    fn borrow_tls_secrets(&self, pn_space: PacketNumberSpace) -> error::Result<&tls::Secrets> {
        let pn_info = self.borrow_pn_info(pn_space);
        pn_info.tls_secrets.as_ref().ok_or(Error::InternalError(
            "attempted to retrieve unset tls secrets",
        ))
    }

    pub fn set_scid(&mut self, scid: U160, scid_len: usize) {
        self.scid = Some((scid, scid_len));
    }

    pub fn get_dcid(&self) -> (U160, u8) {
        let (a, b) = self.dcid;
        (a, b as u8)
    }

    pub fn get_scid(&self) -> error::Result<(U160, u8)> {
        let (a, b) = self.scid.ok_or(Error::InternalError("scid not set"))?;
        Ok((a, b as u8))
    }

    pub fn get_local_hp_mask<T>(
        &self,
        pn_space: PacketNumberSpace,
        sample_stream: &mut T,
    ) -> error::Result<[u8; 5]>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let tls_secrets = self.borrow_tls_secrets(pn_space)?;
        let sample = utils::var_bytes_from_stream(
            sample_stream,
            tls_secrets.local.cipher_suite.sample_len(),
        )?;
        tls_secrets.local.get_header_protection_mask(&sample[..])
    }

    pub fn get_remote_hp_mask<T>(
        &self,
        pn_space: PacketNumberSpace,
        sample_stream: &mut T,
    ) -> error::Result<[u8; 5]>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let tls_secrets = self.borrow_tls_secrets(pn_space)?;
        let sample = utils::var_bytes_from_stream(
            sample_stream,
            tls_secrets.remote.cipher_suite.sample_len(),
        )?;
        tls_secrets.remote.get_header_protection_mask(&sample[..])
    }

    pub fn decrypt_remote_payload(
        &self,
        pn_space: PacketNumberSpace,
        payload: &[u8],
        associated_data: &[u8],
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        let tls_secrets = self.borrow_tls_secrets(pn_space)?;
        tls_secrets
            .remote
            .decrypt_payload(payload, associated_data, packet_number)
    }
    pub fn encrypt_local_payload(
        &self,
        pn_space: PacketNumberSpace,
        payload: &[u8],
        associated_data: &[u8],
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        let tls_secrets = self.borrow_tls_secrets(pn_space)?;
        tls_secrets
            .local
            .encrypt_payload(payload, associated_data, packet_number)
    }
    pub fn reconstruct_remote_pn(
        &self,
        pn_space: PacketNumberSpace,
        pn_lsb: &[u8],
    ) -> error::Result<u64> {
        let pn_length = pn_lsb.len();
        assert!(pn_length <= 4);
        let largest_ack = match pn_space {
            PacketNumberSpace::Initial => self.initial_pn_info.largest_remote_ack,
            PacketNumberSpace::Handshake => self.handshake_pn_info.largest_remote_ack,
            PacketNumberSpace::Application => self.application_pn_info.largest_remote_ack,
        };
        let mut tp_pn_bytes = [0u8; 4];
        tp_pn_bytes[(4 - pn_length)..].clone_from_slice(pn_lsb);
        let tp_pn = u32::from_be_bytes(tp_pn_bytes);
        // TODO handle overflow
        let rv = if let Some(x) = largest_ack {
            let mut la_bytes = [0u8; 4];
            la_bytes.clone_from_slice(&x.to_be_bytes()[..4]);
            let tp_la = u32::from_be_bytes(la_bytes);
            if tp_pn > tp_la {
                ((x >> pn_length) << pn_length) + u64::from(tp_pn)
            } else {
                (((x >> pn_length) + 1) << pn_length) + u64::from(tp_pn)
            }
        } else {
            u64::from(tp_pn)
        };
        Ok(rv)
    }

    pub fn get_local_protected_payload_len(
        &self,
        pn_space: PacketNumberSpace,
        payload_len: usize,
    ) -> error::Result<usize> {
        let tls_secrets = self.borrow_tls_secrets(pn_space)?;
        Ok(tls_secrets.local.cipher_suite.tag_len() + payload_len)
    }

    /// Returns next packet number and the truncated encoding
    pub fn get_next_pn(&mut self, pn_space: PacketNumberSpace) -> error::Result<(u64, Vec<u8>)> {
        let pn_info = match pn_space {
            PacketNumberSpace::Initial => &mut self.initial_pn_info,
            PacketNumberSpace::Handshake => &mut self.handshake_pn_info,
            PacketNumberSpace::Application => &mut self.application_pn_info,
        };
        pn_info.next_pn += 1;
        Ok((
            pn_info.next_pn,
            truncate_pn(pn_info.next_pn, pn_info.largest_local_ack)?,
        ))
    }

    pub fn get_version_field(&self) -> u32 {
        self.version.get_version_field_val()
    }
}
