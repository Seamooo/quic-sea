use crate::error;
use crate::tls;
use crate::utils::{self, prelude::*};
use crate::version;

#[derive(Debug)]
pub struct Connection {
    tls_secrets: tls::Secrets,
    pub next_packet_number: u32,
    dcid: U160,
    // issued connection ids issued will always be u64
    // but stored in U160, these cannot be issued during
    // construction, as such it may be uninitialised
    scid: Option<U160>,
}

impl Connection {
    pub fn new(
        is_server: bool,
        version: version::Version,
        dcid: U160,
        dcid_len: usize,
    ) -> error::Result<Self> {
        let tls_secrets =
            tls::Secrets::from_initial(is_server, &dcid.to_var_bytes(dcid_len)[..], version)?;
        Ok(Self {
            tls_secrets,
            next_packet_number: 0,
            dcid,
            scid: None,
        })
    }
    pub fn set_scid(&mut self, scid: U160) {
        self.scid = Some(scid);
    }
    pub fn get_local_hp_mask<T>(&self, sample_stream: &mut T) -> error::Result<[u8; 5]>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let sample = utils::var_bytes_from_stream(
            sample_stream,
            self.tls_secrets.local.cipher_suite.sample_len(),
        )?;
        self.tls_secrets
            .local
            .get_header_protection_mask(&sample[..])
    }
    pub fn get_remote_hp_mask<T>(&self, sample_stream: &mut T) -> error::Result<[u8; 5]>
    where
        T: Iterator<Item = error::Result<u8>>,
    {
        let sample = utils::var_bytes_from_stream(
            sample_stream,
            self.tls_secrets.remote.cipher_suite.sample_len(),
        )?;
        self.tls_secrets
            .remote
            .get_header_protection_mask(&sample[..])
    }
    pub fn decrypt_remote_payload(
        &self,
        payload: &[u8],
        associated_data: &[u8],
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        self.tls_secrets
            .remote
            .decrypt_payload(payload, associated_data, packet_number)
    }
    pub fn reconstruct_pn_initial(&self, packet_number_lsb: u32) -> u64 {
        // TODO implement proper packet number reconstruction
        u64::from(packet_number_lsb)
    }
}
