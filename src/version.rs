use hex_literal::hex;

pub const KDF_INITIAL_SALT_V1: &'static [u8; 20] =
    &hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

#[derive(Debug)]
pub enum Version {
    V1,
}

impl Version {
    pub fn get_kdf_initial_salt(&self) -> &'static [u8] {
        match self {
            Version::V1 => KDF_INITIAL_SALT_V1,
        }
    }
}
