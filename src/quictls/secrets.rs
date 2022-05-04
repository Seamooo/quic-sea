use crate::utils;
use super::cipher_suite::{self, QuicTlsCipherSuite};
use crate::error;
use crate::version::Version;

const SERVER_INITIAL_SECRET_LABEL: &'static [u8; 9] = b"server in";
const CLIENT_INITIAL_SECRET_LABEL: &'static [u8; 9] = b"client in";
const HEADER_PROTECTION_LABEL: &'static [u8; 7] = b"quic hp";
const INITIAL_VECTOR_LABEL: &'static [u8; 7] = b"quic iv";
const KEY_LABEL: &'static [u8; 8] = b"quic key";

#[derive(Debug)]
pub struct Secrets {
    cipher_suite: &'static QuicTlsCipherSuite,
    hp: Vec<u8>,
    iv: Option<Vec<u8>>,
    key: Vec<u8>,
}

impl Secrets {
    pub fn from_initial(server: bool, cid_bytes: &[u8], version: &Version) -> error::Result<Self> {
        let cipher_suite = &cipher_suite::TLS13_AES_128_GCM_SHA256;
        let initial_secret =
            (cipher_suite.hkdf_extract)(Some(version.get_kdf_initial_salt()), cid_bytes);
        let label = if server {
            SERVER_INITIAL_SECRET_LABEL
        } else {
            CLIENT_INITIAL_SECRET_LABEL
        };
        let mut secret = [0u8; 32];
        (cipher_suite.hkdf_expand_label)(&initial_secret[..], label, b"", &mut secret)?;
        Self::from_secret(cipher_suite, &secret[..])
    }
    pub fn from_secret(
        cipher_suite: &'static QuicTlsCipherSuite,
        secret: &[u8],
    ) -> error::Result<Self> {
        let hp = cipher_suite.get_hp_secret(secret, HEADER_PROTECTION_LABEL)?;
        let iv = cipher_suite.get_iv_secret(secret, INITIAL_VECTOR_LABEL)?;
        let key = cipher_suite.get_key(secret, KEY_LABEL)?;
        Ok(Self {
            cipher_suite,
            hp,
            iv,
            key,
        })
    }
    pub fn encrypt_payload(
        &self,
        payload: &[u8],
        associated_data: Option<&[u8]>,
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        let mut iv_internal;
        let iv = match self.iv {
            Some(ref x) => {
                let pn_bytes = packet_number.to_be_bytes();
                iv_internal = x.clone();
                let iv_len = iv_internal.len();
                let length = pn_bytes.len().min(iv_len);
                for i in 0..length {
                    iv_internal[iv_len - i - 1] ^= pn_bytes[pn_bytes.len() - i - 1];
                }
                Some(&iv_internal[..])
            }
            None => None,
        };
        (self.cipher_suite.encrypt)(&self.key[..], iv, associated_data, payload)
    }
    pub fn decrypt_payload(
        &self,
        payload: &[u8],
        associated_data: Option<&[u8]>,
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        let mut iv_internal;
        let iv = match self.iv {
            Some(ref x) => {
                let pn_bytes = packet_number.to_be_bytes();
                iv_internal = x.clone();
                let iv_len = iv_internal.len();
                let length = pn_bytes.len().min(iv_len);
                for i in 0..length {
                    iv_internal[iv_len - i - 1] ^= pn_bytes[pn_bytes.len() - i - 1];
                }
                Some(&iv_internal[..])
            }
            None => None,
        };
        (self.cipher_suite.decrypt)(&self.key[..], iv, associated_data, payload)
    }
    pub fn get_header_protection_mask<T>(
        &self,
        sample_stream: &mut T,
    ) -> error::Result<[u8; 5]>
    where T: Iterator<Item= error::Result<u8>>,
    {
        let sample = utils::var_bytes_from_stream(sample_stream, self.cipher_suite.sample_len)?;
        (self.cipher_suite.hp_mask)(&self.hp[..], &sample[..])
    }
    pub fn get_protected_payload_len(&self, payload_len: usize) -> usize {
        self.cipher_suite.get_protected_payload_len(payload_len)
    }
}

#[cfg(test)]
mod test {
    use super::super::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use hex_literal::hex;
    use hkdf::Hkdf;
    use sha2::Sha256;

    #[test]
    fn test_initial_keys() {
        let expected_secret =
            hex!("7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44");
        let initial_cid_bytes = hex!("8394c8f03e515708");
        let (secret, _) = Hkdf::<Sha256>::extract(
            Some(crate::version::KDF_INITIAL_SALT_V1),
            &initial_cid_bytes,
        );
        assert_eq!(secret[..], expected_secret[..]);
    }

    // below constants retrieved from https://www.rfc-editor.org/rfc/rfc9001.html
    const SAMPLE_FRAME_DATA: [u8; 1162] = hex!(
        "
        060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
        04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
        616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
        04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
        baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
        0d0010000e0403050306030203080408 050806002d00020101001c0002400100
        3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
        75300901100f088394c8f03e51570806 048000ffff0000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000000000000000 00000000000000000000000000000000
        00000000000000000000
        "
    );

    const SAMPLE_FRAME_DATA_ENC: [u8; 1162] = hex!(
        "
        d1b1c98dd7689fb8ec11
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
        "
    );

    const SAMPLE_FRAME_DATA_ENC_TAG: [u8; 16] = hex!("e221af44860018ab0856972e194cd934");

    #[test]
    fn sample_payload_encrypt() {
        let client_initial_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea");
        let associated_data = hex!("c300000001088394c8f03e5157080000449e00000002");
        let payload_data = SAMPLE_FRAME_DATA;
        let expected_cipher_text =
            [&SAMPLE_FRAME_DATA_ENC[..], &SAMPLE_FRAME_DATA_ENC_TAG[..]].concat();
        let packet_number = 2u64;
        let secrets =
            super::Secrets::from_secret(&TLS13_AES_128_GCM_SHA256, &client_initial_secret[..])
                .unwrap();
        let cipher_text = secrets
            .encrypt_payload(&payload_data[..], Some(&associated_data[..]), packet_number)
            .unwrap();
        assert_eq!(
            cipher_text, expected_cipher_text,
            "\ncipher_text: {:02X?},\nexpected_cipher_text: {:02X?}",
            cipher_text, expected_cipher_text
        );
    }

    #[test]
    fn sample_payload_decrypt() {
        let client_initial_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea");
        let associated_data = hex!("c300000001088394c8f03e5157080000449e00000002");
        let payload_data = [&SAMPLE_FRAME_DATA_ENC[..], &SAMPLE_FRAME_DATA_ENC_TAG[..]].concat();
        let expected_plain_text = SAMPLE_FRAME_DATA;
        let packet_number = 2u64;
        let secrets =
            super::Secrets::from_secret(&TLS13_AES_128_GCM_SHA256, &client_initial_secret[..])
                .unwrap();
        let plain_text = secrets
            .decrypt_payload(&payload_data[..], Some(&associated_data[..]), packet_number)
            .unwrap();
        assert_eq!(
            plain_text, expected_plain_text,
            "\nplain_text: {:02X?},\nexpected_plain_text: {:02X?}",
            plain_text, expected_plain_text
        );
    }

    #[test]
    fn test_initial_secrets() {
        let cid_bytes = hex!("8394c8f03e515708");
        let client_secrets =
            super::Secrets::from_initial(false, &cid_bytes[..], &crate::version::Version::V1)
                .unwrap();
        let expected_client_secrets = super::Secrets {
            cipher_suite: &TLS13_AES_128_GCM_SHA256,
            key: hex!("1f369613dd76d5467730efcbe3b1a22d").to_vec(),
            hp: hex!("9f50449e04a0e810283a1e9933adedd2").to_vec(),
            iv: Some(hex!("fa044b2f42a3fd3b46fb255c").to_vec()),
        };
        assert_eq!(client_secrets.key, expected_client_secrets.key);
        assert_eq!(client_secrets.hp, expected_client_secrets.hp);
        assert_eq!(client_secrets.iv, expected_client_secrets.iv);
    }
}
