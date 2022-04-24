use crate::error::{self, Error};
use crate::utils::U160;
use crate::version;
use hkdf::Hkdf;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt, encrypt_aead, Cipher};
use sha2::Sha256;

pub const SERVER_INITIAL_SECRET_LABEL: &'static [u8; 9] = b"server in";
pub const CLIENT_INITIAL_SECRET_LABEL: &'static [u8; 9] = b"client in";
pub const HEADER_PROTECTION_LABEL: &'static [u8; 7] = b"quic hp";
pub const INITIAL_VECTOR_LABEL: &'static [u8; 7] = b"quic iv";
pub const KEY_LABEL: &'static [u8; 8] = b"quic key";

#[derive(Debug)]
pub enum ProtectionProtocol {
    Aes128CcmSha256,
    Aes128GcmSha256,
    Aes256GcmSha256,
    Chacha20Poly1305Sha256,
}

impl ProtectionProtocol {
    pub fn sample_len(&self) -> usize {
        match self {
            ProtectionProtocol::Aes256GcmSha256 => 32,
            ProtectionProtocol::Aes128GcmSha256 => 16,
            ProtectionProtocol::Aes128CcmSha256 => 16,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub struct Secret {
    pub secret: [u8; 32],
    pub cipher_suite: ProtectionProtocol,
}

#[derive(Debug)]
pub struct Secrets {
    pub local: Secret,
    pub remote: Secret,
}

impl Secrets {
    pub fn from_initial_secret(is_server: bool, initial_secret: &[u8]) -> error::Result<Self> {
        let mut client_initial_secret = [0u8; 32];
        hkdf_expand_label_sha256(
            &initial_secret[..],
            CLIENT_INITIAL_SECRET_LABEL,
            b"",
            &mut client_initial_secret,
        )?;
        let mut server_initial_secret = [0u8; 32];
        hkdf_expand_label_sha256(
            &initial_secret[..],
            SERVER_INITIAL_SECRET_LABEL,
            b"",
            &mut server_initial_secret,
        )?;
        let (local_secret_key, remote_secret_key) = if is_server {
            (server_initial_secret, client_initial_secret)
        } else {
            (client_initial_secret, server_initial_secret)
        };
        let local = Secret {
            secret: local_secret_key,
            cipher_suite: ProtectionProtocol::Aes128GcmSha256,
        };
        let remote = Secret {
            secret: remote_secret_key,
            cipher_suite: ProtectionProtocol::Aes128GcmSha256,
        };
        Ok(Self { local, remote })
    }
    pub fn from_initial(
        is_server: bool,
        cid_bytes: &[u8],
        version: version::Version,
    ) -> error::Result<Self> {
        let (initial_secret, _) =
            Hkdf::<Sha256>::extract(Some(version.get_kdf_initial_salt()), cid_bytes);
        Self::from_initial_secret(is_server, &initial_secret[..])
    }
}

impl Secret {
    pub fn get_header_protection_mask(&self, sample: &[u8]) -> error::Result<[u8; 5]> {
        // TODO potentially memoise results of expand_label
        let mut header_key = [0u8; 16];
        hkdf_expand_label_sha256(&self.secret, HEADER_PROTECTION_LABEL, b"", &mut header_key)?;
        Ok(get_header_protection_mask(
            &header_key,
            sample,
            &self.cipher_suite,
        ))
    }
    pub fn decrypt_payload(
        &self,
        payload: &[u8],
        associated_data: &[u8],
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        // TODO potentially memoise results of expand_label
        let mut iv_var = [0u8; 12];
        // padded packet number
        let mut set_iv = || -> error::Result<()> {
            hkdf_expand_label_sha256(&self.secret, INITIAL_VECTOR_LABEL, b"", &mut iv_var)?;
            let packet_number_bytes = packet_number.to_be_bytes();
            for i in 0..packet_number_bytes.len() {
                iv_var[iv_var.len() - i - 1] ^=
                    packet_number_bytes[packet_number_bytes.len() - i - 1];
            }
            Ok(())
        };
        Ok(match self.cipher_suite {
            ProtectionProtocol::Aes128GcmSha256 => {
                let mut key = vec![0u8; 16];
                hkdf_expand_label_sha256(&self.secret, KEY_LABEL, b"", &mut key)?;
                set_iv()?;
                let tag = &payload[(payload.len() - 16)..];
                let cipher_text = &payload[..(payload.len() - 16)];
                decrypt_aead(
                    Cipher::aes_128_gcm(),
                    &key,
                    Some(&iv_var[..]),
                    associated_data,
                    cipher_text,
                    tag,
                )
                .unwrap()
            }
            ProtectionProtocol::Aes128CcmSha256 => {
                let mut key = vec![0u8; 16];
                hkdf_expand_label_sha256(&self.secret, KEY_LABEL, b"", &mut key)?;
                set_iv()?;
                let tag = &payload[(payload.len() - 16)..];
                let cipher_text = &payload[..(payload.len() - 16)];
                decrypt_aead(
                    Cipher::aes_128_ccm(),
                    &key,
                    Some(&iv_var[..]),
                    associated_data,
                    cipher_text,
                    tag,
                )
                .unwrap();
                unimplemented!();
            }
            ProtectionProtocol::Aes256GcmSha256 => {
                let mut key = vec![0u8; 32];
                hkdf_expand_label_sha256(&self.secret, KEY_LABEL, b"", &mut key)?;
                set_iv()?;
                decrypt_aead(
                    Cipher::aes_256_gcm(),
                    &key,
                    Some(&iv_var[..]),
                    b"",
                    payload,
                    b"",
                )
                .unwrap();
                unimplemented!();
            }
            _ => unimplemented!(),
        })
    }
    pub fn encrypt_payload(
        &self,
        payload: &[u8],
        associated_data: &[u8],
        packet_number: u64,
    ) -> error::Result<Vec<u8>> {
        // TODO potentially memoise results of expand_label
        let mut iv_var = [0u8; 12];
        // padded packet number
        let mut set_iv = || -> error::Result<()> {
            hkdf_expand_label_sha256(&self.secret, INITIAL_VECTOR_LABEL, b"", &mut iv_var)?;
            let packet_number_bytes = packet_number.to_be_bytes();
            for i in 0..packet_number_bytes.len() {
                iv_var[iv_var.len() - i - 1] ^=
                    packet_number_bytes[packet_number_bytes.len() - i - 1];
            }
            Ok(())
        };
        Ok(match self.cipher_suite {
            ProtectionProtocol::Aes128GcmSha256 => {
                let mut key = vec![0u8; 16];
                hkdf_expand_label_sha256(&self.secret, KEY_LABEL, b"", &mut key)?;
                set_iv()?;
                let mut tag = [0u8; 16];
                let cipher_text = encrypt_aead(
                    Cipher::aes_128_gcm(),
                    &key,
                    Some(&iv_var[..]),
                    associated_data,
                    payload,
                    &mut tag,
                )
                .unwrap();
                [&cipher_text[..], &tag[..]].concat()
            }
            _ => unimplemented!(),
        })
    }
}

pub fn get_connection_id() -> U160 {
    let mut buff = [0u8; 8];
    rand_bytes(&mut buff).unwrap();
    U160::from(u64::from_be_bytes(buff))
}

pub fn get_header_protection_mask(
    key: &[u8],
    sample: &[u8],
    protocol: &ProtectionProtocol,
) -> [u8; 5] {
    let cipher = match protocol {
        ProtectionProtocol::Aes128GcmSha256 => Cipher::aes_128_ecb(),
        ProtectionProtocol::Aes128CcmSha256 => Cipher::aes_128_ecb(),
        ProtectionProtocol::Aes256GcmSha256 => Cipher::aes_256_ecb(),
        ProtectionProtocol::Chacha20Poly1305Sha256 => Cipher::chacha20_poly1305(),
    };
    let result = encrypt(cipher, key, None, sample).unwrap();
    let mut rv = [0u8; 5];
    rv.clone_from_slice(&result[..5]);
    rv
}

fn get_hkdf_label_info(length: usize, label: &[u8], context: &[u8]) -> error::Result<[Vec<u8>; 5]> {
    if length > u16::MAX as usize {
        return Err(Error::InternalError("length does not fit in u16"));
    }
    if context.len() > u8::MAX as usize {
        return Err(Error::InternalError("context length does not fit in u8"));
    }
    let new_label = [b"tls13 ", label].concat();
    if new_label.len() > u8::MAX as usize {
        return Err(Error::InternalError("label length does not fit in u8"));
    }
    let length_bytes = (length as u16).to_be_bytes();
    let label_len_bytes = (new_label.len() as u8).to_be_bytes();
    let context_len_bytes = (context.len() as u8).to_be_bytes();
    let rv = [
        length_bytes.to_vec(),
        label_len_bytes.to_vec(),
        new_label.to_vec(),
        context_len_bytes.to_vec(),
        context.to_vec(),
    ];
    Ok(rv)
}

// TODO make below functions generic
// (issues with dependencies for satisfying trait bounds)
pub fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> error::Result<()> {
    let kdf = Hkdf::<Sha256>::from_prk(secret).unwrap();
    let hkdf_label = get_hkdf_label_info(output.len(), label, context)?;
    kdf.expand(&(hkdf_label.concat())[..], output).unwrap();
    Ok(())
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use hkdf::Hkdf;
    use ring::aead::quic as ring_quic;
    use ring::hkdf as ring_hkdf;
    use sha2::Sha256;

    #[test]
    fn test_get_kdf_bytes() {
        let client_initial_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea");
        let sample = hex!("d1b1c98dd7689fb8ec11d242b123dc9b");
        let expected_mask = hex!("437b9aec36");
        let hkdf_label_info = super::get_hkdf_label_info(16, b"quic hp", b"").unwrap();
        let kdf = ring_hkdf::Prk::new_less_safe(ring_hkdf::HKDF_SHA256, &client_initial_secret);
        let label_info_refs = [
            &hkdf_label_info[0][..],
            &hkdf_label_info[1][..],
            &hkdf_label_info[2][..],
            &hkdf_label_info[3][..],
            &hkdf_label_info[4][..],
        ];
        let okm = kdf.expand(&label_info_refs, &ring_quic::AES_128).unwrap();
        let prot_key = ring_quic::HeaderProtectionKey::from(okm);
        let mask = prot_key.new_mask(&sample).unwrap();
        assert_eq!(
            mask, expected_mask,
            "\nmask: {:X?},\nexpected_mask: {:X?}",
            mask, expected_mask
        );
    }

    #[test]
    fn test_hkdf_expand_label_sha256() {
        let client_initial_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea");
        let expected_client_hp = hex!("9f50449e04a0e810283a1e9933adedd2");
        let mut client_hp = [0u8; 16];
        super::hkdf_expand_label_sha256(&client_initial_secret, b"quic hp", b"", &mut client_hp)
            .unwrap();
        assert_eq!(
            client_hp, expected_client_hp,
            "\nclient_hp: {:X?},\nexpected_client_hp: {:X?}",
            client_hp, expected_client_hp
        );
    }

    // below cases retrieved from https://www.rfc-editor.org/rfc/rfc9001.html
    #[test]
    fn sample_expand_test_cases() {
        let initial_secret =
            hex!("7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44");
        let expected_client_initial_secret =
            hex!("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea");
        let mut client_initial_secret = [0u8; 32];
        super::hkdf_expand_label_sha256(
            &initial_secret,
            super::CLIENT_INITIAL_SECRET_LABEL,
            b"",
            &mut client_initial_secret,
        )
        .unwrap();
        assert_eq!(
            client_initial_secret, expected_client_initial_secret,
            "\nclient_initial_secret: {:X?},\nexpected_client_initial_secret: {:X?}",
            client_initial_secret, expected_client_initial_secret
        );

        let expected_client_key = hex!("1f369613dd76d5467730efcbe3b1a22d");
        let expected_client_iv = hex!("fa044b2f42a3fd3b46fb255c");
        let expected_client_hp = hex!("9f50449e04a0e810283a1e9933adedd2");

        let mut client_key = [0u8; 16];
        super::hkdf_expand_label_sha256(
            &client_initial_secret,
            super::KEY_LABEL,
            b"",
            &mut client_key,
        )
        .unwrap();
        assert_eq!(
            client_key, expected_client_key,
            "\nclient_key: {:X?},\nexpected_client_key: {:X?}",
            client_key, expected_client_key
        );

        let mut client_iv = [0u8; 12];
        super::hkdf_expand_label_sha256(
            &client_initial_secret,
            super::INITIAL_VECTOR_LABEL,
            b"",
            &mut client_iv,
        )
        .unwrap();
        assert_eq!(
            client_iv, expected_client_iv,
            "\nclient_iv: {:X?},\nexpected_client_iv: {:X?}",
            client_iv, expected_client_iv
        );

        let mut client_hp = [0u8; 16];
        super::hkdf_expand_label_sha256(
            &client_initial_secret,
            super::HEADER_PROTECTION_LABEL,
            b"",
            &mut client_hp,
        )
        .unwrap();
        assert_eq!(
            client_hp, expected_client_hp,
            "\nclient_hp: {:X?},\nexpected_client_hp: {:X?}",
            client_hp, expected_client_hp
        );

        let expected_server_initial_secret =
            hex!("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b");
        let mut server_initial_secret = [0u8; 32];
        super::hkdf_expand_label_sha256(
            &initial_secret,
            super::SERVER_INITIAL_SECRET_LABEL,
            b"",
            &mut server_initial_secret,
        )
        .unwrap();
        assert_eq!(
            server_initial_secret, expected_server_initial_secret,
            "\nserver_initial_secret: {:X?},\nexpected_server_initial_secret: {:X?}",
            server_initial_secret, expected_server_initial_secret
        );

        let expected_server_key = hex!("cf3a5331653c364c88f0f379b6067e37");
        let expected_server_iv = hex!("0ac1493ca1905853b0bba03e");
        let expected_server_hp = hex!("c206b8d9b9f0f37644430b490eeaa314");

        let mut server_key = [0u8; 16];
        super::hkdf_expand_label_sha256(
            &server_initial_secret,
            super::KEY_LABEL,
            b"",
            &mut server_key,
        )
        .unwrap();
        assert_eq!(
            server_key, expected_server_key,
            "\nserver_key: {:X?},\nexpected_server_key: {:X?}",
            server_key, expected_server_key
        );

        let mut server_iv = [0u8; 12];
        super::hkdf_expand_label_sha256(
            &server_initial_secret,
            super::INITIAL_VECTOR_LABEL,
            b"",
            &mut server_iv,
        )
        .unwrap();
        assert_eq!(
            server_iv, expected_server_iv,
            "\nserver_iv: {:X?},\nexpected_server_iv: {:X?}",
            server_iv, expected_server_iv
        );

        let mut server_hp = [0u8; 16];
        super::hkdf_expand_label_sha256(
            &server_initial_secret,
            super::HEADER_PROTECTION_LABEL,
            b"",
            &mut server_hp,
        )
        .unwrap();
        assert_eq!(
            server_hp, expected_server_hp,
            "\nserver_hp: {:X?},\nexpected_server_hp: {:X?}",
            server_hp, expected_server_hp
        );
    }

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

    #[test]
    fn test_gen_mask_aes_ecb() {
        let hp = hex!("9f50449e04a0e810283a1e9933adedd2");
        let sample = hex!("d1b1c98dd7689fb8ec11d242b123dc9b");
        let expected_mask = hex!("437b9aec36");
        let mask = super::get_header_protection_mask(
            &hp,
            &sample,
            &super::ProtectionProtocol::Aes128GcmSha256,
        );
        assert_eq!(
            mask, expected_mask,
            "\nmask: {:X?},\nexpected_mask: {:X?}",
            mask, expected_mask
        );
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
        let initial_secret =
            hex!("7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44");
        let associated_data = hex!("c300000001088394c8f03e5157080000449e00000002");
        let payload_data = SAMPLE_FRAME_DATA;
        let expected_cipher_text =
            [&SAMPLE_FRAME_DATA_ENC[..], &SAMPLE_FRAME_DATA_ENC_TAG[..]].concat();
        let packet_number = 2u64;
        let secrets = super::Secrets::from_initial_secret(false, &initial_secret[..]).unwrap();
        let cipher_text = secrets
            .local
            .encrypt_payload(&payload_data[..], &associated_data[..], packet_number)
            .unwrap();
        assert_eq!(
            cipher_text, expected_cipher_text,
            "\ncipher_text: {:02X?},\nexpected_cipher_text: {:02X?}",
            cipher_text, expected_cipher_text
        );
    }

    #[test]
    fn sample_payload_decrypt() {
        let initial_secret =
            hex!("7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44");
        let associated_data = hex!("c300000001088394c8f03e5157080000449e00000002");
        let payload_data = [&SAMPLE_FRAME_DATA_ENC[..], &SAMPLE_FRAME_DATA_ENC_TAG[..]].concat();
        let expected_plain_text = SAMPLE_FRAME_DATA;
        let packet_number = 2u64;
        let secrets = super::Secrets::from_initial_secret(true, &initial_secret[..]).unwrap();
        let plain_text = secrets
            .remote
            .decrypt_payload(&payload_data[..], &associated_data[..], packet_number)
            .unwrap();
        assert_eq!(
            plain_text, expected_plain_text,
            "\nplain_text: {:02X?},\nexpected_plain_text: {:02X?}",
            plain_text, expected_plain_text
        );
    }
}
