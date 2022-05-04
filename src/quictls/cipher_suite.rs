use crate::error::{self, Error};
use hkdf::Hkdf;
use openssl::symm::{decrypt_aead, encrypt, encrypt_aead, Cipher};
use sha2::Sha256;

// NOTE interface will change when chacha20_pol1305 implemented
pub struct QuicTlsCipherSuite {
    pub sample_len: usize,
    tag_len: Option<usize>,
    key_len: usize,
    iv_len: Option<usize>,
    // decrypt: key, iv, associated_data, payload -> plain_text
    pub decrypt: fn(&[u8], Option<&[u8]>, Option<&[u8]>, &[u8]) -> error::Result<Vec<u8>>,
    // encrypt: key, iv, associated_data, payload -> cipher_text
    pub encrypt: fn(&[u8], Option<&[u8]>, Option<&[u8]>, &[u8]) -> error::Result<Vec<u8>>,
    // hp_mask: key, sample -> mask
    pub hp_mask: fn(&[u8], &[u8]) -> error::Result<[u8; 5]>,
    // hkdf_expand_label: secret, label, context, output_buffer (also indicates length) -> ()
    pub hkdf_expand_label: fn(&[u8], &[u8], &[u8], &mut [u8]) -> error::Result<()>,
    // hkdf_extract: salt, initial_key_material -> secret
    pub hkdf_extract: fn(Option<&[u8]>, &[u8]) -> Vec<u8>,
}

impl std::fmt::Debug for QuicTlsCipherSuite {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        Ok(())
    }
}

impl QuicTlsCipherSuite {
    // not storing key label as versioning could change this
    pub fn get_key(&self, secret: &[u8], key_label: &[u8]) -> error::Result<Vec<u8>> {
        let mut rv = vec![0u8; self.key_len];
        (self.hkdf_expand_label)(secret, key_label, b"", &mut rv)?;
        Ok(rv)
    }
    pub fn get_hp_secret(&self, secret: &[u8], hp_label: &[u8]) -> error::Result<Vec<u8>> {
        let mut rv = vec![0u8; 16];
        (self.hkdf_expand_label)(secret, hp_label, b"", &mut rv)?;
        Ok(rv)
    }
    pub fn get_iv_secret(&self, secret: &[u8], iv_label: &[u8]) -> error::Result<Option<Vec<u8>>> {
        Ok(match self.iv_len {
            Some(x) => {
                let mut rv = vec![0u8; x];
                (self.hkdf_expand_label)(secret, iv_label, b"", &mut rv)?;
                Some(rv)
            }
            None => None,
        })
    }
    pub fn get_protected_payload_len(&self, payload_len: usize) -> usize {
        self.tag_len.unwrap_or(0) + payload_len
    }
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

pub fn hkdf_extract_sha256(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let (rv, _) = Hkdf::<Sha256>::extract(salt, ikm);
    (&rv[..]).to_vec()
}

pub fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> error::Result<()> {
    let kdf = Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Error::InternalError("error creating kdf object"))?;
    let hkdf_label = get_hkdf_label_info(output.len(), label, context)?;
    kdf.expand(&(hkdf_label.concat())[..], output)
        .map_err(|_| Error::InternalError("error expanding label"))
}

fn hp_mask(cipher: Cipher, key: &[u8], sample: &[u8]) -> [u8; 5] {
    let result = encrypt(cipher, key, None, sample).unwrap();
    let mut rv = [0u8; 5];
    rv.clone_from_slice(&result[..5]);
    rv
}

fn hp_mask_aes_128_ecb(key: &[u8], sample: &[u8]) -> error::Result<[u8; 5]> {
    Ok(hp_mask(Cipher::aes_128_ecb(), key, sample))
}

const AES_128_GCM_SAMPLE_LEN: usize = 16;
const AES_128_GCM_TAG_LEN: usize = 16;
const AES_128_KEY_LEN: usize = 16;
const AES_128_IV_LEN: usize = 12;

fn internal_encrypt_aes_128_gcm(
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
    payload: &[u8],
) -> error::Result<Vec<u8>> {
    let mut tag = [0u8; AES_128_GCM_TAG_LEN];
    let cipher_text = encrypt_aead(
        Cipher::aes_128_gcm(),
        key,
        Some(iv),
        associated_data,
        payload,
        &mut tag,
    )
    .map_err(|_| Error::InternalError("error in aes_128_gcm encryption"))?;
    Ok([&cipher_text[..], &tag[..]].concat())
}

fn encrypt_aes_128_gcm(
    key: &[u8],
    iv: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    payload: &[u8],
) -> error::Result<Vec<u8>> {
    let iv = iv.ok_or(Error::InternalError(
        "aes_128_gcm requires an initialsation vector",
    ))?;
    let associated_data =
        associated_data.ok_or(Error::InternalError("aes_128_gcm requires associated data"))?;
    internal_encrypt_aes_128_gcm(key, iv, associated_data, payload)
}

fn internal_decrypt_aes_128_gcm(
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
    payload: &[u8],
) -> error::Result<Vec<u8>> {
    let tag = &payload[(payload.len() - AES_128_GCM_TAG_LEN)..];
    let cipher_text = &payload[..(payload.len() - 16)];
    decrypt_aead(
        Cipher::aes_128_gcm(),
        &key,
        Some(iv),
        associated_data,
        cipher_text,
        tag,
    )
    .map_err(|_| Error::InternalError("error in aes_128_gcm decryption"))
}

fn decrypt_aes_128_gcm(
    key: &[u8],
    iv: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    payload: &[u8],
) -> error::Result<Vec<u8>> {
    let iv = iv.ok_or(Error::InternalError(
        "aes_128_gcm requires an initialsation vector",
    ))?;
    let associated_data =
        associated_data.ok_or(Error::InternalError("aes_128_gcm requires associated data"))?;
    internal_decrypt_aes_128_gcm(key, iv, associated_data, payload)
}

pub static TLS13_AES_128_GCM_SHA256: QuicTlsCipherSuite = QuicTlsCipherSuite {
    sample_len: AES_128_GCM_SAMPLE_LEN,
    tag_len: Some(AES_128_GCM_TAG_LEN),
    key_len: AES_128_KEY_LEN,
    iv_len: Some(AES_128_IV_LEN),
    hp_mask: hp_mask_aes_128_ecb,
    hkdf_expand_label: hkdf_expand_label_sha256,
    hkdf_extract: hkdf_extract_sha256,
    encrypt: encrypt_aes_128_gcm,
    decrypt: decrypt_aes_128_gcm,
};

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use ring::aead::quic as ring_quic;
    use ring::hkdf as ring_hkdf;

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

    const SERVER_INITIAL_SECRET_LABEL: &'static [u8; 9] = b"server in";
    const CLIENT_INITIAL_SECRET_LABEL: &'static [u8; 9] = b"client in";
    const HEADER_PROTECTION_LABEL: &'static [u8; 7] = b"quic hp";
    const INITIAL_VECTOR_LABEL: &'static [u8; 7] = b"quic iv";
    const KEY_LABEL: &'static [u8; 8] = b"quic key";

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
            CLIENT_INITIAL_SECRET_LABEL,
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
        super::hkdf_expand_label_sha256(&client_initial_secret, KEY_LABEL, b"", &mut client_key)
            .unwrap();
        assert_eq!(
            client_key, expected_client_key,
            "\nclient_key: {:X?},\nexpected_client_key: {:X?}",
            client_key, expected_client_key
        );

        let mut client_iv = [0u8; 12];
        super::hkdf_expand_label_sha256(
            &client_initial_secret,
            INITIAL_VECTOR_LABEL,
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
            HEADER_PROTECTION_LABEL,
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
            SERVER_INITIAL_SECRET_LABEL,
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
        super::hkdf_expand_label_sha256(&server_initial_secret, KEY_LABEL, b"", &mut server_key)
            .unwrap();
        assert_eq!(
            server_key, expected_server_key,
            "\nserver_key: {:X?},\nexpected_server_key: {:X?}",
            server_key, expected_server_key
        );

        let mut server_iv = [0u8; 12];
        super::hkdf_expand_label_sha256(
            &server_initial_secret,
            INITIAL_VECTOR_LABEL,
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
            HEADER_PROTECTION_LABEL,
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
        let secret = super::hkdf_extract_sha256(
            Some(crate::version::KDF_INITIAL_SALT_V1),
            &initial_cid_bytes,
        );
        assert_eq!(secret[..], expected_secret[..]);
    }

    #[test]
    fn test_hp_mask_aes_128_ecb() {
        let hp = hex!("9f50449e04a0e810283a1e9933adedd2");
        let sample = hex!("d1b1c98dd7689fb8ec11d242b123dc9b");
        let expected_mask = hex!("437b9aec36");
        let mask = super::hp_mask_aes_128_ecb(&hp, &sample).unwrap();
        assert_eq!(
            mask, expected_mask,
            "\nmask: {:X?},\nexpected_mask: {:X?}",
            mask, expected_mask
        );
    }
}
