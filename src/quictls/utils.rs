use openssl::rand::rand_bytes;

pub fn get_connection_id() -> u64 {
    let mut buff = [0u8; 8];
    rand_bytes(&mut buff).unwrap();
    u64::from_be_bytes(buff)
}