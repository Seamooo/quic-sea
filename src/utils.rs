use crate::error;
use crate::error::Error;
use std::alloc::{self, Layout};
use std::io::{self, Write};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct U160 {
    pub idx0: u32,
    pub idx1: u128,
}

impl From<u64> for U160 {
    fn from(val: u64) -> Self {
        let idx1 = u128::from(val);
        Self { idx0: 0u32, idx1 }
    }
}

impl U160 {
    pub const BITS: usize = 160;
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut tp_low = self.idx1;
        let mut tp_high = self.idx0;
        let mut rv = [0u8; 20];
        for i in 0..20 {
            rv[20 - i - 1] = (tp_low & 0xff) as u8;
            tp_low >>= 8;
            tp_low |= ((tp_high & 0xff) as u128) << 120;
            tp_high >>= 8;
        }
        rv
    }
    pub fn to_var_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        bytes.rotate_left(Self::BITS / 8 - len);
        bytes[..len].to_vec()
    }
    pub fn zero() -> Self {
        Self {
            idx0: 0u32,
            idx1: 0u128,
        }
    }
}

pub mod prelude {
    use crate::error;
    use crate::error::Error;

    pub use super::U160;

    pub trait DecodeFromBytes {
        type Output;
        fn decode_from_bytes(data: &[u8]) -> error::Result<(Self::Output, usize)>;
    }

    pub trait FromDatagram {
        type Output;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>;
    }

    impl DecodeFromBytes for u8 {
        type Output = Self;
        fn decode_from_bytes(data: &[u8]) -> error::Result<(Self::Output, usize)> {
            if data.len() < 1 {
                return Err(Error::InternalError("not enough bytes for u8"));
            }
            Ok((data[0], 1))
        }
    }

    impl DecodeFromBytes for u16 {
        type Output = Self;
        fn decode_from_bytes(data: &[u8]) -> error::Result<(Self::Output, usize)> {
            let size = std::mem::size_of::<Self>();
            if data.len() < size {
                return Err(Error::InternalError("not enough bytes for u16"));
            }
            let mut result: Self = 0;
            for i in 0..size {
                result <<= 8;
                result |= Self::from(data[i]);
            }
            Ok((result, size))
        }
    }

    impl DecodeFromBytes for u32 {
        type Output = Self;
        fn decode_from_bytes(data: &[u8]) -> error::Result<(Self::Output, usize)> {
            let size = std::mem::size_of::<Self>();
            if data.len() < size {
                return Err(Error::InternalError("not enough bytes for u32"));
            }
            let mut result: Self = 0;
            for i in 0..size {
                result <<= 8;
                result |= Self::from(data[i]);
            }
            Ok((result, size))
        }
    }

    impl DecodeFromBytes for u64 {
        type Output = Self;
        fn decode_from_bytes(data: &[u8]) -> error::Result<(Self::Output, usize)> {
            let size = std::mem::size_of::<Self>();
            if data.len() < size {
                return Err(Error::InternalError("not enough bytes for u64"));
            }
            let mut result: Self = 0;
            for i in 0..size {
                result <<= 8;
                result |= Self::from(data[i]);
            }
            Ok((result, size))
        }
    }

    impl DecodeFromBytes for u128 {
        type Output = Self;
        fn decode_from_bytes(data: &[u8]) -> error::Result<(Self::Output, usize)> {
            let size = std::mem::size_of::<Self>();
            if data.len() < size {
                return Err(Error::InternalError("not enough bytes for u128"));
            }
            let mut result: Self = 0;
            for i in 0..size {
                result <<= 8;
                result |= Self::from(data[i]);
            }
            Ok((result, size))
        }
    }

    impl FromDatagram for u8 {
        type Output = Self;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>,
        {
            let size = std::mem::size_of::<Self>();
            let mut bytes = [0u8; (Self::BITS / 8) as usize];
            for i in 0..size {
                bytes[i] = datagram
                    .next()
                    .unwrap_or(Err(Error::InternalError("not enough bytes for u8")))?;
            }
            let (rv, _) = Self::decode_from_bytes(&bytes)?;
            Ok(rv)
        }
    }

    impl FromDatagram for u16 {
        type Output = Self;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>,
        {
            let size = std::mem::size_of::<Self>();
            let mut bytes = [0u8; (Self::BITS / 8) as usize];
            for i in 0..size {
                bytes[i] = datagram
                    .next()
                    .unwrap_or(Err(Error::InternalError("not enough bytes for u16")))?;
            }
            let (rv, _) = Self::decode_from_bytes(&bytes)?;
            Ok(rv)
        }
    }

    impl FromDatagram for u32 {
        type Output = Self;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>,
        {
            let size = std::mem::size_of::<Self>();
            let mut bytes = [0u8; (Self::BITS / 8) as usize];
            for i in 0..size {
                bytes[i] = datagram
                    .next()
                    .unwrap_or(Err(Error::InternalError("not enough bytes for u32")))?;
            }
            let (rv, _) = Self::decode_from_bytes(&bytes)?;
            Ok(rv)
        }
    }

    impl FromDatagram for u64 {
        type Output = Self;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>,
        {
            let size = std::mem::size_of::<Self>();
            let mut bytes = [0u8; (Self::BITS / 8) as usize];
            for i in 0..size {
                bytes[i] = datagram
                    .next()
                    .unwrap_or(Err(Error::InternalError("not enough bytes for u64")))?;
            }
            let (rv, _) = Self::decode_from_bytes(&bytes)?;
            Ok(rv)
        }
    }

    impl FromDatagram for u128 {
        type Output = Self;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>,
        {
            let size = std::mem::size_of::<Self>();
            let mut bytes = [0u8; (Self::BITS / 8) as usize];
            for i in 0..size {
                bytes[i] = datagram
                    .next()
                    .unwrap_or(Err(Error::InternalError("not enough bytes for u128")))?;
            }
            let (rv, _) = Self::decode_from_bytes(&bytes)?;
            Ok(rv)
        }
    }

    impl FromDatagram for U160 {
        type Output = Self;
        fn from_datagram<T>(datagram: &mut T) -> error::Result<Self::Output>
        where
            T: Iterator<Item = error::Result<u8>>,
        {
            let size = (u32::BITS / 8 + u128::BITS / 8) as usize;
            let mut idx0 = 0u32;
            let mut idx1 = 0u128;
            for _ in 0..size {
                idx0 <<= 8;
                idx0 |= (idx1 >> 120) as u32;
                // mask to prevent overflow
                idx1 &= (1 << 120) - 1;
                idx1 <<= 8;
                idx1 |= u128::from(
                    datagram
                        .next()
                        .unwrap_or(Err(Error::InternalError("not enough bytes for u160")))?,
                );
            }
            Ok(Self { idx0, idx1 })
        }
    }
}

use self::prelude::*;

// TODO mark errors with more specificity

pub fn decode_var_int(data: &[u8]) -> error::Result<(u64, usize)> {
    if data.len() == 0 {
        return Err(Error::InternalError("missing first byte for varint"));
    }
    let n_shifts = usize::from(data[0] >> 6);
    if data.len() < n_shifts + 1 {
        return Err(Error::InternalError("not enough bytes for varint"));
    }
    let mut result = u64::from(data[0] & 0x3f);
    for i in 0..n_shifts {
        result <<= 8;
        result += u64::from(data[i + 1]);
    }
    Ok((result, n_shifts + 1))
}

pub fn decode_bytes(data: &[u8], length: usize) -> Result<(Vec<u8>, usize), Error> {
    if data.len() < length {
        return Err(Error::InternalError("not enough bytes to decode"));
    }
    let rv = data[..length].to_vec();
    Ok((rv, length))
}

pub fn var_int_with_bytes_from_stream<T>(stream: &mut T) -> error::Result<(u64, Vec<u8>)>
where
    T: Iterator<Item = error::Result<u8>>,
{
    let first_byte = stream
        .next()
        .unwrap_or(Err(Error::InternalError("missing first byte for varint")))?;
    let n_shifts = usize::from(first_byte >> 6);
    let mut bytes = Vec::<u8>::with_capacity(n_shifts + 1);
    bytes.push(first_byte);
    let mut result = u64::from(first_byte & 0x3f);
    for _ in 0..n_shifts {
        result <<= 8;
        let next_byte = stream
            .next()
            .unwrap_or(Err(Error::InternalError("not enough bytes for varint")))?;
        bytes.push(next_byte);
        result += u64::from(next_byte);
    }
    Ok((result, bytes))
}

pub fn var_int_from_stream<T>(stream: &mut T) -> Result<u64, Error>
where
    T: Iterator<Item = Result<u8, Error>>,
{
    let first_byte = stream
        .next()
        .unwrap_or(Err(Error::InternalError("missing first byte for varint")))?;
    let n_shifts = usize::from(first_byte >> 6);
    let mut result = u64::from(first_byte & 0x3f);
    for _ in 0..n_shifts {
        result <<= 8;
        result += u64::from(
            stream
                .next()
                .unwrap_or(Err(Error::InternalError("not enough bytes for varint")))?,
        );
    }
    Ok(result)
}

pub fn var_u32_from_stream<T>(stream: &mut T, n_bytes: usize) -> error::Result<u32>
where
    T: Iterator<Item = Result<u8, Error>>,
{
    let mut rv = 0u32;
    for _ in 0..n_bytes {
        rv <<= 8;
        rv |= u32::from(
            stream
                .next()
                .unwrap_or(Err(Error::InternalError("not enough bytes for var_u32")))?,
        );
    }
    Ok(rv)
}

pub fn var_u160_from_stream<T>(stream: &mut T, n_bytes: u8) -> error::Result<U160>
where
    T: Iterator<Item = error::Result<u8>>,
{
    let mut idx0 = 0u32;
    let mut idx1 = 0u128;
    for _ in 0..n_bytes {
        idx0 <<= 8;
        idx0 |= (idx1 >> 120) as u32;
        // mask to prevent overflow
        idx1 &= (1 << 120) - 1;
        idx1 <<= 8;
        idx1 |= u128::from(
            stream
                .next()
                .unwrap_or(Err(Error::InternalError("not enough bytes for var160")))?,
        );
    }
    Ok(U160 { idx0, idx1 })
}

pub fn var_bytes_from_stream<T>(stream: &mut T, n_bytes: usize) -> Result<Vec<u8>, Error>
where
    T: Iterator<Item = Result<u8, Error>>,
{
    // this needs to be dynamic to avoid malicious large allocations
    let mut rv = Vec::<u8>::new();
    for i in 0..n_bytes {
        let tp = stream
            .next()
            .unwrap_or(Err(Error::InternalError("not enough bytes for var_bytes")));
        if tp.is_err() {
            println!("failed at: {}", i);
            io::stdout().flush().unwrap();
        }
        // rv.push(stream.next().unwrap_or(Err(Error::InternalError))?);
        rv.push(tp?);
    }
    Ok(rv)
}

pub fn all_bytes_from_stream<T>(stream: &mut T) -> error::Result<Vec<u8>>
where
    T: Iterator<Item = Result<u8, Error>>,
{
    // TODO optimize collection here
    let mut rv = Vec::<u8>::new();
    while let Some(x) = stream.next() {
        rv.push(x?);
    }
    Ok(rv)
}

pub fn fixed_len_dcid_from_stream<T>(stream: &mut T) -> error::Result<U160>
where
    T: Iterator<Item = error::Result<u8>>,
{
    let dcid = u64::from_datagram(stream)?;
    let idx1 = u128::from(dcid);
    let idx0 = 0u32;
    Ok(U160 { idx0, idx1 })
}

pub fn calloc_box_buffer<T>(len: usize) -> Box<[T]> {
    if len == 0 {
        return Box::<[T]>::default();
    }
    let layout = Layout::array::<T>(len).unwrap();
    let ptr = unsafe { alloc::alloc_zeroed(layout) as *mut T };
    let slice_ptr = core::ptr::slice_from_raw_parts_mut(ptr, len);
    unsafe { Box::from_raw(slice_ptr) }
}

pub fn alloc_box_buffer<T>(len: usize) -> Box<[T]> {
    if len == 0 {
        return Box::<[T]>::default();
    }
    let layout = Layout::array::<T>(len).unwrap();
    let ptr = unsafe { alloc::alloc(layout) as *mut T };
    let slice_ptr = core::ptr::slice_from_raw_parts_mut(ptr, len);
    unsafe { Box::from_raw(slice_ptr) }
}

pub fn make_result_stream<'a>(
    bytes: &'a [u8],
) -> impl Iterator<Item = error::Result<u8>> + 'a + Clone {
    bytes.iter().map(|x| -> error::Result<u8> { Ok(x.clone()) })
}
