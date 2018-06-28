#![allow(dead_code)]

#[derive(Debug)]
pub enum Error {
    BadChar,
    BufferTooSmall,
}

pub fn half_byte_to_hex(i: u8) -> u8 {
    match i & 0xF {
        0xA => b'A',
        0xB => b'B',
        0xC => b'C',
        0xD => b'D',
        0xE => b'E',
        0xF => b'F',
        _ => b'0' + i,
    }
}

pub fn hex_to_half_byte(c: u8) -> Result<u8, Error> {
    if c >= b'0' && c <= b'9' {
        Ok(c - b'0')
    } else if c >= b'A' && c <= b'F' {
        Ok(c - b'A' + 0xA)
    } else {
        Err(Error::BadChar)
    }
}

pub fn hex_byte_to_byte(h: u8, l: u8) -> Result<u8, Error> {
    Ok(hex_to_half_byte(h)? << 4 | hex_to_half_byte(l)? & 0xF)
}

pub fn bytes_to_hex(i: &[u8], o: &mut [u8]) -> Result<(), Error> {
    if i.len() * 2 > o.len() {
        return Err(Error::BufferTooSmall);
    }

    for (i, o) in i.iter().zip(o.chunks_mut(2)) {
        o[0] = half_byte_to_hex(i >> 4);
        o[1] = half_byte_to_hex(i & 0xF);
    }
    Ok(())
}

pub fn hex_to_bytes(i: &[u8], o: &mut [u8]) -> Result<(), Error> {
    if i.len() / 2 > o.len() {
        return Err(Error::BufferTooSmall);
    }

    for (i, o) in i.chunks(2).zip(o.iter_mut()) {
        *o = hex_byte_to_byte(i[0], i[1])?;
    }

    Ok(())
}
