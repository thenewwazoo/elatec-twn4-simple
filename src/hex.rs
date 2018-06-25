#![allow(dead_code)]

#[derive(Debug)]
pub enum Error {
    BadChar,
    BufferTooSmall,
}

pub fn half_byte_to_hex(i: u8) -> u8 {
    match i & 0xF {
        0xA => 'A' as u8,
        0xB => 'B' as u8,
        0xC => 'C' as u8,
        0xD => 'D' as u8,
        0xE => 'E' as u8,
        0xF => 'F' as u8,
        _ => '0' as u8 + i,
    }
}

pub fn hex_to_half_byte(c: u8) -> Result<u8, Error> {
    if c >= '0' as u8 && c <= '9' as u8 {
        Ok(c - '0' as u8)
    } else if c >= 'A' as u8 && c <= 'F' as u8 {
        Ok(c - 'A' as u8 + 0xA)
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
