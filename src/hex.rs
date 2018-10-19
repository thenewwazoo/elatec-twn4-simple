//! Helper functions to convert between bytes and hex-encoded characters
#![allow(dead_code)]

#[derive(Debug)]
/// Errors arising from conversion
pub enum Error {
    /// Input char not in 0-9, A-F
    BadChar,
    /// Output buffer too small to contain results of conversion
    BufferTooSmall,
}

/// Convert a nibble to a hex char
pub fn half_byte_to_hex(i: u8) -> u8 {
    let h = i & 0xF;
    if h < 0xA {
        b'0' + h
    } else {
        b'A' + (h - 0xA)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn half_byte_to_hex_test() {
        assert_eq!(half_byte_to_hex(0xF), b'F');
        assert_eq!(half_byte_to_hex(0x0), b'0');
        assert_eq!(half_byte_to_hex(0x9), b'9');
        assert_eq!(half_byte_to_hex(0xA), b'A');
    }
}

/// Convert a hex character to a nibble
pub fn hex_to_half_byte(c: u8) -> Result<u8, Error> {
    if c >= b'0' && c <= b'9' {
        Ok(c - b'0')
    } else if c >= b'A' && c <= b'F' {
        Ok(c - b'A' + 0xA)
    } else {
        Err(Error::BadChar)
    }
}

/// Convert two hex characters to a byte
pub fn hex_byte_to_byte(h: u8, l: u8) -> Result<u8, Error> {
    Ok(hex_to_half_byte(h)? << 4 | hex_to_half_byte(l)? & 0xF)
}

/// Convert a slice of bytes to a slice of hex characters
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

/// Convert a slice of hex characters to bytes
pub fn hex_to_bytes(i: &[u8], o: &mut [u8]) -> Result<(), Error> {
    if i.len() / 2 > o.len() {
        return Err(Error::BufferTooSmall);
    }

    for (i, o) in i.chunks(2).zip(o.iter_mut()) {
        *o = hex_byte_to_byte(i[0], i[1])?;
    }

    Ok(())
}
