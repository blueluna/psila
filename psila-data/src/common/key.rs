use core::convert::TryFrom;
use std::fmt;
use std::str;

use crate::pack::PackFixed;
use crate::Error;

extended_enum!(
    // 4.4.3 Transport-Key Services
    // Table 4.14 KeyType Parameter of the Transport-Key Primitive
    KeyType, u8,
    TrustCenterMasterKey => 0x00,
    StandardNetworkKey => 0x01,
    ApplicationMasterKey => 0x02,
    ApplicationLinkKey => 0x03,
    UniqueTrustCenterLinkKey => 0x04,
    HighSecurityNetworkKey => 0x05,
    );

/// Key length
pub const KEY_SIZE: usize = 16;

/// Key
///
/// 128-bit key used for security operations
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Key([u8; KEY_SIZE]);

impl PackFixed<Key, Error> for Key {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != KEY_SIZE {
            return Err(Error::NotEnoughSpace);
        }
        data.clone_from_slice(&self.0);
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != KEY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut key = Key([0; KEY_SIZE]);
        key.0.clone_from_slice(&data);
        Ok(key)
    }
}

impl PartialEq<[u8; KEY_SIZE]> for Key {
    fn eq(&self, other: &[u8; KEY_SIZE]) -> bool {
        self.0 == *other
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5], self.0[6], self.0[7],
            self.0[8], self.0[9], self.0[10], self.0[11],
            self.0[12], self.0[13], self.0[14], self.0[15])
    }
}

impl From<[u8; KEY_SIZE]> for Key {
    fn from(value: [u8; KEY_SIZE]) -> Self {
        Key(value)
    }
}

impl From<Key> for [u8; KEY_SIZE] {
    fn from(value: Key) -> Self {
        value.0
    }
}

impl str::FromStr for Key {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != KEY_SIZE * 2 {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 0;
        let mut key = [0u8; KEY_SIZE];
        for byte in key.iter_mut().take(KEY_SIZE) {
            *byte = match u8::from_str_radix(&s[offset..offset + 2], 16) {
                Ok(v) => v,
                Err(_) => return Err(Error::InvalidValue),
            };
            offset += 2;
        }
        Ok(Key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn key() {
        let a = Key::unpack(&[
            0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
            0x30, 0x39,
        ])
        .unwrap();
        assert_eq!(
            a,
            [
                0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
                0x30, 0x39
            ]
        );
        assert_eq!(format!("{}", a), "5a6967426565416c6c69616e63653039");

        let a = Key::from([
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
            0x1e, 0x0f,
        ]);
        assert_eq!(
            a,
            [
                0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
                0x1e, 0x0f
            ]
        );
        assert_eq!(format!("{}", a), "f0e1d2c3b4a5968778695a4b3c2d1e0f");

        let a = Key::from_str("5a6967426565416c6c69616e63653039").unwrap();
        assert_eq!(
            a,
            [
                0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65,
                0x30, 0x39
            ]
        );
    }
}
