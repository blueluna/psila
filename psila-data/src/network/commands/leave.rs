use crate::error::Error;
use crate::pack::Pack;

const REJOIN: u8 = 0b0010_0000;
const REQUEST: u8 = 0b0100_0000;
const REMOVE_CHILDREN: u8 = 0b1000_0000;

/// Leave request
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Leave {
    /// Will rejoin
    pub rejoin: bool,
    /// Request a device to leave the network if true.
    /// If false the sending device intends to leave the network
    pub request: bool,
    /// The children of the device will be removed if true
    pub remove_children: bool,
}

impl Pack<Leave, Error> for Leave {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = if self.rejoin { REJOIN } else { 0 }
            | if self.request { REQUEST } else { 0 }
            | if self.remove_children {
                REMOVE_CHILDREN
            } else {
                0
            };
        Ok(1)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let rejoin = (data[0] & REJOIN) == REJOIN;
        let request = (data[0] & REQUEST) == REQUEST;
        let remove_children = (data[0] & REMOVE_CHILDREN) == REMOVE_CHILDREN;

        Ok((
            Leave {
                rejoin,
                request,
                remove_children,
            },
            1,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_leave() {
        let data = [0x00];
        let (leave, used) = Leave::unpack(&data).unwrap();
        assert_eq!(used, 1);
        assert_eq!(
            leave,
            Leave {
                rejoin: false,
                request: false,
                remove_children: false
            }
        );

        let data = [0x20];
        let (leave, used) = Leave::unpack(&data).unwrap();
        assert_eq!(used, 1);
        assert_eq!(
            leave,
            Leave {
                rejoin: true,
                request: false,
                remove_children: false
            }
        );

        let data = [0x40];
        let (leave, used) = Leave::unpack(&data).unwrap();
        assert_eq!(used, 1);
        assert_eq!(
            leave,
            Leave {
                rejoin: false,
                request: true,
                remove_children: false
            }
        );

        let data = [0x80];
        let (leave, used) = Leave::unpack(&data).unwrap();
        assert_eq!(used, 1);
        assert_eq!(
            leave,
            Leave {
                rejoin: false,
                request: false,
                remove_children: true
            }
        );

        let data = [0xff];
        let (leave, used) = Leave::unpack(&data).unwrap();
        assert_eq!(used, 1);
        assert_eq!(
            leave,
            Leave {
                rejoin: true,
                request: true,
                remove_children: true
            }
        );
    }

    #[test]
    fn pack_leave() {
        let mut data = [0x00];
        let leave = Leave {
            rejoin: false,
            request: false,
            remove_children: false,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0x00);

        let leave = Leave {
            rejoin: true,
            request: false,
            remove_children: false,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0x20);

        let leave = Leave {
            rejoin: false,
            request: true,
            remove_children: false,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0x40);

        let leave = Leave {
            rejoin: false,
            request: false,
            remove_children: true,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0x80);

        let leave = Leave {
            rejoin: true,
            request: true,
            remove_children: false,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0x60);

        let leave = Leave {
            rejoin: true,
            request: false,
            remove_children: true,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0xa0);

        let leave = Leave {
            rejoin: false,
            request: true,
            remove_children: true,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0xc0);

        let leave = Leave {
            rejoin: true,
            request: true,
            remove_children: true,
        };
        let used = leave.pack(&mut data[..]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(data[0], 0xe0);
    }
}
