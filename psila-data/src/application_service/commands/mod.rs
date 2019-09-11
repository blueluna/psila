mod device;
mod key;
mod key_establishment;
pub mod transport_key;
mod tunnel;

use core::convert::TryFrom;

use crate::error::Error;
use crate::pack::Pack;

pub use device::{RemoveDevice, UpdateDevice};
pub use key::{ConfirmKey, RequestKey, SwitchKey, VerifyKey};
pub use key_establishment::KeyEstablishment;
pub use transport_key::TransportKey;
pub use tunnel::Tunnel;

extended_enum!(
    // 4.4.9 Command Frames
    /// Application services command identifiers
    CommandIdentifier, u8,
    /// Key establishment stage one command identifier
    SymmetricKeyKeyEstablishment1 => 0x01,
    /// Key establishment stage two command identifier
    SymmetricKeyKeyEstablishment2 => 0x02,
    /// Key establishment stage three command identifier
    SymmetricKeyKeyEstablishment3 => 0x03,
    /// Key establishment stage four command identifier
    SymmetricKeyKeyEstablishment4 => 0x04,
    /// Transport-key command identifier
    TransportKey => 0x05,
    /// Update device command identifier
    UpdateDevice => 0x06,
    /// Remove device command identifier
    RemoveDevice => 0x07,
    /// Request key command identifier
    RequestKey => 0x08,
    /// Switch key command identifier
    SwitchKey => 0x09,
    /// Entity authentication challange initiation command identifier
    EntityAuthenticationInitiatorChallange => 0x0a,
    /// Entity authentication challange response command identifier
    EntityAuthenticationResponderChallange => 0x0b,
    /// Entity authentication ? command identifier
    EntityAuthenticationInitiatorMacAndData => 0x0c,
    /// Entity authentication ? command identifier
    EntityAuthenticationResponderMacAndData => 0x0d,
    /// Tunnel command identifier
    /// 
    /// Tunneling of application service frames
    Tunnel => 0x0e,
    /// Verify link-key command identifier
    VerifyKey => 0x0f,
    /// Confirm link-key command identifier
    ConfirmKey => 0x10,
);

/// Application services commands
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// Key establishment stage one command
    SymmetricKeyKeyEstablishment1(KeyEstablishment),
    /// Key establishment stage two command
    SymmetricKeyKeyEstablishment2(KeyEstablishment),
    /// Key establishment stage three command
    SymmetricKeyKeyEstablishment3(KeyEstablishment),
    /// Key establishment stage four command
    SymmetricKeyKeyEstablishment4(KeyEstablishment),
    /// Transport-key command
    TransportKey(TransportKey),
    /// Update device command
    UpdateDevice(UpdateDevice),
    /// Remove device command
    RemoveDevice(RemoveDevice),
    /// Request key command
    RequestKey(RequestKey),
    /// Switch key command
    SwitchKey(SwitchKey),
    /// Entity authentication command
    ///
    /// NOT IMPLEMENTED
    EntityAuthenticationInitiatorChallange,
    /// Entity authentication command
    ///
    /// NOT IMPLEMENTED
    EntityAuthenticationResponderChallange,
    /// Entity authentication command
    ///
    /// NOT IMPLEMENTED
    EntityAuthenticationInitiatorMacAndData,
    /// Entity authentication command
    ///
    /// NOT IMPLEMENTED
    EntityAuthenticationResponderMacAndData,
    /// Tunnel command
    ///
    /// NOT FULLY IMPLEMENTED
    Tunnel(Tunnel),
    /// Verify link-key command
    VerifyKey(VerifyKey),
    /// Confirm link-key command
    ConfirmKey(ConfirmKey),
}

impl Pack<Command, Error> for Command {
    fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let command_identifier = CommandIdentifier::try_from(data[0])?;
        let (cmd, used) = match command_identifier {
            CommandIdentifier::SymmetricKeyKeyEstablishment1 => {
                let (ke, used) = KeyEstablishment::unpack(&data[1..])?;
                (Command::SymmetricKeyKeyEstablishment1(ke), used)
            }
            CommandIdentifier::SymmetricKeyKeyEstablishment2 => {
                let (ke, used) = KeyEstablishment::unpack(&data[1..])?;
                (Command::SymmetricKeyKeyEstablishment2(ke), used)
            }
            CommandIdentifier::SymmetricKeyKeyEstablishment3 => {
                let (ke, used) = KeyEstablishment::unpack(&data[1..])?;
                (Command::SymmetricKeyKeyEstablishment3(ke), used)
            }
            CommandIdentifier::SymmetricKeyKeyEstablishment4 => {
                let (ke, used) = KeyEstablishment::unpack(&data[1..])?;
                (Command::SymmetricKeyKeyEstablishment4(ke), used)
            }
            CommandIdentifier::TransportKey => {
                let (tk, used) = TransportKey::unpack(&data[1..])?;
                (Command::TransportKey(tk), used)
            }
            CommandIdentifier::UpdateDevice => {
                let (ud, used) = UpdateDevice::unpack(&data[1..])?;
                (Command::UpdateDevice(ud), used)
            }
            CommandIdentifier::RemoveDevice => {
                let (rd, used) = RemoveDevice::unpack(&data[1..])?;
                (Command::RemoveDevice(rd), used)
            }
            CommandIdentifier::RequestKey => {
                let (rk, used) = RequestKey::unpack(&data[1..])?;
                (Command::RequestKey(rk), used)
            }
            CommandIdentifier::SwitchKey => {
                let (sk, used) = SwitchKey::unpack(&data[1..])?;
                (Command::SwitchKey(sk), used)
            }
            CommandIdentifier::EntityAuthenticationInitiatorChallange => {
                (Command::EntityAuthenticationInitiatorChallange, 0)
            }
            CommandIdentifier::EntityAuthenticationResponderChallange => {
                (Command::EntityAuthenticationResponderChallange, 0)
            }
            CommandIdentifier::EntityAuthenticationInitiatorMacAndData => {
                (Command::EntityAuthenticationInitiatorMacAndData, 0)
            }
            CommandIdentifier::EntityAuthenticationResponderMacAndData => {
                (Command::EntityAuthenticationResponderMacAndData, 0)
            }
            CommandIdentifier::Tunnel => {
                let (t, used) = Tunnel::unpack(&data[1..])?;
                (Command::Tunnel(t), used)
            }
            CommandIdentifier::VerifyKey => {
                let (vk, used) = VerifyKey::unpack(&data[1..])?;
                (Command::VerifyKey(vk), used)
            }
            CommandIdentifier::ConfirmKey => {
                let (ck, used) = ConfirmKey::unpack(&data[1..])?;
                (Command::ConfirmKey(ck), used)
            }
        };
        Ok((cmd, 1 + used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_transport_key_command() {
        let data = [
            0x05, 0x01, 0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48,
            0x00, 0x40, 0x64, 0x08, 0x00, 0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00, 0x38,
            0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00,
        ];
        let (cmd, used) = Command::unpack(&data).unwrap();
        assert_eq!(used, 35);
        match cmd {
            Command::TransportKey(tk) => match tk {
                TransportKey::StandardNetworkKey(k) => {
                    assert_eq!(
                        k.key,
                        [
                            0x00, 0x2c, 0x6c, 0x08, 0xd0, 0xf4, 0xf4, 0x2c, 0xd8, 0x40, 0xd8, 0x48,
                            0x00, 0x40, 0x64, 0x08
                        ]
                    );
                    assert_eq!(k.sequence, 0);
                    assert_eq!(
                        k.destination,
                        [0x85, 0xae, 0x21, 0xfe, 0xff, 0x6f, 0x0d, 0x00]
                    );
                    assert_eq!(k.source, [0x38, 0x2e, 0x03, 0xff, 0xff, 0x2e, 0x21, 0x00]);
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}
