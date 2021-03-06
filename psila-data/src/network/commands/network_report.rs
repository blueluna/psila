use core::convert::TryFrom;

use crate::common::address::{
    ExtendedPanIdentifier, PanIdentifier, EXTENDED_ADDRESS_SIZE, SHORT_ADDRESS_SIZE,
};
use crate::error::Error;
use crate::pack::{Pack, PackFixed};

extended_enum!(
    CommandIdentifier, u8,
    PanIdentifierConflict => 0x00,
);

const NUMBER_OF_RECORDS_MASK: u8 = 0b0001_1111;
const COMMAND_IDENTIFIER_MASK: u8 = 0b1110_0000;

/// Network report
///
/// There is something to report about the network.
///
/// This command actually has the potential to mean other things, but only one
/// command identifier is standardised as of yet.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkReport {
    /// Command identifiers
    pub command_identifier: CommandIdentifier,
    /// Device extended PAN identifier
    pub extended_pan_identifier: ExtendedPanIdentifier,
    /// Device PAN identifier
    pub pan_identifier: PanIdentifier,
}

impl Pack<NetworkReport, Error> for NetworkReport {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        data[0] = (self.command_identifier as u8) << 5 | 0x01;
        let mut offset = 1;
        self.extended_pan_identifier
            .pack(&mut data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        self.pan_identifier
            .pack(&mut data[offset..offset + SHORT_ADDRESS_SIZE])?;
        offset += SHORT_ADDRESS_SIZE;
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 11 {
            return Err(Error::WrongNumberOfBytes);
        }
        let num_records = (data[0] & NUMBER_OF_RECORDS_MASK) as usize;
        if num_records != 1 {
            return Err(Error::InvalidValue);
        }
        let command_identifier =
            CommandIdentifier::try_from((data[0] & COMMAND_IDENTIFIER_MASK) >> 5)?;
        let mut offset = 1;
        let extended_pan_identifier =
            ExtendedPanIdentifier::unpack(&data[offset..offset + EXTENDED_ADDRESS_SIZE])?;
        offset += EXTENDED_ADDRESS_SIZE;
        let pan_identifier = PanIdentifier::unpack(&data[offset..offset + SHORT_ADDRESS_SIZE])?;
        offset += SHORT_ADDRESS_SIZE;
        Ok((
            Self {
                command_identifier,
                extended_pan_identifier,
                pan_identifier,
            },
            offset,
        ))
    }
}
