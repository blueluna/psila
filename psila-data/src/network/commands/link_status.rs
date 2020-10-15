use core::default::Default;

use crate::error::Error;
use crate::pack::{Pack, PackFixed};
use crate::NetworkAddress;

const INCOMING_COST_MASK: u8 = 0b0000_0111;
const OUTGOING_COST_MASK: u8 = 0b0111_0000;
const LINK_STATUS_ENTRY_SIZE: usize = 3;

/// Link status entry
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct LinkStatusEntry {
    /// Device address
    pub address: NetworkAddress,
    /// Incoming link cost
    pub incoming_cost: u8,
    /// Outgoing link cost
    pub outgoing_cost: u8,
}

impl PackFixed<LinkStatusEntry, Error> for LinkStatusEntry {
    fn pack(&self, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != LINK_STATUS_ENTRY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        assert!(self.incoming_cost < 16);
        assert!(self.outgoing_cost < 16);
        self.address.pack(&mut data[0..2])?;
        data[2] = self.incoming_cost | self.outgoing_cost << 4;
        Ok(())
    }

    fn unpack(data: &[u8]) -> Result<Self, Error> {
        if data.len() != LINK_STATUS_ENTRY_SIZE {
            return Err(Error::WrongNumberOfBytes);
        }
        let address = NetworkAddress::unpack(&data[0..2])?;
        let incoming_cost = data[2] & INCOMING_COST_MASK;
        let outgoing_cost = (data[2] & OUTGOING_COST_MASK) >> 4;
        Ok(LinkStatusEntry {
            address,
            incoming_cost,
            outgoing_cost,
        })
    }
}

impl Default for LinkStatusEntry {
    fn default() -> Self {
        Self {
            address: NetworkAddress::default(),
            incoming_cost: 0,
            outgoing_cost: 0,
        }
    }
}

const NUMBER_OF_ENTRIES_MASK: u8 = 0b0001_1111;
const FIRST_FRAME: u8 = 0b0010_0000;
const LAST_FRAME: u8 = 0b0100_0000;

/// Link status message
#[derive(Clone, Debug, PartialEq)]
pub struct LinkStatus {
    /// This is the first frame
    pub first_frame: bool,
    /// This is the last frame
    pub last_frame: bool,
    /// Number of entries
    num_entries: u8,
    /// Link status entries
    entries: [LinkStatusEntry; 32],
}

impl LinkStatus {
    /// No link status entries
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }
    /// Number of link status entries
    pub fn len(&self) -> usize {
        self.num_entries as usize
    }
    /// Link status entries
    pub fn entries(&self) -> &[LinkStatusEntry] {
        &self.entries[..self.num_entries as usize]
    }
    /// Create link status message from entries
    pub fn new(devices: &[LinkStatusEntry]) -> Self {
        let mut entries = [LinkStatusEntry::default(); 32];
        let num_entries = devices.len();
        let num_entries = if num_entries > 32 { 32 } else { num_entries };
        entries[..num_entries].copy_from_slice(&devices[..num_entries]);
        let num_entries = num_entries as u8;
        Self {
            first_frame: false,
            last_frame: false,
            num_entries,
            entries,
        }
    }
}

impl Pack<LinkStatus, Error> for LinkStatus {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        assert!(self.num_entries <= 32);
        if data.len() < (1 + ((self.num_entries as usize) * LINK_STATUS_ENTRY_SIZE)) {
            return Err(Error::WrongNumberOfBytes);
        }
        let mut offset = 1;
        data[0] = self.num_entries
            | if self.first_frame { FIRST_FRAME } else { 0 }
            | if self.last_frame { LAST_FRAME } else { 0 };
        for entry in self.entries[..self.num_entries as usize].iter() {
            entry.pack(&mut data[offset..offset + LINK_STATUS_ENTRY_SIZE])?;
            offset += LINK_STATUS_ENTRY_SIZE;
        }
        Ok(offset)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        let num_entries = data[0] & NUMBER_OF_ENTRIES_MASK;
        if data.len() < (1 + ((num_entries as usize) * LINK_STATUS_ENTRY_SIZE)) {
            return Err(Error::WrongNumberOfBytes);
        }
        let first_frame = (data[0] & FIRST_FRAME) == FIRST_FRAME;
        let last_frame = (data[0] & LAST_FRAME) == LAST_FRAME;
        let mut offset = 1;
        let mut entries = [LinkStatusEntry::default(); 32];
        for entry in entries[..num_entries as usize].iter_mut() {
            *entry = LinkStatusEntry::unpack(&data[offset..offset + LINK_STATUS_ENTRY_SIZE])?;
            offset += LINK_STATUS_ENTRY_SIZE;
        }

        Ok((
            LinkStatus {
                first_frame,
                last_frame,
                num_entries,
                entries,
            },
            offset,
        ))
    }
}
