//! # Network commands
//!

mod end_device;
mod leave;
mod link_status;
mod network_report;
mod network_status;
mod network_update;
mod rejoin;
mod route_record;
pub mod route_reply;
pub mod route_request;

use crate::pack::Pack;
use crate::Error;

pub use end_device::{EndDeviceTimeoutRequest, EndDeviceTimeoutResponse};
pub use leave::Leave;
pub use link_status::{LinkStatus, LinkStatusEntry};
pub use network_report::NetworkReport;
pub use network_status::{NetworkStatus, Status};
pub use network_update::NetworkUpdate;
pub use rejoin::{RejoinRequest, RejoinResponse};
pub use route_record::RouteRecord;
pub use route_reply::RouteReply;
pub use route_request::{AddressType, ManyToOne, RouteRequest};

/// Network Commands
///
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// Route request
    RouteRequest(RouteRequest),
    /// Route reply
    RouteReply(RouteReply),
    /// Network status
    NetworkStatus(NetworkStatus),
    /// Leave
    Leave(Leave),
    /// Route record
    RouteRecord(RouteRecord),
    /// Rejoin request
    RejoinRequest(RejoinRequest),
    /// Rejoin response
    RejoinResponse(RejoinResponse),
    /// Link status
    LinkStatus(LinkStatus),
    /// Network report
    NetworkReport(NetworkReport),
    /// Network update
    NetworkUpdate(NetworkUpdate),
    /// End device timeout request
    EndDeviceTimeoutRequest(EndDeviceTimeoutRequest),
    /// End device timeout response
    EndDeviceTimeoutResponse(EndDeviceTimeoutResponse),
}

impl Pack<Command, Error> for Command {
    fn pack(&self, data: &mut [u8]) -> Result<usize, Error> {
        let used = match self {
            Command::RouteRequest(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x01;
                used + 1
            }
            Command::RouteReply(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x02;
                used + 1
            }
            Command::NetworkStatus(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x03;
                used + 1
            }
            Command::Leave(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x04;
                used + 1
            }
            Command::RouteRecord(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x05;
                used + 1
            }
            Command::RejoinRequest(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x06;
                used + 1
            }
            Command::RejoinResponse(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x07;
                used + 1
            }
            Command::LinkStatus(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x08;
                used + 1
            }
            Command::NetworkReport(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x09;
                used + 1
            }
            Command::NetworkUpdate(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x0a;
                used + 1
            }
            Command::EndDeviceTimeoutRequest(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x0b;
                used + 1
            }
            Command::EndDeviceTimeoutResponse(cmd) => {
                let used = cmd.pack(&mut data[1..])?;
                data[0] = 0x0c;
                used + 1
            }
        };
        Ok(used)
    }

    fn unpack(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::WrongNumberOfBytes);
        }
        match data[0] {
            0x01 => {
                let (cmd, used) = RouteRequest::unpack(&data[1..])?;
                Ok((Command::RouteRequest(cmd), 1 + used))
            }
            0x02 => {
                let (cmd, used) = RouteReply::unpack(&data[1..])?;
                Ok((Command::RouteReply(cmd), 1 + used))
            }
            0x03 => {
                let (cmd, used) = NetworkStatus::unpack(&data[1..])?;
                Ok((Command::NetworkStatus(cmd), 1 + used))
            }
            0x04 => {
                let (cmd, used) = Leave::unpack(&data[1..])?;
                Ok((Command::Leave(cmd), 1 + used))
            }
            0x05 => {
                let (cmd, used) = RouteRecord::unpack(&data[1..])?;
                Ok((Command::RouteRecord(cmd), 1 + used))
            }
            0x06 => {
                let (cmd, used) = RejoinRequest::unpack(&data[1..])?;
                Ok((Command::RejoinRequest(cmd), 1 + used))
            }
            0x07 => {
                let (cmd, used) = RejoinResponse::unpack(&data[1..])?;
                Ok((Command::RejoinResponse(cmd), 1 + used))
            }
            0x08 => {
                let (cmd, used) = LinkStatus::unpack(&data[1..])?;
                Ok((Command::LinkStatus(cmd), 1 + used))
            }
            0x09 => {
                let (cmd, used) = NetworkReport::unpack(&data[1..])?;
                Ok((Command::NetworkReport(cmd), 1 + used))
            }
            0x0a => {
                let (cmd, used) = NetworkUpdate::unpack(&data[1..])?;
                Ok((Command::NetworkUpdate(cmd), 1 + used))
            }
            0x0b => {
                let (cmd, used) = EndDeviceTimeoutRequest::unpack(&data[1..])?;
                Ok((Command::EndDeviceTimeoutRequest(cmd), 1 + used))
            }
            0x0c => {
                let (cmd, used) = EndDeviceTimeoutResponse::unpack(&data[1..])?;
                Ok((Command::EndDeviceTimeoutResponse(cmd), 1 + used))
            }
            _ => Err(Error::UnknownNetworkCommand),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_link_status_command() {
        let data = [0x08, 0x60];
        let (cmd, used) = Command::unpack(&data).unwrap();
        assert_eq!(used, 2);
        match cmd {
            Command::LinkStatus(ls) => {
                assert_eq!(ls.first_frame, true);
                assert_eq!(ls.last_frame, true);
                assert_eq!(ls.len(), 0);
                assert_eq!(ls.is_empty(), true);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unpack_route_request_command() {
        let data = [0x01, 0x08, 0xef, 0xfc, 0xff, 0x00];
        let (cmd, used) = Command::unpack(&data).unwrap();
        assert_eq!(used, 6);
        match cmd {
            Command::RouteRequest(rr) => {
                assert_eq!(rr.options.many_to_one, ManyToOne::RouteRequestTableSupport);
                assert_eq!(rr.options.destination_ieee_address, false);
                assert_eq!(rr.options.multicast, false);
                assert_eq!(rr.identifier, 0xef);
                assert_eq!(rr.path_cost, 0x00);
            }
            _ => unreachable!(),
        }
    }
}
