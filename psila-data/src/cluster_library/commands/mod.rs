mod attributes;
mod default_response;

use core::convert::TryFrom;

use crate::pack::Pack;
use crate::Error;

use attributes::{
    ReadAttributes, ReadAttributesResponse, ReportAttributes, WriteAttributes,
    WriteAttributesResponse,
};
use default_response::DefaultResponse;

extended_enum!(
    /// Cluster library general command identifiers
    GeneralCommandIdentifier, u8,
    ReadAttributes => 0x00,
    ReadAttributesResponse => 0x01,
    WriteAttributes => 0x02,
    WriteAttributesUndivided => 0x03,
    WriteAttributesResponse => 0x04,
    WriteAttributesNoResponse => 0x05,
    ConfigureReporting => 0x06,
    ConfigureReportingResponse => 0x07,
    ReadReportingConfiguration => 0x08,
    ReadReportingConfigurationResponse => 0x09,
    ReportAttributes => 0x0a,
    DefaultResponse => 0x0b,
    DiscoverAttributes => 0x0c,
    DiscoverAttributesResponse => 0x0d,
    ReadAttributesStructured => 0x0e,
    WriteAttributesStructured => 0x0f,
    WriteAttributesStructuredResponse => 0x10,
    DiscoverCommandsReceived => 0x11,
    DiscoverCommandsReceivedResponse => 0x12,
    DiscoverCommandsGenerated => 0x13,
    DiscoverCommandsGeneratedResponse => 0x14,
    DiscoverAttributesExtended => 0x15,
    DiscoverAttributesExtendedResponse => 0x16,
);

/// Cluster library general command
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    ReadAttributes(ReadAttributes),
    ReadAttributesResponse(ReadAttributesResponse),
    WriteAttributes(WriteAttributes),
    WriteAttributesUndivided(WriteAttributes),
    WriteAttributesResponse(WriteAttributesResponse),
    WriteAttributesNoResponse(WriteAttributes),
    ConfigureReporting,
    ConfigureReportingResponse,
    ReadReportingConfiguration,
    ReadReportingConfigurationResponse,
    ReportAttributes(ReportAttributes),
    DefaultResponse(DefaultResponse),
    DiscoverAttributes,
    DiscoverAttributesResponse,
    ReadAttributesStructured,
    WriteAttributesStructured,
    WriteAttributesStructuredResponse,
    DiscoverCommandsReceived,
    DiscoverCommandsReceivedResponse,
    DiscoverCommandsGenerated,
    DiscoverCommandsGeneratedResponse,
    DiscoverAttributesExtended,
    DiscoverAttributesExtendedResponse,
}

impl Command {
    pub fn pack(&self, data: &mut [u8]) -> Result<(usize, GeneralCommandIdentifier), Error> {
        match self {
            Command::ReadAttributes(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::ReadAttributes))
            }
            Command::ReadAttributesResponse(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::ReadAttributesResponse))
            }
            Command::WriteAttributes(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::WriteAttributes))
            }
            Command::WriteAttributesUndivided(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::WriteAttributesUndivided))
            }
            Command::WriteAttributesResponse(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::WriteAttributesResponse))
            }
            Command::WriteAttributesNoResponse(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::WriteAttributesNoResponse))
            }
            Command::ConfigureReporting => Ok((0, GeneralCommandIdentifier::ConfigureReporting)),
            Command::ConfigureReportingResponse => {
                Ok((0, GeneralCommandIdentifier::ConfigureReportingResponse))
            }
            Command::ReadReportingConfiguration => {
                Ok((0, GeneralCommandIdentifier::ReadReportingConfiguration))
            }
            Command::ReadReportingConfigurationResponse => Ok((
                0,
                GeneralCommandIdentifier::ReadReportingConfigurationResponse,
            )),
            Command::ReportAttributes(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::ReportAttributes))
            }
            Command::DefaultResponse(cmd) => {
                let used = cmd.pack(data)?;
                Ok((used, GeneralCommandIdentifier::DefaultResponse))
            }
            Command::DiscoverAttributes => Ok((0, GeneralCommandIdentifier::DiscoverAttributes)),
            Command::DiscoverAttributesResponse => {
                Ok((0, GeneralCommandIdentifier::DiscoverAttributesResponse))
            }
            Command::ReadAttributesStructured => {
                Ok((0, GeneralCommandIdentifier::ReadAttributesStructured))
            }
            Command::WriteAttributesStructured => {
                Ok((0, GeneralCommandIdentifier::WriteAttributesStructured))
            }
            Command::WriteAttributesStructuredResponse => Ok((
                0,
                GeneralCommandIdentifier::WriteAttributesStructuredResponse,
            )),
            Command::DiscoverCommandsReceived => {
                Ok((0, GeneralCommandIdentifier::DiscoverCommandsReceived))
            }
            Command::DiscoverCommandsReceivedResponse => Ok((
                0,
                GeneralCommandIdentifier::DiscoverCommandsReceivedResponse,
            )),
            Command::DiscoverCommandsGenerated => {
                Ok((0, GeneralCommandIdentifier::DiscoverCommandsGenerated))
            }
            Command::DiscoverCommandsGeneratedResponse => Ok((
                0,
                GeneralCommandIdentifier::DiscoverCommandsGeneratedResponse,
            )),
            Command::DiscoverAttributesExtended => {
                Ok((0, GeneralCommandIdentifier::DiscoverAttributesExtended))
            }
            Command::DiscoverAttributesExtendedResponse => Ok((
                0,
                GeneralCommandIdentifier::DiscoverAttributesExtendedResponse,
            )),
        }
    }

    pub fn unpack(data: &[u8], command: GeneralCommandIdentifier) -> Result<(Self, usize), Error> {
        match command {
            GeneralCommandIdentifier::ReadAttributes => {
                let (cmd, used) = ReadAttributes::unpack(&data)?;
                Ok((Command::ReadAttributes(cmd), used))
            }
            GeneralCommandIdentifier::ReadAttributesResponse => {
                let (cmd, used) = ReadAttributesResponse::unpack(&data)?;
                Ok((Command::ReadAttributesResponse(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributes => {
                let (cmd, used) = WriteAttributes::unpack(&data)?;
                Ok((Command::WriteAttributes(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributesUndivided => {
                let (cmd, used) = WriteAttributes::unpack(&data)?;
                Ok((Command::WriteAttributesUndivided(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributesResponse => {
                let (cmd, used) = WriteAttributesResponse::unpack(&data)?;
                Ok((Command::WriteAttributesResponse(cmd), used))
            }
            GeneralCommandIdentifier::WriteAttributesNoResponse => {
                let (cmd, used) = WriteAttributes::unpack(&data)?;
                Ok((Command::WriteAttributesNoResponse(cmd), used))
            }
            GeneralCommandIdentifier::ConfigureReporting => Ok((Command::ConfigureReporting, 0)),
            GeneralCommandIdentifier::ConfigureReportingResponse => {
                Ok((Command::ConfigureReportingResponse, 0))
            }
            GeneralCommandIdentifier::ReadReportingConfiguration => {
                Ok((Command::ReadReportingConfiguration, 0))
            }
            GeneralCommandIdentifier::ReadReportingConfigurationResponse => {
                Ok((Command::ReadReportingConfigurationResponse, 0))
            }
            GeneralCommandIdentifier::ReportAttributes => {
                let (cmd, used) = ReportAttributes::unpack(&data)?;
                Ok((Command::ReportAttributes(cmd), used))
            }
            GeneralCommandIdentifier::DefaultResponse => {
                let (cmd, used) = DefaultResponse::unpack(&data)?;
                Ok((Command::DefaultResponse(cmd), used))
            }
            GeneralCommandIdentifier::DiscoverAttributes => Ok((Command::DiscoverAttributes, 0)),
            GeneralCommandIdentifier::DiscoverAttributesResponse => {
                Ok((Command::DiscoverAttributesResponse, 0))
            }
            GeneralCommandIdentifier::ReadAttributesStructured => {
                Ok((Command::ReadAttributesStructured, 0))
            }
            GeneralCommandIdentifier::WriteAttributesStructured => {
                Ok((Command::WriteAttributesStructured, 0))
            }
            GeneralCommandIdentifier::WriteAttributesStructuredResponse => {
                Ok((Command::WriteAttributesStructuredResponse, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsReceived => {
                Ok((Command::DiscoverCommandsReceived, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsReceivedResponse => {
                Ok((Command::DiscoverCommandsReceivedResponse, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsGenerated => {
                Ok((Command::DiscoverCommandsGenerated, 0))
            }
            GeneralCommandIdentifier::DiscoverCommandsGeneratedResponse => {
                Ok((Command::DiscoverCommandsGeneratedResponse, 0))
            }
            GeneralCommandIdentifier::DiscoverAttributesExtended => {
                Ok((Command::DiscoverAttributesExtended, 0))
            }
            GeneralCommandIdentifier::DiscoverAttributesExtendedResponse => {
                Ok((Command::DiscoverAttributesExtendedResponse, 0))
            }
        }
    }
}
