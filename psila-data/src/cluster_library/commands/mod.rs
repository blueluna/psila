mod attributes;

use core::convert::TryFrom;

use crate::pack::Pack;
use crate::Error;

use attributes::{ReadAttributes, ReadAttributesResponse};

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

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    ReadAttributes(ReadAttributes),
    ReadAttributesResponse(ReadAttributesResponse),
    WriteAttributes,
    WriteAttributesUndivided,
    WriteAttributesResponse,
    WriteAttributesNoResponse,
    ConfigureReporting,
    ConfigureReportingResponse,
    ReadReportingConfiguration,
    ReadReportingConfigurationResponse,
    ReportAttributes,
    DefaultResponse,
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
    pub fn pack(&self, _data: &mut [u8]) -> Result<usize, Error> {
        unimplemented!();
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
            GeneralCommandIdentifier::WriteAttributes => Ok((Command::WriteAttributes, 0)),
            GeneralCommandIdentifier::WriteAttributesUndivided => {
                Ok((Command::WriteAttributesUndivided, 0))
            }
            GeneralCommandIdentifier::WriteAttributesResponse => {
                Ok((Command::WriteAttributesResponse, 0))
            }
            GeneralCommandIdentifier::WriteAttributesNoResponse => {
                Ok((Command::WriteAttributesNoResponse, 0))
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
            GeneralCommandIdentifier::ReportAttributes => Ok((Command::ReportAttributes, 0)),
            GeneralCommandIdentifier::DefaultResponse => Ok((Command::DefaultResponse, 0)),
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
