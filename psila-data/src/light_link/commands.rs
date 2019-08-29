use core::convert::TryFrom;

use crate::error::Error;

extended_enum!(
    // ZLL, 7.1.2.2 Commands received
    RequestCommand, u8,
    ScanRequest => 0x00,
    ScanResponse => 0x01,
    DeviceInformationRequest => 0x02,
    DeviceInformationResponse => 0x03,
    IdentifyRequest => 0x06,
    FactoryResetRequest => 0x07,
    NetworkStartRequest => 0x10,
    NetworkStartResponse => 0x11,
    NetworkJoinRouterRequest => 0x12,
    NetworkJoinRouterResponse => 0x13,
    NetworkJoinEndDeviceRequest => 0x14,
    NetworkJoinEndDeviceResponse => 0x15,
    NetworkUpdateRequest => 0x16,
    EndpointInformation => 0x40,
    GetGroupIdentifiers => 0x41, // Both request and response
    GetEndpointList => 0x42, // Both request and response
    );
