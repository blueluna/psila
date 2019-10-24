//! Common profile identifiers

use crate::Error;
use core::convert::TryFrom;

extended_enum!(
    ProfileIdentifier, u16,
    DeviceProfile => 0x0000,
    IndustrialPlantMonitoring => 0x0101,
    Test1 => 0x0103,
    HomeAutomation => 0x0104,
    CommercialBuildingAutomation => 0x0105,
    WirelessSensorNetwork => 0x0106,
    TelecomAutomation => 0x0107,
    HealthCare => 0x0108,
    SmartEnergy => 0x0109,
    RetailServices => 0x010a,
    Test2 => 0x7f01,
    Gateway => 0x7f02,
    GreenPower => 0xa1e0,
    LighLink => 0xc05e,
    Wildcard => 0xffff,
);
