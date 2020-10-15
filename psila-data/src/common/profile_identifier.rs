//! Common profile identifiers

use crate::Error;
use core::convert::TryFrom;

extended_enum!(
    /// Profile identifiers
    ProfileIdentifier, u16,
    /// Device profile
    DeviceProfile => 0x0000,
    /// Industrial and plant monitoring profile
    IndustrialPlantMonitoring => 0x0101,
    /// Test profile
    Test1 => 0x0103,
    /// Home automation profile
    HomeAutomation => 0x0104,
    /// Commercial building automation profile
    CommercialBuildingAutomation => 0x0105,
    /// Wireless sensor network profile
    WirelessSensorNetwork => 0x0106,
    /// Telecom automation profile
    TelecomAutomation => 0x0107,
    /// Healthcare profile
    HealthCare => 0x0108,
    /// Smart energy profile
    SmartEnergy => 0x0109,
    /// Retail services profile
    RetailServices => 0x010a,
    /// Test profile
    Test2 => 0x7f01,
    /// Gateway profile
    Gateway => 0x7f02,
    /// Green power profile
    GreenPower => 0xa1e0,
    /// Light link profile
    LighLink => 0xc05e,
    /// Wildcard profile
    Wildcard => 0xffff,
);
