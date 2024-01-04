use crate::cluster_library::Cluster;
use core::convert::TryFrom;
use psila_data::cluster_library::{basic::*, AttributeValue, ClusterLibraryStatus};
use psila_data::common::types::CharacterString;

pub trait BasicCluster {
    fn library_version(&self, _endpoint: u8) -> Result<u8, ClusterLibraryStatus>;
    fn application_version(&self, _endpoint: u8) -> Result<u8, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn stack_version(&self, _endpoint: u8) -> Result<u8, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn hardware_version(&self, _endpoint: u8) -> Result<u8, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn manufacturer_name(&self, _endpoint: u8) -> Result<CharacterString, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    } // 32 bytes
    fn model_identifier(&self, _endpoint: u8) -> Result<CharacterString, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    } // 32 bytes
    fn date_code(&self, _endpoint: u8) -> Result<CharacterString, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    } // 16 bytes
    fn power_source(&self, _endpoint: u8) -> Result<PowerSource, ClusterLibraryStatus>;
    fn location_description(&self, _endpoint: u8) -> Result<CharacterString, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    } // 16 bytes
    fn set_location_description(
        &mut self,
        _endpoint: u8,
        _value: &CharacterString,
    ) -> ClusterLibraryStatus {
        ClusterLibraryStatus::UnsupportedAttribute
    } // 16 bytes
    fn physical_environment(
        &self,
        _endpoint: u8,
    ) -> Result<PhysicalEnvironment, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn set_physical_environment(
        &mut self,
        _endpoint: u8,
        _value: PhysicalEnvironment,
    ) -> ClusterLibraryStatus {
        ClusterLibraryStatus::UnsupportedAttribute
    }
    fn device_enabled(&self, _endpoint: u8) -> Result<bool, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn set_device_enabled(&mut self, _endpoint: u8, _value: bool) -> ClusterLibraryStatus {
        ClusterLibraryStatus::UnsupportedAttribute
    }
    fn alarm_mask(&self, _endpoint: u8) -> Result<u8, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn set_alarm_mask(&mut self, _endpoint: u8, _value: u8) -> ClusterLibraryStatus {
        ClusterLibraryStatus::UnsupportedAttribute
    }
    fn disable_local_config(&self, _endpoint: u8) -> Result<u8, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    }
    fn set_disable_local_config(&mut self, _endpoint: u8, _value: u8) -> ClusterLibraryStatus {
        ClusterLibraryStatus::UnsupportedAttribute
    }
    fn software_build_identity(
        &self,
        _endpoint: u8,
    ) -> Result<CharacterString, ClusterLibraryStatus> {
        Err(ClusterLibraryStatus::UnsupportedAttribute)
    } // 16 bytes

    fn reset_to_factory_defaults(&mut self) -> ClusterLibraryStatus {
        ClusterLibraryStatus::UnsupportedClusterCommand
    }
}

impl Cluster for dyn BasicCluster {
    fn cluster_identifier() -> u16 {
        CLUSTER
    }

    fn read_attribute(
        &self,
        endpoint: u8,
        attribute: u16,
    ) -> Result<AttributeValue, ClusterLibraryStatus> {
        let result = match attribute {
            ATTR_LIBRARY_VERSION => self
                .library_version(endpoint)
                .map(|v| AttributeValue::Unsigned8(v)),
            ATTR_APPLICATION_VERSION => self
                .application_version(endpoint)
                .map(|v| AttributeValue::Unsigned8(v)),
            ATTR_STACK_VERSION => self
                .stack_version(endpoint)
                .map(|v| AttributeValue::Unsigned8(v)),
            ATTR_HARDWARE_VERSION => self
                .hardware_version(endpoint)
                .map(|v| AttributeValue::Unsigned8(v)),
            ATTR_MANUFACTURER_NAME => self
                .manufacturer_name(endpoint)
                .map(|v| AttributeValue::CharacterString(Some(v))),
            ATTR_MODEL_IDENTIFIER => self
                .model_identifier(endpoint)
                .map(|v| AttributeValue::CharacterString(Some(v))),
            ATTR_DATE_CODE => self
                .date_code(endpoint)
                .map(|v| AttributeValue::CharacterString(Some(v))),
            ATTR_POWER_SOURCE => self
                .power_source(endpoint)
                .map(|v| AttributeValue::Enumeration8(v.into())),
            ATTR_LOCATION_DESCRIPTION => self
                .location_description(endpoint)
                .map(|v| AttributeValue::CharacterString(Some(v))),
            ATTR_PHYSICAL_ENVIRONMENT => self
                .physical_environment(endpoint)
                .map(|v| AttributeValue::Enumeration8(v.into())),
            ATTR_DEVICE_ENABLED => self.device_enabled(endpoint).map(|v| v.into()),
            ATTR_ALARM_MASK => self
                .alarm_mask(endpoint)
                .map(|v| AttributeValue::Bitmap8(v.into())),
            ATTR_DISABLE_LOCAL_CONFIGURATION => self
                .disable_local_config(endpoint)
                .map(|v| AttributeValue::Bitmap8(v.into())),
            ATTR_SOFTWARE_BUILD_IDENTIFIER => self
                .software_build_identity(endpoint)
                .map(|v| AttributeValue::CharacterString(Some(v))),
            _ => Err(ClusterLibraryStatus::UnsupportedAttribute),
        };
        result
    }

    fn write_attribute(
        &mut self,
        endpoint: u8,
        attribute: u16,
        value: AttributeValue,
    ) -> ClusterLibraryStatus {
        let result = match attribute {
            ATTR_LOCATION_DESCRIPTION => {
                if let AttributeValue::CharacterString(Some(value)) = value {
                    self.set_location_description(endpoint, &value)
                } else {
                    ClusterLibraryStatus::InvalidDataType
                }
            }
            ATTR_PHYSICAL_ENVIRONMENT => {
                if let AttributeValue::Enumeration8(value) = value {
                    if let Ok(value) = PhysicalEnvironment::try_from(value) {
                        self.set_physical_environment(endpoint, value)
                    } else {
                        ClusterLibraryStatus::InvalidValue
                    }
                } else {
                    ClusterLibraryStatus::InvalidDataType
                }
            }
            ATTR_DEVICE_ENABLED => {
                if let AttributeValue::Boolean(value) = value {
                    self.set_device_enabled(endpoint, value == 0x01)
                } else {
                    ClusterLibraryStatus::InvalidDataType
                }
            }
            ATTR_ALARM_MASK => {
                if let AttributeValue::Bitmap8(value) = value {
                    self.set_alarm_mask(endpoint, value)
                } else {
                    ClusterLibraryStatus::InvalidDataType
                }
            }
            ATTR_DISABLE_LOCAL_CONFIGURATION => {
                if let AttributeValue::Bitmap8(value) = value {
                    self.set_disable_local_config(endpoint, value)
                } else {
                    ClusterLibraryStatus::InvalidDataType
                }
            }
            _ => ClusterLibraryStatus::UnsupportedAttribute,
        };
        result
    }

    fn command(&mut self, _endpoint: u8, command: u8, _payload: &[u8]) -> ClusterLibraryStatus {
        match command {
            CMD_RESET => self.reset_to_factory_defaults(),
            _ => ClusterLibraryStatus::UnsupportedClusterCommand,
        }
    }
}
