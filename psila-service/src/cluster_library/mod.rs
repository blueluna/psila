use psila_data::{
    cluster_library::{AttributeDataType, AttributeValue, ClusterLibraryStatus, Destination},
    device_profile::SimpleDescriptor,
};

mod basic;

pub trait ClusterLibraryHandler {
    // Report active endpoints
    fn active_endpoints(&self) -> &[u8];
    // Report active endpoints
    fn get_simple_descriptor(&self, endpoint: u8) -> Option<SimpleDescriptor>;
    /// Read attribute
    fn read_attribute(
        &self,
        profile: u16,
        cluster: u16,
        destination: Destination,
        attribute: u16,
        value: &mut [u8],
    ) -> Result<(AttributeDataType, usize), ClusterLibraryStatus>;
    /// Read attribute
    fn write_attribute(
        &mut self,
        profile: u16,
        cluster: u16,
        destination: Destination,
        attribute: u16,
        data_type: AttributeDataType,
        value: &[u8],
    ) -> Result<(), ClusterLibraryStatus>;
    /// Run command
    fn run(
        &mut self,
        profile: u16,
        cluster: u16,
        destination: Destination,
        command: u8,
        arguments: &[u8],
    ) -> Result<(), ClusterLibraryStatus>;
}

pub trait Cluster {
    fn cluster_identifier() -> u16;
    fn read_attribute(
        &self,
        endpoint: u8,
        attribute: u16,
    ) -> Result<AttributeValue, ClusterLibraryStatus>;
    fn write_attribute(
        &mut self,
        endpoint: u8,
        attribute: u16,
        value: AttributeValue,
    ) -> ClusterLibraryStatus;
    fn command(&mut self, endpoint: u8, command: u8, payload: &[u8]) -> ClusterLibraryStatus;
}
