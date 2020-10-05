use psila_data::{
    cluster_library::{AttributeDataType, ClusterLibraryStatus},
    device_profile::SimpleDescriptor,
};

pub trait ClusterLibraryHandler {
    // Report active endpoints
    fn active_endpoints(&self) -> &[u8];
    // Report active endpoints
    fn get_simple_desciptor(&self, endpoint: u8) -> Option<SimpleDescriptor>;
    /// Read attribute
    fn read_attribute(
        &self,
        profile: u16,
        cluster: u16,
        endpoint: u8,
        attribute: u16,
        value: &mut [u8],
    ) -> Result<(AttributeDataType, usize), ClusterLibraryStatus>;
    /// Read attribute
    fn write_attribute(
        &mut self,
        profile: u16,
        cluster: u16,
        endpoint: u8,
        attribute: u16,
        data_type: AttributeDataType,
        value: &[u8],
    ) -> Result<(), ClusterLibraryStatus>;
    /// Run command
    fn run(
        &mut self,
        profile: u16,
        cluster: u16,
        endpoint: u8,
        command: u8,
        arguments: &[u8],
    ) -> Result<(), ClusterLibraryStatus>;
}
