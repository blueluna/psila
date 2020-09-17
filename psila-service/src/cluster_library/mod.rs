use psila_data::cluster_library::{AttributeDataType, ClusterLibraryStatus};

pub trait ClusterLibraryHandler {
    /// Read attribute
    fn read_attribute(
        &self,
        profile: u16,
        cluster: u16,
        attribute: u16,
        value: &mut [u8],
    ) -> Result<(AttributeDataType, usize), ClusterLibraryStatus>;
    /// Read attribute
    fn write_attribute(
        &mut self,
        profile: u16,
        cluster: u16,
        attribute: u16,
        data_type: AttributeDataType,
        value: &[u8],
    ) -> Result<(), ClusterLibraryStatus>;
    /// Run command
    fn run(&mut self, profile: u16, cluster: u16, command: u8) -> Result<(), ClusterLibraryStatus>;
}
