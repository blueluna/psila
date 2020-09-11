use psila_data::cluster_library::{AttributeValue, ClusterLibraryStatus};

pub trait ClusterLibraryHandler {
    /// Read attribute
    fn read_attribute(
        &self,
        profile: u16,
        cluster: u16,
        attribute: u16,
    ) -> Result<AttributeValue, ClusterLibraryStatus>;
    /// Read attribute
    fn write_attribute(
        &mut self,
        profile: u16,
        cluster: u16,
        attribute: u16,
        value: AttributeValue,
    ) -> Result<(), ClusterLibraryStatus>;
    /// Run command
    fn run(&mut self, profile: u16, cluster: u16, command: u8) -> Result<(), ClusterLibraryStatus>;
}
