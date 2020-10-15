//! # Common structs and functions
//!
//! Common things like addresses, security key data, ...

pub mod address;
pub mod capability_information;
pub mod key;
pub mod profile_identifier;
pub mod types;

pub use profile_identifier::ProfileIdentifier;

/// Convert link quality to path cost
pub fn link_quality_to_cost(link_quality: u8) -> u8 {
    if link_quality > 50 {
        1
    } else if link_quality > 30 {
        2
    } else if link_quality > 20 {
        3
    } else if link_quality > 10 {
        4
    } else if link_quality > 5 {
        5
    } else if link_quality > 2 {
        6
    } else {
        7
    }
}
