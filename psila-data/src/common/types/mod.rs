#[cfg(feature = "core")]
mod types_core;

#[cfg(feature = "std")]
mod types_std;

#[cfg(feature = "core")]
pub use types_core::{CharacterString, OctetString};

#[cfg(feature = "std")]
pub use types_std::{CharacterString, OctetString};
