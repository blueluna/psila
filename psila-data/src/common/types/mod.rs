#[cfg(feature = "core")]
mod types_core;

#[cfg(not(feature = "core"))]
mod types_std;

#[cfg(feature = "core")]
pub use types_core::{CharacterString, OctetString};

#[cfg(not(feature = "core"))]
pub use types_std::{CharacterString, OctetString};
