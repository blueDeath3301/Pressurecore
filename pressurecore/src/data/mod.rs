pub mod types;
pub mod structs;
pub mod constants;

pub use types::*;
//pub use structs::*;
pub use constants::*;

/// Evaluates to TRUE if the return value specified by `nt_status` is a success
/// type (0 − 0x3FFFFFFF) or an informational type (0x40000000 − 0x7FFFFFFF).
/// This function is taken from ntdef.h in the WDK.
pub const fn NT_SUCCESS(nt_status: NTSTATUS) -> bool {
    nt_status >= 0
}

#[repr(C)]
pub enum EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
}