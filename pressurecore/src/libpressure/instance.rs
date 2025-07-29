use super::{ntapi::veh_syscall::NtDll, k32::Kernel32, user32::User32};


// A magic number to identify a valid `Instance` struct
pub const INSTANCE_MAGIC: u32 = 0x17171717;


#[repr(C)]
pub struct Instance {
    pub magic: u32, //unique id for a valid instance
    pub ntdll: NtDll, // NTDLL API functions
    pub k32: Kernel32, // KERNEL32 API functions
    pub user32: User32, // USER32 API functions
    

}

impl Instance {
    pub fn new() -> Self {
        Instance {
            magic: INSTANCE_MAGIC,
            ntdll: NtDll::new(),
            k32: Kernel32::new(),
            user32: User32::new(),
            

        }
    } 
}