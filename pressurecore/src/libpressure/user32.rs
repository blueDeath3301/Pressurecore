use core::{
    ffi::c_void,
    ptr::null_mut,
};

use crate::{get_instance, libpressure::ldrapi::ldr_function};
use crate::libpressure::hash::dbj2_hash;
use crate::data::types::MessageBoxA;
pub struct User32 {
    pub module_base: *mut u8,
    pub messagebox_a: MessageBoxA,

    //other functions grow here

}

impl User32 {
    pub fn new() -> Self {
        User32 {
            module_base: null_mut(),
            messagebox_a: unsafe { core::mem::transmute(null_mut::<c_void>()) },



        }
    }
}

unsafe impl Sync for User32 {}
unsafe impl Send for User32 {}

pub fn init_user32_funcs() {
    unsafe {
        //hashes go here
        const MESSAGEBOX_A_HASH: usize = dbj2_hash(b"MessageBoxA\0") as usize;


        let instance = get_instance().unwrap();

        //proc addresses go here
        //MessageBoxA
        let messagebox_a_addr = ldr_function(instance.user32.module_base, MESSAGEBOX_A_HASH);
        instance.user32.messagebox_a = core::mem::transmute(messagebox_a_addr);

    }
}