use core::{
    ffi::c_void,
    ptr::null_mut,
};



use crate::{get_instance, libpressure::ldrapi::ldr_function};
use crate::data::types::{WinExec, AddVectoredExceptionHandler,
    RemoveVectoredExceptionHandler, GetProcessHeap, HeapAlloc};
use crate::libpressure::hash::dbj2_hash;

pub struct Kernel32 {
    pub module_base: *mut u8,
    pub winexec: WinExec,
    pub add_vectored_exception_handler: AddVectoredExceptionHandler,
    pub remove_vectored_exception_handler: RemoveVectoredExceptionHandler,
    pub get_process_heap: GetProcessHeap,
    pub heap_alloc: HeapAlloc
    //other functions grow here
}

impl Kernel32 {
    pub fn new() -> Self {
        Kernel32 {
            module_base: null_mut(),
            winexec: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            add_vectored_exception_handler: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            remove_vectored_exception_handler:  unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_process_heap: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            heap_alloc: unsafe { core::mem::transmute(null_mut::<c_void>()) },

            //other functions grow here
        }
    }
}

unsafe impl Sync for Kernel32 {}
unsafe impl Send for Kernel32 {}

pub fn init_kernel32_funcs() {
    unsafe {
        //compute hashes at compile time...hashes grow here
        const WINEXEC_HASH: usize = dbj2_hash(b"WinExec\0") as usize;
        const ADD_VECTORED_EXCEPTION_HANDLER_HASH: usize = dbj2_hash(b"AddVectoredExceptionHandler\0") as usize;
        const REMOVE_VECTORED_EXCEPTION_HANDLER_HASH: usize = dbj2_hash(b"RemoveVectoredExceptionHandler\0") as usize;
        const GET_PROCESS_HEAP_HASH: usize = dbj2_hash(b"GetProcessHeap\0") as usize;
        const HEAP_ALLOC_HASH: usize = dbj2_hash(b"HeapAlloc\0") as usize;

        let instance = get_instance().unwrap();

        //WinExec
        let winexec_addr = ldr_function(instance.k32.module_base, WINEXEC_HASH);
        instance.k32.winexec = core::mem::transmute(winexec_addr);

        //AddVectoredExceptionHandler
        let add_vectored_exception_handler_addr = ldr_function(instance.k32.module_base, ADD_VECTORED_EXCEPTION_HANDLER_HASH);
        instance.k32.add_vectored_exception_handler = core::mem::transmute(add_vectored_exception_handler_addr);

        //RemoveVectoredExceptionHandler
        let remove_vectored_exception_handler_addr = ldr_function(instance.k32.module_base, REMOVE_VECTORED_EXCEPTION_HANDLER_HASH);
        instance.k32.remove_vectored_exception_handler = core::mem::transmute(remove_vectored_exception_handler_addr);

        //GetProcessHeap
        let get_process_heap_addr = ldr_function(instance.k32.module_base, GET_PROCESS_HEAP_HASH);
        instance.k32.get_process_heap = core::mem::transmute(get_process_heap_addr);

        //HeapAlloc
        let heap_alloc_addr = ldr_function(instance.k32.module_base, HEAP_ALLOC_HASH);
        instance.k32.heap_alloc = core::mem::transmute(heap_alloc_addr);
    }
}