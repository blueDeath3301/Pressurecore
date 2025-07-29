extern crate alloc;
//use alloc::string::{ToString, String};


use crate::data::structs::{find_peb, PebLoaderData, ImageDosHeader,
    ImageNtHeaders, ImageExportDirectory, LoaderDataTableEntry};
use crate::data::constants::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
//use crate::data::HMODULE;
//use crate::libpressure::hash::crc32ba;
use crate::libpressure::hash::dbj2_hash;
use crate::libpressure::utils::get_cstr_len;

use core::ptr::null_mut;

/// Retrieves the NT headers from the base address of a module.
///
/// # Arguments
/// * `base_addr` - The base address of the module.
///
/// Returns a pointer to `ImageNtHeaders` or null if the headers are invalid.
#[cfg(target_arch = "x86_64")]
pub fn get_nt_headers(base_addr: *mut u8) -> *mut ImageNtHeaders {
   unsafe {
    let dos_header = base_addr as *mut ImageDosHeader;

    // Check if the DOS signature is valid (MZ)
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    // Calculate the address of NT headers
    let nt_headers = (base_addr as isize + (*dos_header).e_lfanew as isize) as *mut ImageNtHeaders;

    // Check if the NT signature is valid (PE\0\0)
    if (*nt_headers).signature != IMAGE_NT_SIGNATURE as _ {
        return null_mut();
    }
    nt_headers
   }

    
}

/// Finds and returns the base address of a module by its hash.
///
/// # Arguments
/// * `module_hash` - The hash of the module name to locate.
///
/// Returns the base address of the module or null if not found.
pub fn ldr_module(module_hash: u32) -> (*mut u8, usize) {
    unsafe {
        let peb = find_peb(); // Retrieve the PEB (Process Environment Block)

    if peb.is_null() {
        return (null_mut(), 0);
    }

    let peb_ldr_data_ptr = (*peb).loader_data as *mut PebLoaderData;
    if peb_ldr_data_ptr.is_null() {
        return (null_mut(), 0);
    }

    // Start with the first module in the InLoadOrderModuleList
    let mut module_list =
        (*peb_ldr_data_ptr).in_load_order_module_list.flink as *mut LoaderDataTableEntry;

    // Iterate through the list of loaded modules
    let list_head = &(*peb_ldr_data_ptr).in_load_order_module_list as *const _ as usize;

    while (module_list as usize) != list_head && !(*module_list).dll_base.is_null() {
        let dll_buffer_ptr = (*module_list).base_dll_name.buffer;
        let dll_length = (*module_list).base_dll_name.length as usize / 2; // WCHAR count

        // Create a slice from the DLL name
        //let dll_name_slice = core::slice::from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        // Convert UTF-16 to u8 for hashing
        let dll_name_utf16 = core::slice::from_raw_parts(dll_buffer_ptr, dll_length);
        // Convert to ASCII (lossy, but module names are ASCII)
        let mut dll_name_ascii = [0u8; 64];
        for (i, &ch) in dll_name_utf16.iter().enumerate().take(64) {
            dll_name_ascii[i] = ch as u8;
        }
        let dll_name_slice = &dll_name_ascii[..dll_length];

        // Compare the hash of the DLL name with the provided hash
        if module_hash == dbj2_hash(dll_name_slice) {
              //obtain the size of the module from the OptionalHeader.SizeOfImage field
              let nt_headers = get_nt_headers((*module_list).dll_base as *mut u8);
              let size_of_image = (*nt_headers).optional_header.size_of_image as usize;


            return ((*module_list).dll_base as _, size_of_image) ; // Return the base address of the module if the hash matches

          
        }

        // Move to the next module in the list
        module_list = (*module_list).in_load_order_links.flink as *mut LoaderDataTableEntry;
    }
    }

    (null_mut(), 0) // Return null if no matching module is found
}




pub fn ldr_function(module_base: *mut u8, function_hash: usize) -> *mut u8 {
   unsafe {
    let p_img_nt_headers = get_nt_headers(module_base); // Retrieve NT headers for the module

    if p_img_nt_headers.is_null() {
        return null_mut();
    }

    // Get the export directory from the NT headers
    let data_directory = &(*p_img_nt_headers).optional_header.data_directory[0];
    let export_directory =
        (module_base.offset(data_directory.virtual_address as isize)) as *mut ImageExportDirectory;
    if export_directory.is_null() {
        return null_mut();
    }

    let number_of_functions = (*export_directory).number_of_functions;
    let array_of_names =
        module_base.offset((*export_directory).address_of_names as isize) as *const u32;
    let array_of_addresses =
        module_base.offset((*export_directory).address_of_functions as isize) as *const u32;
    let array_of_ordinals =
        module_base.offset((*export_directory).address_of_name_ordinals as isize) as *const u16;

    // Create slices from the export directory arrays
    let names = core::slice::from_raw_parts(array_of_names, number_of_functions as _);
    let functions = core::slice::from_raw_parts(array_of_addresses, number_of_functions as _);
    let ordinals = core::slice::from_raw_parts(array_of_ordinals, number_of_functions as _);

    // Iterate through the export names to find the function matching the given hash
    for i in 0..number_of_functions {
        let name_addr = module_base.offset(names[i as usize] as isize) as *const i8;
        let name_len = get_cstr_len(name_addr as _); // Get the length of the function name
        let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

        // Compare the hash of the function name with the provided hash
        if function_hash as u32 == dbj2_hash(name_slice) {
            // Retrieve the function's address by its ordinal
            let ordinal = ordinals[i as usize] as usize;
            return module_base.offset(functions[ordinal] as isize) as *mut u8;
        }
    }
   }

    null_mut() // Return null if the function is not found
}



/*

fn get_proc_addr(module_handle: HINSTANCE, function_name: &str) -> FARPROC{
    
    unsafe {
        let dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        let nt_headers = (module_handle as UINT_PTR + (*dos_headers).e_lfanew as UINT_PTR) 
            as *const IMAGE_NT_HEADERS64;

        let data_directory = &(*nt_headers).OptionalHeader.DataDirectory[0];
        let export_directory = (module_handle as UINT_PTR + (*data_directory).VirtualAddress as UINT_PTR) 
            as *const IMAGE_EXPORT_DIRECTORY;

        let mut address_array = module_handle as UINT_PTR + (*export_directory).AddressOfFunctions as UINT_PTR;
        let mut name_array = module_handle as UINT_PTR + (*export_directory).AddressOfNames as UINT_PTR;
        let mut name_ordinals = module_handle as UINT_PTR + (*export_directory).AddressOfNameOrdinals as UINT_PTR;

        loop {

            let name_offset: u32 = *(name_array as *const u32);
            let current_function_name = std::ffi::CStr::from_ptr(
                (module_handle as UINT_PTR + name_offset as UINT_PTR) as *const c_char
            ).to_str().unwrap();

            if current_function_name == function_name{
                address_array = address_array + (*(name_ordinals as *const u16) as UINT_PTR * std::mem::size_of::<DWORD>() as UINT_PTR);
                let fun_addr: FARPROC = std::mem::transmute(module_handle as UINT_PTR + *(address_array as *const u32) as UINT_PTR);
                return fun_addr;
            }

            name_array = name_array + std::mem::size_of::<DWORD>() as UINT_PTR;
            name_ordinals = name_ordinals + std::mem::size_of::<u16>() as UINT_PTR;
        }
    }
}

*/