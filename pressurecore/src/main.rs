#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]


pub mod libpressure;
pub mod data;

use libpressure::instance::{Instance, INSTANCE_MAGIC};

use data::structs::find_peb;

extern crate alloc;

use core::arch::global_asm;
use core::ffi::c_void;
use libpressure::{ntapi::veh_syscall::init_ntdll_funcs, k32::init_kernel32_funcs, 
    user32::init_user32_funcs};
use crate::libpressure::hash::dbj2_hash;
use crate::libpressure::ldrapi::ldr_module;

//set a custom global allocator
use libpressure::allocator::NtVirtualAlloc;

#[global_allocator]
static GLOBAL: NtVirtualAlloc = NtVirtualAlloc;

#[unsafe(no_mangle)]
pub extern "C" fn initialize() {
    unsafe {
        //stack allocation of Instance
        let mut instance = Instance::new();

         //compute hashes at compile time
        const NTDLL_HASH: u32 = dbj2_hash(b"ntdll.dll");
        const KERNEL32_HASH: u32 = dbj2_hash(b"kernel32.dll");
        const USER32_HASH: u32 = dbj2_hash(b"user32.dll");
        
        // Extract the base address from the tuple returned by ldr_module
        let (ntdll_base, _) = ldr_module(NTDLL_HASH);
        instance.ntdll.module_base = ntdll_base;

        // Extract the base address for kernel32.dll
        let (k32_base, _) = ldr_module(KERNEL32_HASH);
        instance.k32.module_base = k32_base;

        //extract the base address for user32.dll
        let (user32_base, _) = ldr_module(USER32_HASH);
        instance.user32.module_base = user32_base;

        //append instance address to PEB.ProcessHeaps
        let instance_ptr: *mut c_void = &mut instance as *mut _ as *mut c_void;

        let peb = find_peb();
        let process_heaps = (*peb).process_heaps as *mut *mut c_void;
        let number_of_heaps = (*peb).number_of_heaps as usize;

        //increase the NumberOfHeaps
        (*peb).number_of_heaps += 1;

        //append the instance pointer to the process heaps
        *process_heaps.add(number_of_heaps) = instance_ptr;

        //proceed to the main() function
        main();
    }
}

//initializes system modules and functions, then detonates the payload
unsafe fn main() {
    init_ntdll_funcs();
    init_kernel32_funcs();
    init_user32_funcs();
    
    // You can add more payloads or functionality here
    pop_message_box();
    
}

//pop a message box payload with MessageBoxA
fn pop_message_box() {
    unsafe {
        let instance = crate::get_instance().unwrap();
        let message = "Hello from the kernel32 module!";
        let title = "Kernel32 Message";
        
        // Call the MessageBoxA function from user32.dll
        (instance.user32.messagebox_a)(
            core::ptr::null_mut(),
            message.as_ptr() as *const i8,
            title.as_ptr() as *const i8,
            0,
        );
    }
}
   
    

/*#[no_mangle]
unsafe extern "C" {
    fn _start();
}
*/

global_asm!(
    r#"
.globl _start
.globl isyscall

.section .text

_start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0xFFFFFFFFFFFFFFF0
    sub   rsp, 0x20
    call  initialize
    mov   rsp, rsi
    pop   rsi
    ret

isyscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    xor r10, r10			
    mov rax, rcx			
    mov r10, rax

    mov eax, ecx

    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
"#
);





/// Attempts to locate the global `Instance` by scanning process heaps and
/// returns a mutable reference to it if found.
pub fn get_instance() -> Option<&'static mut Instance> {
   unsafe {
    let peb = find_peb(); // Locate the PEB (Process Environment Block)
    let process_heaps = (*peb).process_heaps;
    let number_of_heaps = (*peb).number_of_heaps as usize;

    for i in 0..number_of_heaps {
        let heap = *process_heaps.add(i);
        if !heap.is_null() {
            let instance = &mut *(heap as *mut Instance);
            if instance.magic == INSTANCE_MAGIC {
                return Some(instance); // Return the instance if the magic value matches
            }
        }
    }
    None
   }
}

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}



