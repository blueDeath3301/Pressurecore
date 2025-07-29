/*
indirect syscalls by abusing Vectored Exception Handling (VEH) to generate legitimate API call stack frames.
By calling a standard Windows API function and setting a hardware breakpoint within it, the function's call 
 stack is captured. This breakpoint then lets VEH redirect the process to a syscall wrapper in `ntdll.dll`, 
 preserving the original API's call stack structure. This approach enables syscalls to appear as if they 
 originate from legitimate Windows API calls.
*/

use core::ptr;
use core::ptr::null_mut;
use core::ffi::c_void;

use crate::data::constants::*;
use crate::data::structs::{Context, ExceptionPointers, DllInfo};
use crate::get_instance;
use crate::libpressure::ldrapi::ldr_module;
use crate::libpressure::hash::dbj2_hash;

static mut OPCODE_SYSCALL_OFF: u64 = 0;
static mut OPCODE_SYSCALL_RET_OFF: u64 = 0;

static mut SAVED_CONTEXT: *mut Context = core::ptr::null_mut();
static mut SYSCALL_ENTRY_ADDRESS: u64 = 0;
static mut IS_SUB_RSP: i32 = 0;
static mut SYSCALL_NO: u32 = 0;
static mut EXTENDED_ARGS: bool = false;

static mut NTDLL_INFO: DllInfo = DllInfo {
    base_address: 0,
    end_address: 0,
};

static mut H1: *mut c_void = ptr::null_mut();
static mut H2: *mut c_void = ptr::null_mut();

//example function designed to maintain a clean cal stack
//can be modife=ied to call different legit windows APIs
pub unsafe extern "C" fn demofunction() {
   let instance =get_instance().unwrap();
   unsafe {
    (instance.user32.messagebox_a)(
        null_mut(),
        null_mut(),
        null_mut(),
        0,
    );
   }
}

//initialize DllInfo struct with ntdll.dll base address and end address
pub fn initialize_dll_info(obj: &mut DllInfo) {
    const NTDLL_HASH: u32 = dbj2_hash(b"ntdll.dll");

    let (base_addr, size_of_image) = ldr_module(NTDLL_HASH) ;

    
    obj.base_address = base_addr as u64;
    obj.end_address = unsafe { base_addr.add(size_of_image) } as u64;
}

/// Adds hardware breakpoints at the syscall entry and return addresses.
///
/// This function is triggered when an `EXCEPTION_ACCESS_VIOLATION` occurs. It identifies the syscall
/// opcode by scanning the instruction pointer (Rcx) for the `syscall` instruction, then sets
/// hardware breakpoints (Dr0 and Dr1) at the syscall entry and return addresses, allowing for
/// interception and manipulation of the syscall.
#[unsafe(no_mangle)]
unsafe extern "system" fn add_hwbp(exception_info: *mut ExceptionPointers) -> i32 {
   unsafe {
        let exception_info = &*exception_info;

        //check if the exception is an access violation
        if (*exception_info.ExceptionRecord).ExceptionCode == EXCEPTION_ACCESS_VIOLATION.try_into().unwrap() {
            //set the syscall entry address to the current RCX value
            SYSCALL_ENTRY_ADDRESS = (*exception_info.ContextRecord).Rcx;

            //scan for the syscall opcode (0x0F 0x05) in the instruction sequence
            for i in 0..25 {
                if ptr::read((SYSCALL_ENTRY_ADDRESS + i) as *const u8) == 0x0F
                    && ptr::read((SYSCALL_ENTRY_ADDRESS + i + 1) as *const u8) == 0x05
                {
                    OPCODE_SYSCALL_OFF = i as u64;
                        OPCODE_SYSCALL_RET_OFF = i as u64 + 2;
                        break;    
                }
            }

            //set DR0 to the syscall entry address and enable the breakpoint
            (*exception_info.ContextRecord).Dr0 = SYSCALL_ENTRY_ADDRESS;
            (*exception_info.ContextRecord).Dr7 |= 1 << 0;

            // Set Dr1 to monitor the syscall return address
            (*exception_info.ContextRecord).Dr1 = SYSCALL_ENTRY_ADDRESS + OPCODE_SYSCALL_RET_OFF;
            (*exception_info.ContextRecord).Dr7 |= 1 << 2;

            (*exception_info.ContextRecord).Rip += OPCODE_SZ_ACC_VIO;

            /*debug_println!(
                "[*] Hardware Breakpoint added at address {:#x} (syscall)",
                (*exception_info.ContextRecord).Dr0
            );
            debug_println!(
                "[*] Hardware Breakpoint added at address {:#x} (ret)",
                (*exception_info.ContextRecord).Dr1
            ); */

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        EXCEPTION_CONTINUE_SEARCH
   }
} 


// Handles hardware breakpoints and single-step exceptions for syscall interception.
///
/// This function is triggered by `EXCEPTION_SINGLE_STEP` and checks for two key conditions:
/// 1. A hit on the syscall entry breakpoint (Dr0).
/// 2. A hit on the syscall return breakpoint (Dr1).
/// Additionally, it traces and handles the instruction flow within `ntdll.dll`, emulating
/// syscalls and restoring context as necessary.
///
/// - Clears and disables hardware breakpoints when hit.
/// - Saves and restores context for syscall interception.
/// - Emulates syscalls by manipulating the instruction pointer (Rip) and registers.
#[allow(static_mut_refs)]
#[unsafe(no_mangle)]
unsafe extern "system" fn hwbp_handler(exception_info: *mut ExceptionPointers) -> i32 {
    
    unsafe {
        let exception_info = &*exception_info;

        ////check if the exception is due to a single step event (hardware breakpoint hit)
        if (*exception_info.ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
            // Handle syscall hardware breakpoint (entry point)
            if (*exception_info.ExceptionRecord).ExceptionAddress
                == (SYSCALL_ENTRY_ADDRESS as *mut c_void)
            {
                /*debug_println!(
                    "[*] Hardware Breakpoint hit at {:#x} (syscall)",
                    (*exception_info.ContextRecord).Rip
                );
                debug_println!("[*] Storing Context");*/

                // Disable Dr0 (syscall entry breakpoint)
                (*exception_info.ContextRecord).Dr0 = 0;
                (*exception_info.ContextRecord).Dr7 &= !(1 << 0);

                // Save the current CPU context
                ptr::copy_nonoverlapping(exception_info.ContextRecord, SAVED_CONTEXT, 1);

                // Redirect execution to a demo function after storing the context
                (*exception_info.ContextRecord).Rip = demofunction as u64;

                // Set the trace flag to continue tracing
                (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Handle syscall return (Dr1 breakpoint)
            else if (*exception_info.ExceptionRecord).ExceptionAddress
                == (SYSCALL_ENTRY_ADDRESS + OPCODE_SYSCALL_RET_OFF) as *mut c_void
            {
                /*debug_println!(
                    "[*] Hardware Breakpoint hit at {:#x} (ret)",
                    (*exception_info.ContextRecord).Rip
                );

                debug_println!("[*] Restoring stack pointer");*/

                // Disable Dr1 (return breakpoint)
                (*exception_info.ContextRecord).Dr1 = 0;
                (*exception_info.ContextRecord).Dr7 &= !(1 << 2);

                // Restore the saved stack pointer
                (*exception_info.ContextRecord).Rsp = (*SAVED_CONTEXT).Rsp;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Handle tracing within `ntdll.dll`
            else if (*exception_info.ContextRecord).Rip >= NTDLL_INFO.base_address
                && (*exception_info.ContextRecord).Rip <= NTDLL_INFO.end_address
            {
                // Look for a "sub rsp" instruction to detect the stack frame
                if IS_SUB_RSP == 0 {
                    for i in 0..80 {
                        let opcode_ret_cc =
                            ptr::read(((*exception_info.ContextRecord).Rip + i as u64) as *const u16);

                        if opcode_ret_cc == OPCODE_RET_CC {
                            break;
                        }
                        let opcode_sub_rsp =
                            ptr::read(((*exception_info.ContextRecord).Rip + i as u64) as *const u32);

                        if (opcode_sub_rsp & 0xffffff) == OPCODE_SUB_RSP {
                            if (opcode_sub_rsp >> 24) >= 0x58 {
                                // Stack frame detected
                                IS_SUB_RSP = 1;
                                (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
                                return EXCEPTION_CONTINUE_EXECUTION;
                            } else {
                                break;
                            }
                        }
                    }
                }

                // Wait for a "call" instruction to continue processing
                if IS_SUB_RSP == 1 {
                    let rip_value = ptr::read((*exception_info.ContextRecord).Rip as *const u16);
                    if rip_value == OPCODE_RET_CC || rip_value as u8 == OPCODE_RET {
                        IS_SUB_RSP = 0;
                    } else if rip_value as u8 == OPCODE_CALL {
                        IS_SUB_RSP = 2;
                        (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }

                // Handle stack frame and call instruction
                if IS_SUB_RSP == 2 {
                    IS_SUB_RSP = 0;
                    /*debug_println!(
                        "[*] Inside ntdll after setting Trace Flag at {:#x} ({:#x})",
                        (*exception_info.ContextRecord).Rip,
                        (*exception_info.ContextRecord).Rip - NTDLL_INFO.base_address
                    );
                    debug_println!(
                        "[*] Generating stack & invoking intended syscall (ssn: {:#x})",
                        SYSCALL_NO
                    );*/

                    // Save the current RSP (stack pointer)
                    let temp_rsp = (*exception_info.ContextRecord).Rsp;
                    ptr::copy_nonoverlapping(
                        SAVED_CONTEXT,
                        exception_info.ContextRecord as *mut Context,
                        1,
                    );
                    (*exception_info.ContextRecord).Rsp = temp_rsp;

                    // Emulate the syscall by setting registers and instruction pointer
                    (*exception_info.ContextRecord).R10 = (*exception_info.ContextRecord).Rcx;
                    (*exception_info.ContextRecord).Rax = SYSCALL_NO as u64;
                    (*exception_info.ContextRecord).Rip = SYSCALL_ENTRY_ADDRESS + OPCODE_SYSCALL_OFF;

                    // Handles extended arguments for syscalls with more than 4 up to a maximum of 12 arguments.
                    if EXTENDED_ARGS {
                        let saved_rsp = (*SAVED_CONTEXT).Rsp;

                        ptr::copy_nonoverlapping(
                            (saved_rsp + FIFTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + FIFTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + SIXTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + SIXTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + SEVENTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + SEVENTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + EIGHTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + EIGHTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + NINTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + NINTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + TENTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + TENTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + ELEVENTH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + ELEVENTH_ARGUMENT) as *mut u64,
                            1,
                        );

                        ptr::copy_nonoverlapping(
                            (saved_rsp + TWELVETH_ARGUMENT) as *const u64,
                            ((*exception_info.ContextRecord).Rsp + TWELVETH_ARGUMENT) as *mut u64,
                            1,
                        );
                    }

                    // Clear the trace flag after handling the syscall
                    (*exception_info.ContextRecord).EFlags &= !TRACE_FLAG;

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            // Continue tracing
            (*exception_info.ContextRecord).EFlags |= TRACE_FLAG;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        EXCEPTION_CONTINUE_SEARCH
    }
}

///initializes necessary hooks for syscall interception
/// sets up the VEH handler and , allocates memory for saving CPU context
/// and initializes information about ntdll.dll (base address and end address) for use in syscall tracing
#[allow(static_mut_refs)]
pub fn veh_hooks() {
    unsafe {
        let instance = get_instance().unwrap();

        H1 = (instance.k32.add_vectored_exception_handler)(CALL_FIRST, Some(add_hwbp));
        H2 = (instance.k32.add_vectored_exception_handler)(CALL_FIRST, Some(hwbp_handler));

        // Allocate memory for the saved context
        SAVED_CONTEXT = ((instance.k32.heap_alloc)((instance.k32.get_process_heap)(), HEAP_ZERO_MEMORY, core::mem::size_of::<Context>())) as *mut Context;

        //initilaize ntdll.dll base address and end address for syscall tracing
        initialize_dll_info(&mut NTDLL_INFO);
        //debug_println!("[*] NTDLL Base Address: {:#x}", NTDLL_INFO.base_address);
        //debug_println!("[*] NTDLL End Address: {:#x}", NTDLL_INFO.end_address);

    }
}

///cleans up the VEH hooks by removing the exception handlers (and freeing allocated memory)?
/// checks if exception handlers h1 & h2 were added, and if so, removes them
pub fn remove_veh_hooks() {
    unsafe {
        let instance = get_instance().unwrap();

        if !H1.is_null() {
            (instance.k32.remove_vectored_exception_handler)(H1);
            //H1 = ptr::null_mut();
        }

        if !H2.is_null() {
            (instance.k32.remove_vectored_exception_handler)(H2);
            //H2 = ptr::null_mut();
        }
    }
}

/// This function triggers an access violation exception to force the system to raise an exception.
#[allow(unused_variables)]
pub fn set_hw_bp(func_address: usize, flag: i32, ssn: u32) {
    unsafe {
        EXTENDED_ARGS = flag != 0;
        SYSCALL_NO = ssn;
        trigger_access_violation_exception();
    }
}

/// This function dereferences a null pointer, which causes an access violation and is used to
/// invoke the previously set vectored exception handlers.
fn trigger_access_violation_exception() {
    unsafe {
        let a: *mut i32 = 0 as *mut i32;
        let _b = *a;
    }
}





