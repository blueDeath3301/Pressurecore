///! This module provides key constants for interacting with APIs

//use core::arch::asm;
use core::ffi::c_ulong;
//use core::ffi::c_void;
//use core::ptr;

use super::types::{IMAGE_DIRECTORY_ENTRY, DWORD};


pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: IMAGE_DIRECTORY_ENTRY = 0u16;

pub const EXCEPTION_SINGLE_STEP: i32 = 0x80000004_u32 as _;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

pub const CONTEXT_DEBUG_REGISTERS_AMD64: u32 = 1048592u32;
pub const CONTEXT_DEBUG_REGISTERS_X86: u32 = 65552u32;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;
//pub const SYNCHRONIZE: u32 = 0x00100000;
pub const EVENT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3;
pub const WT_EXECUTEONLYONCE: u32 = 0x00000008;
pub const WT_EXECUTEINWAITTHREAD: u32 = 0x00000004;
pub const WT_EXECUTEINTIMERTHREAD: u32 = 0x00000020;

//for RusticShell
pub const OBJ_CASE_INSENSITIVE: c_ulong = 0x40;
pub const OBJ_INHERIT: c_ulong = 0x00000002;

pub const GENERIC_READ: u32 = 0x80000000;
pub const FILE_WRITE_ATTRIBUTES: c_ulong = 0x00000100;
pub const SYNCHRONIZE: c_ulong = 0x00100000;
pub const FILE_SHARE_READ: c_ulong = 0x00000001;
pub const FILE_SHARE_WRITE: c_ulong = 0x00000002;
pub const FILE_CREATE: u32 = 0x00000002;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
pub const FILE_PIPE_BYTE_STREAM_TYPE: u32 = 0x00000000;
pub const FILE_PIPE_BYTE_STREAM_MODE: u32 = 0x00000000;
pub const FILE_PIPE_QUEUE_OPERATION: u32 = 0x00000000;
pub const FILE_WRITE_DATA: c_ulong = 0x00000002;
pub const STANDARD_RIGHTS_WRITE: c_ulong = 0x00020000;
pub const FILE_WRITE_EA: c_ulong = 0x00000010;
pub const FILE_APPEND_DATA: c_ulong = 0x00000004;
pub const FILE_GENERIC_WRITE: u32 = STANDARD_RIGHTS_WRITE
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | SYNCHRONIZE;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;


pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

pub const PAGE_NOACCESS: u32 = 0x1;
pub const PAGE_READONLY: u32 = 0x2;
pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_WRITECOPY: u32 = 0x8;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

pub const SECTION_MEM_READ: u32 = 0x40000000;
pub const SECTION_MEM_WRITE: u32 = 0x80000000;
pub const SECTION_MEM_EXECUTE: u32 = 0x20000000;

// Access mask
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const GENERIC_ALL: u32 = 0x10000000;
pub const SECTION_ALL_ACCESS: u32 = 0x10000000;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const THREAD_ALL_ACCESS: u32 =  0x000F0000 |  0x00100000 | 0xFFFF;

//File share flags
pub const FILE_SHARE_NONE: u32 = 0x0;
pub const FILE_SHARE_DELETE: u32 = 0x4;

//File access flags
pub const DELETE: u32 = 0x10000;
pub const FILE_READ_DATA: u32 = 0x1;
pub const FILE_READ_ATTRIBUTES: u32 = 0x80;
pub const FILE_READ_EA: u32 = 0x8;
pub const READ_CONTROL: u32 = 0x20000;

pub const WRITE_DAC: u32 = 0x40000;
pub const WRITE_OWNER: u32 = 0x80000;

//defs for VEH syscalls
pub const OPCODE_SUB_RSP: u32 = 0xec8348;
pub const OPCODE_RET_CC: u16 = 0xccc3;
pub const OPCODE_RET: u8 = 0xc3;
pub const OPCODE_CALL: u8 = 0xe8;
// pub const OPCODE_JMP: u8 = 0xe9;
// pub const OPCODE_JMP_LEN: usize = 8;
// pub const MAX_SEARCH_LIMIT: usize = 20;
pub const CALL_FIRST: u32 = 1;
// pub const RESUME_FLAG: u64 = 0x10000;
pub const TRACE_FLAG: u32 = 0x100;
// pub const OPCODE_SYSCALL: u16 = 0x050F;
// pub const OPCODE_SZ_DIV: u64 = 4;
pub const OPCODE_SZ_ACC_VIO: u64 = 2;

pub const FIFTH_ARGUMENT: u64 = 0x8 * 0x5;
pub const SIXTH_ARGUMENT: u64 = 0x8 * 0x6;
pub const SEVENTH_ARGUMENT: u64 = 0x8 * 0x7;
pub const EIGHTH_ARGUMENT: u64 = 0x8 * 0x8;
pub const NINTH_ARGUMENT: u64 = 0x8 * 0x9;
pub const TENTH_ARGUMENT: u64 = 0x8 * 0xa;
pub const ELEVENTH_ARGUMENT: u64 = 0x8 * 0xb;
pub const TWELVETH_ARGUMENT: u64 = 0x8 * 0xc;

pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;
