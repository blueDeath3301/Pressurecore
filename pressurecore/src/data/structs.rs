use core::arch::asm;
use core::ffi::{c_ulong, c_void};
use core::ptr;

use crate::libpressure::utils::string_length_w;
use crate::data::types::*;
//use crate::data::types::{LPCWSTR, LPWSTR};

use bitflags::bitflags;

// Definition of LIST_ENTRY
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

// Definition of UNICODE_STRING
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub fn new() -> Self {
        UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        }
    }

    // RtlInitUnicodeString
    pub fn init(&mut self, source_string: *const u16) {
        if !source_string.is_null() {
            let dest_size = string_length_w(source_string) * 2;
            self.length = dest_size as u16;
            self.maximum_length = (dest_size + 2) as u16;
            self.buffer = source_string as *mut u16;
        } else {
            self.length = 0;
            self.maximum_length = 0;
            self.buffer = ptr::null_mut();
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SectionPointer {
    pub section_pointer: *mut c_void,
    pub check_sum: c_ulong,
}

#[repr(C)]
pub union HashLinksOrSectionPointer {
    pub hash_links: ListEntry,
    pub section_pointer: SectionPointer,
}

#[repr(C)]
pub union TimeDateStampOrLoadedImports {
    pub time_date_stamp: c_ulong,
    pub loaded_imports: *mut c_void,
}

#[repr(C)]
pub struct LoaderDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: c_ulong,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: c_ulong,
    pub load_count: i16,
    pub tls_index: i16,
    pub hash_links_or_section_pointer: HashLinksOrSectionPointer,
    pub time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports,
    pub entry_point_activation_context: *mut c_void,
    pub patch_information: *mut c_void,
    pub forwarder_links: ListEntry,
    pub service_tag_links: ListEntry,
    pub static_links: ListEntry,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [*mut c_void; 2],
    pub InMemoryOrderLinks: ListEntry,
    pub Reserved2: [*mut c_void; 2],
    pub DllBase: *mut c_void,
    pub Reserved3: [*mut c_void; 2],
    pub FullDllName: UnicodeString,
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut c_void; 3],
    pub Anonymous: LdrDataTableEntry_0,
    pub TimeDateStamp: u32,
}


#[repr(C)]
pub union LdrDataTableEntry_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut core::ffi::c_void,
}


#[repr(C)]
pub struct PebLoaderData {
    pub length: c_ulong,
    pub initialized: c_ulong,
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: bool,
    pub read_image_file_exec_options: bool,
    pub being_debugged: bool,
    pub spare: bool,
    pub mutant: *mut c_void,
    pub image_base: *mut c_void,
    pub loader_data: *const PebLoaderData,
    pub process_parameters: *const RtlUserProcessParameters,
    pub sub_system_data: *mut c_void,
    pub process_heap: *mut c_void,
    pub fast_peb_lock: *mut c_void,
    pub fast_peb_lock_routine: *mut c_void,
    pub fast_peb_unlock_routine: *mut c_void,
    pub environment_update_count: c_ulong,
    pub kernel_callback_table: *const *mut c_void,
    pub event_log_section: *mut c_void,
    pub event_log: *mut c_void,
    pub free_list: *mut c_void,
    pub tls_expansion_counter: c_ulong,
    pub tls_bitmap: *mut c_void,
    pub tls_bitmap_bits: [c_ulong; 2],
    pub read_only_shared_memory_base: *mut c_void,
    pub read_only_shared_memory_heap: *mut c_void,
    pub read_only_static_server_data: *const *mut c_void,
    pub ansi_code_page_data: *mut c_void,
    pub oem_code_page_data: *mut c_void,
    pub unicode_case_table_data: *mut c_void,
    pub number_of_processors: c_ulong,
    pub nt_global_flag: c_ulong,
    pub spare_2: [u8; 4],
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: c_ulong,
    pub heap_segment_commit: c_ulong,
    pub heap_de_commit_total_free_threshold: c_ulong,
    pub heap_de_commit_free_block_threshold: c_ulong,
    pub number_of_heaps: c_ulong,
    pub maximum_number_of_heaps: c_ulong,
    pub process_heaps: *const *const *mut c_void,
    pub gdi_shared_handle_table: *mut c_void,
    pub process_starter_helper: *mut c_void,
    pub gdi_dc_attribute_list: *mut c_void,
    pub loader_lock: *mut c_void,
    pub os_major_version: c_ulong,
    pub os_minor_version: c_ulong,
    pub os_build_number: c_ulong,
    pub os_platform_id: c_ulong,
    pub image_sub_system: c_ulong,
    pub image_sub_system_major_version: c_ulong,
    pub image_sub_system_minor_version: c_ulong,
    pub gdi_handle_buffer: [c_ulong; 22],
    pub post_process_init_routine: c_ulong,
    pub tls_expansion_bitmap: c_ulong,
    pub tls_expansion_bitmap_bits: [u8; 80],
    pub session_id: c_ulong,
}

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: *mut c_void,
    pub console_flags: u32,
    pub standard_input: *mut c_void,
    pub standard_output: *mut c_void,
    pub standard_error: *mut c_void,
    pub current_directory_path: UnicodeString,
    pub current_directory_handle: *mut c_void,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: *mut c_void,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UnicodeString,
    pub desktop_info: UnicodeString,
    pub shell_info: UnicodeString,
    pub runtime_data: UnicodeString,
    pub current_directories: [UnicodeString; 32],
    pub environment_size: u32,
    pub environment_version: u32,
    pub package_dependency_data: *mut c_void,
    pub process_group_id: u32,
    pub loader_threads: u32,
}

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ImageNtHeaders {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[cfg(target_arch = "x86_64")]
pub fn find_peb() -> *mut PEB {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb_ptr
        );
    }
    peb_ptr
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LargeInteger {
    pub low_part: u32,
    pub high_part: i32,
}

impl LargeInteger {
    pub fn new() -> Self {
        LargeInteger {
            high_part: 0,
            low_part: 0,
        }
    }
}

#[repr(C)]
pub struct ClientId {
    pub unique_process: *mut c_void,
    pub unique_thread: *mut c_void,
}

#[repr(C)]
pub struct NtTib {
    pub exception_list: *mut c_void,
    pub stack_base: *mut c_void,
    pub stack_limit: *mut c_void,
    pub sub_system_tib: *mut c_void,
    pub fiber_data: *mut c_void,
    pub arbitrary_user_pointer: *mut c_void,
    pub self_: *mut NtTib,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct TEB {
    pub nt_tib: NtTib,
    pub environment_pointer: *mut c_void,
    pub client_id: ClientId,
    pub active_rpc_handle: *mut c_void,
    pub thread_local_storage_pointer: *mut c_void,
    pub process_environment_block: *mut PEB,
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    pub csr_client_thread: *mut c_void,
    pub win32_thread_info: *mut c_void,
    pub user32_reserved: [u32; 26],
    pub user_reserved: [u32; 5],
    pub wow64_reserved: *mut c_void,
    pub current_locale: u32,
    pub fp_software_status_register: u32,
    pub system_reserved1: [*mut c_void; 54],
    pub exception_code: u32,
    pub activation_context_stack_pointer: *mut c_void,
    pub spare_bytes: [u8; 24],
    pub tx_fs_context: u32,
    pub gdi_tcell_buffer: *mut c_void,
    pub gdi_prev_spare_tcell: u32,
    pub gdi_prev_spare_tx: u32,
    pub gdi_batch_count: u32,
    pub spare_stack_array: [u32; 0x200],
    pub spare1: [u8; 40],
    pub x64_spare2: [u32; 0x3d],
    pub x64_spare3: [u32; 0x3d],
    pub tx_fb_context: u32,
    pub gdi_last_spare_tcell: u32,
    pub gdi_last_spare_tx: u32,
    pub gdi_last_spare_stack_array: [u32; 0x200],
}

unsafe impl Sync for TEB {}
unsafe impl Send for TEB {}

/// Find the Thread Environment Block (TEB) of the current process on x86_64
#[cfg(target_arch = "x86_64")]
pub fn nt_current_teb() -> *mut TEB {
    let teb_ptr: *mut TEB;
    unsafe {
        asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb_ptr
        );
    }
    teb_ptr
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: c_ulong,
    pub root_directory: *mut c_void,
    pub object_name: *mut UnicodeString,
    pub attributes: c_ulong,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

impl ObjectAttributes {
    pub fn new() -> Self {
        ObjectAttributes {
            length: 0,
            root_directory: ptr::null_mut(),
            object_name: ptr::null_mut(),
            attributes: 0,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        }
    }

    //InitializeObjectAttributes
    pub fn initialize(
        p: &mut ObjectAttributes,
        n: *mut UnicodeString,
        a: c_ulong,
        r: *mut c_void,
        s: *mut c_void,
    ) {
        p.length = core::mem::size_of::<ObjectAttributes>() as c_ulong;
        p.root_directory = r;
        p.attributes = a;
        p.object_name = n;
        p.security_descriptor = s;
        p.security_quality_of_service = ptr::null_mut();
    }
}

#[repr(C)]
pub union IO_STATUS_BLOCK_u {
    pub status: i32,
    pub pointer: *mut c_void,
}

#[repr(C)]
pub struct IoStatusBlock {
    pub u: IO_STATUS_BLOCK_u,
    pub information: c_ulong,
}

impl IoStatusBlock {
    pub fn new() -> Self {
        IoStatusBlock {
            u: IO_STATUS_BLOCK_u { status: 0 },
            information: 0,
        }
    }
}

#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    pub peb_base_address: *mut c_void,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: *mut c_void,
    pub inherited_from_unique_process_id: *mut c_void,
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86_64")]
pub struct Context {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: Context_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Context_0 {
    pub FltSave: XSaveFormat,
    pub Anonymous: Context_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XSaveFormat {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

impl Default for Context {
    #[cfg(target_arch = "x86_64")]
    fn default() -> Self {
        Self {
            P1Home: 0,
            P2Home: 0,
            P3Home: 0,
            P4Home: 0,
            P5Home: 0,
            P6Home: 0,
            ContextFlags: 0,
            MxCsr: 0,
            SegCs: 0,
            SegDs: 0,
            SegEs: 0,
            SegFs: 0,
            SegGs: 0,
            SegSs: 0,
            EFlags: 0,
            Dr0: 0,
            Dr1: 0,
            Dr2: 0,
            Dr3: 0,
            Dr6: 0,
            Dr7: 0,
            Rax: 0,
            Rcx: 0,
            Rdx: 0,
            Rbx: 0,
            Rsp: 0,
            Rbp: 0,
            Rsi: 0,
            Rdi: 0,
            R8: 0,
            R9: 0,
            R10: 0,
            R11: 0,
            R12: 0,
            R13: 0,
            R14: 0,
            R15: 0,
            Rip: 0,
            Anonymous: Context_0::default(),
            VectorRegister: [M128A::default(); 26],
            VectorControl: 0,
            DebugControl: 0,
            LastBranchToRip: 0,
            LastBranchFromRip: 0,
            LastExceptionToRip: 0,
            LastExceptionFromRip: 0,
        }
    }
}

impl Default for Context_0 {
    fn default() -> Self {
        Self {
            FltSave: XSaveFormat::default(),
        }
    }
}

impl Default for XSaveFormat {
    fn default() -> Self {
        Self {
            ControlWord: 0,
            StatusWord: 0,
            TagWord: 0,
            Reserved1: 0,
            ErrorOpcode: 0,
            ErrorOffset: 0,
            ErrorSelector: 0,
            Reserved2: 0,
            DataOffset: 0,
            DataSelector: 0,
            Reserved3: 0,
            MxCsr: 0,
            MxCsr_Mask: 0,
            FloatRegisters: [M128A::default(); 8],
            XmmRegisters: [M128A::default(); 16],
            Reserved4: [0; 96],
        }
    }
}

impl Default for M128A {
    fn default() -> Self {
        Self {
            Low: 0,
            High: 0,
        }
    }
}


impl Default for Context_0_0 {
    fn default() -> Self {
        Self {
            Header: [M128A::default(); 2],
            Legacy: [M128A::default(); 8],
            Xmm0: M128A::default(),
            Xmm1: M128A::default(),
            Xmm2: M128A::default(),
            Xmm3: M128A::default(),
            Xmm4: M128A::default(),
            Xmm5: M128A::default(),
            Xmm6: M128A::default(),
            Xmm7: M128A::default(),
            Xmm8: M128A::default(),
            Xmm9: M128A::default(),
            Xmm10: M128A::default(),
            Xmm11: M128A::default(),
            Xmm12: M128A::default(),
            Xmm13: M128A::default(),
            Xmm14: M128A::default(),
            Xmm15: M128A::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionPointers {
    pub ExceptionRecord: *mut ExceptionRecord,
    pub ContextRecord: *mut Context,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRecord {
    pub ExceptionCode: NTSTATUS,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut ExceptionRecord,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

#[repr(C)]
pub struct PsAttributeList {
    pub TotalLength: usize,
    pub Attributes: [PsAttribute; 1],
}

#[repr(C)]
pub struct PsAttribute {
    pub Attribute: usize,
    pub Size: usize,
    pub u: PsAttribute_0,
    pub ReturnLength: *mut usize,
}

#[repr(C)]
pub union PsAttribute_0 {
    pub Value: usize,
    pub ValuePtr: *mut c_void,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct BitField: u8 {
        const ImageUsesLargePages          = 1 << 0;
        const IsProtectedProcess           = 1 << 1;
        const IsImageDynamicallyRelocated  = 1 << 2;
        const SkipPatchingUser32Forwarders = 1 << 3;
        const IsPackagedProcess            = 1 << 4;
        const IsAppContainer               = 1 << 5;
        const IsProtectedProcessLight      = 1 << 6;
        const IsLongPathAwareProcess       = 1 << 7;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct CrossProcessFlags: u32 {
        const ProcessInJob               = 1 << 0;
        const ProcessInitializing        = 1 << 1;
        const ProcessUsingVEH            = 1 << 2;
        const ProcessUsingVCH            = 1 << 3;
        const ProcessUsingFTH            = 1 << 4;
        const ProcessPreviouslyThrottled = 1 << 5;
        const ProcessCurrentlyThrottled  = 1 << 6;
        const ProcessImagesHotPatched    = 1 << 7;
        const ReservedBits0              = 0xFFFFFF00;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct AppModelFeatureState: u32 {
        const ForegroundBoostProcesses     = 1 << 0;
        const AppModelFeatureStateReserved = 0xFFFFFFFE; 
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TracingFlags: u32 {
        const HeapTracingEnabled      = 1 << 0;
        const CritSecTracingEnabled   = 1 << 1;
        const LibLoaderTracingEnabled = 1 << 2;
        const SpareTracingBits        = 0xFFFF_FFF8;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct LeapSecondFlags: u128 {
        const Depth     = 0xFFFF;
        const Sequence  = 0xFFFFFFFFFFFF << 16;
        const Reserved  = 0xF << 64;
        const NextEntry = 0xFFFFFFFFFFFFFFF << 68;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TelemetryCoverageHeader_0: u16 {
        const TRACING_ENABLED = 1 << 0; 
        const RESERVED1       = 0xFFFE;
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_0 {
    pub BitField: u8,
    pub Anonymous: BitField
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_1 {
    pub CrossProcessFlags: u32,
    pub Anonymous: CrossProcessFlags,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Peb2 {
    pub KernelCallbackTable: *mut c_void,
    pub UserSharedInfoPtr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Peb3 {
    pub AppModelFeatureState: u32,
    pub Anonymous: AppModelFeatureState,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Peb4 {
    pub pContextData: *mut c_void,
    pub EcCodeBitMap: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Peb5 {
    pub TracingFlags: u32,
    pub Anonymous: TracingFlags,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Peb6 {
    pub LeapSecondFlags: u32,
    pub Anonymous: LeapSecondFlags,
}

/*pub union LdrDataTableEntry_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut core::ffi::c_void,
}
*/
#[repr(C)]
pub struct TelemetryCoverageHeader {
    pub MajorVersion: u8,
    pub MinorVersion: u8,
    pub Anonymous: TelemetryCoverageHeader_0,
    pub HashTableEntries: u32,
    pub HashIndexMask: u32,
    pub TableUpdateVersion: u32,
    pub TableSizeInBytes: u32,
    pub LastResetTick: u32,
    pub ResetRound: u32,
    pub Reserved2: u32,
    pub RecordedCount: u32,
}

#[repr(C)]
pub struct WER_RECOVERY_INFO {
    pub Length: u32,
    pub Callback: *mut c_void,
    pub Parameter: *mut c_void,
    pub Started: HANDLE,
    pub Finished: HANDLE,
    pub InProgress: HANDLE,
    pub LastError: i32,
    pub Successful: i32,
    pub PingInterval: u32,
    pub Flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WER_FILE {
    pub Flags: u16,
    pub Path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WER_MEMORY {
    pub Address: *mut c_void,
    pub Size: u32,
}

#[repr(C)]
pub union WER_GATHER_VALUE {
    pub File: WER_FILE,
    pub Memory: WER_MEMORY,
}

#[repr(C)]
pub struct WER_GATHER {
    pub Next: *mut WER_GATHER,
    pub Flags: u16,
    pub v: WER_GATHER_VALUE,
}

#[repr(C)]
pub struct WER_METADATA {
    pub Next: *mut WER_METADATA,
    pub Key: [u16; 64],
    pub Value: [u16; 128],
}

#[repr(C)]
pub struct WER_RUNTIME_DLL {
    pub Next: *mut WER_RUNTIME_DLL,
    pub Length: u32,
    pub Context: *mut c_void,
    pub CallbackDllPath: [u16; 260],
}

#[repr(C)]
pub struct WER_DUMP_COLLECTION {
    pub Next: *mut WER_DUMP_COLLECTION,
    pub ProcessId: u32,
    pub ThreadId: u32,
}

#[repr(C)]
pub struct WER_HEAP_MAIN_HEADER {
    pub Signature: [u16; 16],
    pub Links: ListEntry,
    pub Mutex: HANDLE,
    pub FreeHeap: *mut c_void,
    pub FreeCount: u32,
}

#[repr(C)]
pub struct WER_PEB_HEADER_BLOCK {
    pub Length: i32,
    pub Signature: [u16; 16],
    pub AppDataRelativePath: [u16; 64],
    pub RestartCommandLine: [u16; 1024],
    pub RecoveryInfo: WER_RECOVERY_INFO,
    pub Gather: *mut WER_GATHER,
    pub MetaData: *mut WER_METADATA,
    pub RuntimeDll: *mut WER_RUNTIME_DLL,
    pub DumpCollection: *mut WER_DUMP_COLLECTION,
    pub GatherCount: i32,
    pub MetaDataCount: i32,
    pub DumpCount: i32,
    pub Flags: i32,
    pub MainHeader: WER_HEAP_MAIN_HEADER,
    pub Reserved: *mut c_void,
}

#[repr(C)]
pub struct AssemblyStorageMapEntry {
    Flags: u32,
    DosPath: UnicodeString,
    Handle: HANDLE
}

#[repr(C)]
pub struct AssemblyStorageMap {
    pub Flags: u32,
    pub AssemblyCount: u32,
    pub AssemblyArray: *mut AssemblyStorageMapEntry,
}

#[repr(C)]
pub struct ActivationContextData {
    pub Magic: u32,
    pub HeaderSize: u32,
    pub FormatVersion: u32,
    pub TotalSize: u32,
    pub DefaultTocOffset: u32,
    pub ExtendedTocOffset: u32,
    pub AssemblyRosterOffset: u32,
    pub Flags: u32
}

#[repr(C)]
pub struct SecurityAttributes {
    pub n_length: u32,
    pub lp_security_descriptor: *mut c_void,
    pub b_inherit_handle: bool,
}


#[repr(C)]
pub struct StartupInfoW {
    pub cb: u32,
    pub lp_reserved: *mut u16,
    pub lp_desktop: *mut u16,
    pub lp_title: *mut u16,
    pub dw_x: u32,
    pub dw_y: u32,
    pub dw_x_size: u32,
    pub dw_y_size: u32,
    pub dw_x_count_chars: u32,
    pub dw_y_count_chars: u32,
    pub dw_fill_attribute: u32,
    pub dw_flags: u32,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: *mut c_void,
    pub h_std_output: *mut c_void,
    pub h_std_error: *mut c_void,
}

impl StartupInfoW {
    pub fn new() -> Self {
        StartupInfoW {
            cb: core::mem::size_of::<StartupInfoW>() as u32,
            lp_reserved: ptr::null_mut(),
            lp_desktop: ptr::null_mut(),
            lp_title: ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: ptr::null_mut(),
            h_std_input: ptr::null_mut(),
            h_std_output: ptr::null_mut(),
            h_std_error: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct ProcessInformation {
    pub h_process: *mut c_void,
    pub h_thread: *mut c_void,
    pub dw_process_id: u32,
    pub dw_thread_id: u32,
}

impl ProcessInformation {
    pub fn new() -> Self {
        ProcessInformation {
            h_process: ptr::null_mut(),
            h_thread: ptr::null_mut(),
            dw_process_id: 0,
            dw_thread_id: 0,
        }
    }
}


#[repr(C)]
pub struct DllInfo {
    pub base_address: u64,
    pub end_address: u64,
}
