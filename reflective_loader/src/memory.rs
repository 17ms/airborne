use core::ffi::c_void;

use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::{BOOL, BOOLEAN, FARPROC, HANDLE, HMODULE, NTSTATUS, UNICODE_STRING},
        Security::Cryptography::{BCRYPTGENRANDOM_FLAGS, BCRYPT_ALG_HANDLE},
        System::{
            Kernel::LIST_ENTRY,
            Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE},
        },
    },
};

#[allow(non_snake_case)]
pub static KERNEL32_DLL: u32 = 0x6DDB9555;

#[allow(non_snake_case)]
pub static NTDLL_DLL: u32 = 0x1EDAB0ED;

#[allow(non_snake_case)]
pub static BCRYPT_DLL: u32 = 0xEDB54DA3;

#[allow(non_snake_case)]
pub static LOAD_LIBRARY_A: u32 = 0xB7072FDB;

#[allow(non_snake_case)]
pub static GET_PROC_ADDRESS: u32 = 0xDECFC1BF;

#[allow(non_snake_case)]
pub static VIRTUAL_ALLOC: u32 = 0x97BC257;

#[allow(non_snake_case)]
pub static FLUSH_INSTRUCTION_CACHE: u32 = 0xEFB7BF9D;

#[allow(non_snake_case)]
pub static VIRTUAL_PROTECT: u32 = 0xE857500D;

#[allow(non_snake_case)]
pub static SLEEP: u32 = 0xE07CD7E;

#[allow(non_snake_case)]
pub static BCRYPT_GEN_RANDOM: u32 = 0xD966C0D4;

#[allow(non_camel_case_types)]
pub type LoadLibraryA = unsafe extern "system" fn(lpLibFileName: PCSTR) -> HMODULE;

#[allow(non_camel_case_types)]
pub type GetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: PCSTR) -> FARPROC;

#[allow(non_camel_case_types)]
pub type VirtualAlloc = unsafe extern "system" fn(
    lpAddress: *const c_void,
    dwSize: usize,
    flAllocationType: VIRTUAL_ALLOCATION_TYPE,
    flProtect: PAGE_PROTECTION_FLAGS,
) -> *mut c_void;

#[allow(non_camel_case_types)]
pub type VirtualProtect = unsafe extern "system" fn(
    lpAddress: *const c_void,
    dwSize: usize,
    flNewProtect: PAGE_PROTECTION_FLAGS,
    lpflOldProtect: *mut PAGE_PROTECTION_FLAGS,
) -> BOOL;

#[allow(non_camel_case_types)]
pub type FlushInstructionCache = unsafe extern "system" fn(
    hProcess: HANDLE,
    BaseAddress: *const c_void,
    NumberOfBytesToFlush: usize,
) -> BOOL;

#[allow(non_camel_case_types)]
pub type BCryptGenRandom = unsafe extern "system" fn(
    hAlgorithm: BCRYPT_ALG_HANDLE,
    pbBuffer: *mut u8,
    cbBuffer: u32,
    dwFlags: BCRYPTGENRANDOM_FLAGS,
) -> NTSTATUS;

#[allow(non_camel_case_types)]
pub type Sleep = unsafe extern "system" fn(dwMilliseconds: u32);

#[allow(non_camel_case_types)]
pub type DllMain =
    unsafe extern "system" fn(module: HMODULE, call_reason: u32, reserved: *mut c_void) -> BOOL;

#[allow(non_camel_case_types)]
pub type UserFunction =
    unsafe extern "system" fn(user_data: *mut c_void, user_data_len: u32) -> BOOL;

#[repr(C)]
#[allow(non_snake_case)]
pub struct FarProcs {
    pub LoadLibraryA: LoadLibraryA,
    pub GetProcAddress: GetProcAddress,
    pub VirtualAlloc: VirtualAlloc,
    pub VirtualProtect: VirtualProtect,
    pub FlushInstructionCache: FlushInstructionCache,
    pub Sleep: Sleep,
    pub BCryptGenRandom: BCryptGenRandom,
}

#[allow(non_camel_case_types)]
pub type PLDR_INIT_ROUTINE = Option<
    unsafe extern "system" fn(DllHandle: *mut c_void, Reason: u32, Context: *mut c_void) -> BOOLEAN,
>;

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut c_void,
    pub ShutdownInProgress: BOOLEAN,
    pub ShutdownThreadId: HANDLE,
}

#[repr(C)]
#[allow(non_snake_case)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: *mut c_void,
    pub EntryPoint: PLDR_INIT_ROUTINE,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}
