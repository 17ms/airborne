#![no_std]

mod memory;

use core::{
    arch::asm,
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::null_mut,
    slice::from_raw_parts,
};

use airborne_utils::Flags;
use windows_sys::{
    core::PWSTR,
    Win32::{
        Foundation::{BOOL, HMODULE, STATUS_SUCCESS},
        Security::Cryptography::BCRYPT_RNG_ALG_HANDLE,
        System::{
            Diagnostics::Debug::{
                IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,
                IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64,
                IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
                IMAGE_SECTION_HEADER,
            },
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                PAGE_WRITECOPY,
            },
            SystemServices::{
                DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
                IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
                IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_DIR64,
                IMAGE_REL_BASED_HIGHLOW,
            },
            Threading::{PEB, TEB},
            WindowsProgramming::IMAGE_THUNK_DATA64,
        },
    },
};

use crate::memory::*;

const MAX_IMPORT_DELAY_MS: u64 = 2000;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub unsafe extern "system" fn DllMain(_module: HMODULE, _reason: u32, _reserved: *mut u8) -> BOOL {
    1
}

#[link_section = ".text"]
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "system" fn loader(
    payload_dll: *mut c_void,
    function_hash: u32,
    user_data: *mut c_void,
    user_data_len: u32,
    _shellcode_bin: *mut c_void,
    flags: u32,
) {
    let flags = airborne_utils::parse_u32_flag(flags);

    /*
        1.) locate the required functions and modules from exports with their hashed names
    */

    let kernel32_base_ptr = get_module_ptr(KERNEL32_DLL).unwrap();
    let _ntdll_base_ptr = get_module_ptr(NTDLL_DLL).unwrap();
    let bcrypt_base_ptr = get_module_ptr(BCRYPT_DLL).unwrap();

    if kernel32_base_ptr.is_null() || _ntdll_base_ptr.is_null() || bcrypt_base_ptr.is_null() {
        return;
    }

    let far_procs = get_export_ptrs(kernel32_base_ptr, bcrypt_base_ptr).unwrap();

    /*
        2.) load the target image to a newly allocated permanent memory location with RW permissions
    */

    let module_base_ptr = payload_dll as *mut u8;

    if module_base_ptr.is_null() {
        return;
    }

    let module_dos_header_ptr = module_base_ptr as *mut IMAGE_DOS_HEADER;
    let module_nt_headers_ptr = (module_base_ptr as usize
        + (*module_dos_header_ptr).e_lfanew as usize)
        as *mut IMAGE_NT_HEADERS64;
    let module_img_size = (*module_nt_headers_ptr).OptionalHeader.SizeOfImage as usize;
    let preferred_base_ptr = (*module_nt_headers_ptr).OptionalHeader.ImageBase as *mut c_void;
    let base_addr_ptr =
        allocate_rw_memory(preferred_base_ptr, module_img_size, &far_procs).unwrap();

    copy_pe(base_addr_ptr, module_base_ptr, module_nt_headers_ptr);

    /*
        3.) process the image relocations (assumes the image couldn't be loaded to the preferred base address)
    */

    let data_dir_slice = (*module_nt_headers_ptr).OptionalHeader.DataDirectory;
    let relocation_ptr: *mut IMAGE_BASE_RELOCATION = rva_mut(
        base_addr_ptr as _,
        data_dir_slice[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize,
    );

    if relocation_ptr.is_null() {
        return;
    }

    process_relocations(
        base_addr_ptr,
        module_nt_headers_ptr,
        relocation_ptr,
        &data_dir_slice,
    );

    /*
        4.) resolve the imports by patching the Import Address Table (IAT)
    */

    let import_descriptor_ptr: *mut IMAGE_IMPORT_DESCRIPTOR = rva_mut(
        base_addr_ptr as _,
        data_dir_slice[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize,
    );

    if import_descriptor_ptr.is_null() {
        return;
    }

    patch_iat(base_addr_ptr, import_descriptor_ptr, &far_procs, &flags);

    /*
        5.) finalize the sections by setting protective permissions after mapping the image
    */

    finalize_relocations(base_addr_ptr, module_nt_headers_ptr, &far_procs);

    /*
        6.) execute DllMain or user defined function depending on the flag passed into the shellcode by the generator
    */

    if flags.ufn {
        // UserFunction address = base address + RVA of user function
        let user_fn_addr = get_export_addr(base_addr_ptr as _, function_hash).unwrap();

        #[allow(non_snake_case)]
        let UserFunction = transmute::<_, UserFunction>(user_fn_addr);

        // execution with user data passed into the shellcode by the generator
        UserFunction(user_data, user_data_len);
    } else {
        let dll_main_addr = base_addr_ptr as usize
            + (*module_nt_headers_ptr).OptionalHeader.AddressOfEntryPoint as usize;

        #[allow(non_snake_case)]
        let DllMain = transmute::<_, DllMain>(dll_main_addr);

        DllMain(base_addr_ptr as _, DLL_PROCESS_ATTACH, module_base_ptr as _);
    }
}

unsafe fn get_export_ptrs(
    kernel32_base_ptr: *mut u8,
    bcrypt_base_ptr: *mut u8,
) -> Option<FarProcs> {
    let loadlib_addr = get_export_addr(kernel32_base_ptr, LOAD_LIBRARY_A).unwrap();
    let getproc_addr = get_export_addr(kernel32_base_ptr, GET_PROC_ADDRESS).unwrap();
    let virtualalloc_addr = get_export_addr(kernel32_base_ptr, VIRTUAL_ALLOC).unwrap();
    let virtualprotect_addr = get_export_addr(kernel32_base_ptr, VIRTUAL_PROTECT).unwrap();
    let flushcache_addr = get_export_addr(kernel32_base_ptr, FLUSH_INSTRUCTION_CACHE).unwrap();
    let sleep_addr = get_export_addr(kernel32_base_ptr, SLEEP).unwrap();
    let bcrypt_genrandom_addr = get_export_addr(bcrypt_base_ptr, BCRYPT_GEN_RANDOM).unwrap();

    if loadlib_addr == 0
        || getproc_addr == 0
        || virtualalloc_addr == 0
        || virtualprotect_addr == 0
        || flushcache_addr == 0
    {
        return None;
    }

    #[allow(non_snake_case)]
    let LoadLibraryA: LoadLibraryA = transmute(loadlib_addr);

    #[allow(non_snake_case)]
    let GetProcAddress: GetProcAddress = transmute(getproc_addr);

    #[allow(non_snake_case)]
    let VirtualAlloc: VirtualAlloc = transmute(virtualalloc_addr);

    #[allow(non_snake_case)]
    let VirtualProtect: VirtualProtect = transmute(virtualprotect_addr);

    #[allow(non_snake_case)]
    let FlushInstructionCache: FlushInstructionCache = transmute(flushcache_addr);

    #[allow(non_snake_case)]
    let Sleep: Sleep = transmute(sleep_addr);

    #[allow(non_snake_case)]
    let BCryptGenRandom: BCryptGenRandom = transmute(bcrypt_genrandom_addr);

    Some(FarProcs {
        LoadLibraryA,
        GetProcAddress,
        VirtualAlloc,
        VirtualProtect,
        FlushInstructionCache,
        Sleep,
        BCryptGenRandom,
    })
}

#[link_section = ".text"]
unsafe fn get_module_ptr(module_hash: u32) -> Option<*mut u8> {
    // first entry in the InMemoryOrderModuleList -> PEB, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY
    // InLoadOrderModuleList grants direct access to the base address without using CONTAINING_RECORD macro
    let peb_ptr = get_peb_ptr();
    let peb_ldr_ptr = (*peb_ptr).Ldr as *mut PEB_LDR_DATA;
    let mut table_entry_ptr =
        (*peb_ldr_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*table_entry_ptr).DllBase.is_null() {
        let name_buf_ptr = (*table_entry_ptr).BaseDllName.Buffer;
        let name_len = (*table_entry_ptr).BaseDllName.Length as usize;
        let name_slice_buf = from_raw_parts(transmute::<PWSTR, *const u8>(name_buf_ptr), name_len);

        // calculate the module hash and compare it
        if module_hash == airborne_utils::calc_hash(name_slice_buf) {
            return Some((*table_entry_ptr).DllBase as _);
        }

        table_entry_ptr = (*table_entry_ptr).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    None
}

#[link_section = ".text"]
unsafe fn get_nt_headers_ptr(module_base_ptr: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header_ptr = module_base_ptr as *mut IMAGE_DOS_HEADER;

    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers_ptr =
        (module_base_ptr as usize + (*dos_header_ptr).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    Some(nt_headers_ptr)
}

#[link_section = ".text"]
unsafe fn get_export_addr(module_base_ptr: *mut u8, function_hash: u32) -> Option<usize> {
    // NT Headers -> RVA of Export Directory Table -> function names, ordinals, and addresses
    let nt_headers_ptr = get_nt_headers_ptr(module_base_ptr).unwrap();
    let export_dir_ptr = (module_base_ptr as usize
        + (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = from_raw_parts(
        (module_base_ptr as usize + (*export_dir_ptr).AddressOfNames as usize) as *const u32,
        (*export_dir_ptr).NumberOfNames as _,
    );
    let funcs = from_raw_parts(
        (module_base_ptr as usize + (*export_dir_ptr).AddressOfFunctions as usize) as *const u32,
        (*export_dir_ptr).NumberOfFunctions as _,
    );
    let ords = from_raw_parts(
        (module_base_ptr as usize + (*export_dir_ptr).AddressOfNameOrdinals as usize) as *const u16,
        (*export_dir_ptr).NumberOfNames as _,
    );

    // compare hashes iteratively for each entry
    for i in 0..(*export_dir_ptr).NumberOfNames {
        let name_ptr = (module_base_ptr as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_ptr as _);
        let name_slice = from_raw_parts(name_ptr as _, name_len);

        if function_hash == airborne_utils::calc_hash(name_slice) {
            return Some(module_base_ptr as usize + funcs[ords[i as usize] as usize] as usize);
        }
    }

    None
}

#[link_section = ".text"]
unsafe fn allocate_rw_memory(
    preferred_base_ptr: *mut c_void,
    alloc_size: usize,
    far_procs: &FarProcs,
) -> Option<*mut c_void> {
    let mut base_addr_ptr = (far_procs.VirtualAlloc)(
        preferred_base_ptr,
        alloc_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );

    // fallback: attempt to allocate at any address if preferred address is unavailable
    if base_addr_ptr.is_null() {
        base_addr_ptr = (far_procs.VirtualAlloc)(
            null_mut(),
            alloc_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
    }

    if base_addr_ptr.is_null() {
        return None;
    }

    Some(base_addr_ptr)
}

#[link_section = ".text"]
unsafe fn copy_pe(
    new_base_ptr: *mut c_void,
    old_base_ptr: *mut u8,
    nt_headers_ptr: *mut IMAGE_NT_HEADERS64,
) {
    let section_header_ptr = (&(*nt_headers_ptr).OptionalHeader as *const _ as usize
        + (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader as usize)
        as *mut IMAGE_SECTION_HEADER;

    // PE sections one by one
    for i in 0..(*nt_headers_ptr).FileHeader.NumberOfSections {
        let header_i_ref = &*(section_header_ptr.add(i as usize));

        let dst_ptr = new_base_ptr
            .cast::<u8>()
            .add(header_i_ref.VirtualAddress as usize);
        let src_ptr = (old_base_ptr as usize + header_i_ref.PointerToRawData as usize) as *const u8;
        let raw_size = header_i_ref.SizeOfRawData as usize;

        let src_data_slice = from_raw_parts(src_ptr, raw_size);

        (0..raw_size).for_each(|x| {
            let src = src_data_slice[x];
            let dst = dst_ptr.add(x);
            *dst = src;
        });
    }

    // PE headers
    for i in 0..(*nt_headers_ptr).OptionalHeader.SizeOfHeaders {
        let dst = new_base_ptr as *mut u8;
        let src = old_base_ptr as *const u8;

        *dst.add(i as usize) = *src.add(i as usize);
    }
}

#[link_section = ".text"]
unsafe fn process_relocations(
    base_addr_ptr: *mut c_void,
    nt_headers_ptr: *mut IMAGE_NT_HEADERS64,
    mut relocation_ptr: *mut IMAGE_BASE_RELOCATION,
    data_dir_slice: &[IMAGE_DATA_DIRECTORY; 16],
) {
    let delta = base_addr_ptr as isize - (*nt_headers_ptr).OptionalHeader.ImageBase as isize;

    // upper bound prevents accessing memory past the end of the relocation data
    let relocation_end = relocation_ptr as usize
        + data_dir_slice[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;

    while (*relocation_ptr).VirtualAddress != 0
        && ((*relocation_ptr).VirtualAddress as usize) <= relocation_end
        && (*relocation_ptr).SizeOfBlock != 0
    {
        // relocation address, first entry, and number of entries in the whole block
        let addr = rva::<isize>(
            base_addr_ptr as _,
            (*relocation_ptr).VirtualAddress as usize,
        ) as isize;
        let item = rva::<u16>(relocation_ptr as _, size_of::<IMAGE_BASE_RELOCATION>());
        let count = ((*relocation_ptr).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>())
            / size_of::<u16>();

        for i in 0..count {
            // high bits -> type, low bits -> offset
            let type_field = (item.add(i).read() >> 12) as u32;
            let offset = item.add(i).read() & 0xFFF;

            match type_field {
                IMAGE_REL_BASED_DIR64 | IMAGE_REL_BASED_HIGHLOW => {
                    *((addr + offset as isize) as *mut isize) += delta;
                }
                _ => {}
            }
        }

        relocation_ptr = rva_mut(relocation_ptr as _, (*relocation_ptr).SizeOfBlock as usize);
    }
}

#[link_section = ".text"]
unsafe fn patch_iat(
    base_addr_ptr: *mut c_void,
    mut import_descriptor_ptr: *mut IMAGE_IMPORT_DESCRIPTOR,
    far_procs: &FarProcs,
    flags: &Flags,
) -> BOOL {
    /*
        1.) shuffle Import Directory Table entries (image import descriptors)
        2.) delay the relocation of each import a random duration
        3.) conditional execution based on ordinal/name
        4.) indirect function call via pointer
    */

    let mut id_ptr = import_descriptor_ptr;
    let mut import_count = 0;

    while (*id_ptr).Name != 0 {
        import_count += 1;
        id_ptr = id_ptr.add(1);
    }

    let id_ptr = import_descriptor_ptr;

    if import_count > 1 && flags.shuffle {
        // Fisher-Yates shuffle
        for i in 0..import_count - 1 {
            let rn = match get_random(far_procs) {
                Some(rn) => rn,
                None => return 0,
            };

            let gap = import_count - i;
            let j_u64 = i + (rn % gap);
            let j = j_u64.min(import_count - 1);

            id_ptr.offset(j as _).swap(id_ptr.offset(i as _));
        }
    }

    while (*import_descriptor_ptr).Name != 0x0 {
        let module_name_ptr = rva::<i8>(base_addr_ptr as _, (*import_descriptor_ptr).Name as usize);

        if module_name_ptr.is_null() {
            return 0;
        }

        let module_handle = (far_procs.LoadLibraryA)(module_name_ptr as _);

        if module_handle == 0 {
            return 0;
        }

        if flags.delay {
            // skip delay if winapi call fails
            let rn = get_random(far_procs).unwrap_or(0);
            let delay = rn % MAX_IMPORT_DELAY_MS;
            (far_procs.Sleep)(delay as _);
        }

        // RVA of the IAT via either OriginalFirstThunk or FirstThunk
        let mut original_thunk_ptr: *mut IMAGE_THUNK_DATA64 = if (base_addr_ptr as usize
            + (*import_descriptor_ptr).Anonymous.OriginalFirstThunk as usize)
            != 0
        {
            rva_mut(
                base_addr_ptr as _,
                (*import_descriptor_ptr).Anonymous.OriginalFirstThunk as usize,
            )
        } else {
            rva_mut(
                base_addr_ptr as _,
                (*import_descriptor_ptr).FirstThunk as usize,
            )
        };

        let mut thunk_ptr: *mut IMAGE_THUNK_DATA64 = rva_mut(
            base_addr_ptr as _,
            (*import_descriptor_ptr).FirstThunk as usize,
        );

        while (*original_thunk_ptr).u1.Function != 0 {
            let is_snap_res = (*original_thunk_ptr).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0;

            // check if the import is by name or by ordinal
            if is_snap_res {
                // mask out the high bits to get the ordinal value and patch the address of the function
                let fn_ord_ptr = ((*original_thunk_ptr).u1.Ordinal & 0xFFFF) as *const u8;
                (*thunk_ptr).u1.Function =
                    match (far_procs.GetProcAddress)(module_handle, fn_ord_ptr) {
                        Some(fn_addr) => fn_addr as usize as _,
                        None => return 0,
                    };
            } else {
                // get the function name from the thunk and patch the address of the function
                let thunk_data_ptr = (base_addr_ptr as usize
                    + (*original_thunk_ptr).u1.AddressOfData as usize)
                    as *mut IMAGE_IMPORT_BY_NAME;
                let fn_name_ptr = (*thunk_data_ptr).Name.as_ptr();
                (*thunk_ptr).u1.Function =
                    match (far_procs.GetProcAddress)(module_handle, fn_name_ptr) {
                        Some(fn_addr) => fn_addr as usize as _,
                        None => return 0,
                    };
            }

            thunk_ptr = thunk_ptr.add(1);
            original_thunk_ptr = original_thunk_ptr.add(1);
        }

        import_descriptor_ptr =
            (import_descriptor_ptr as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as _;
    }

    1
}

#[link_section = ".text"]
unsafe fn finalize_relocations(
    base_addr_ptr: *mut c_void,
    module_nt_headers_ptr: *mut IMAGE_NT_HEADERS64,
    far_procs: &FarProcs,
) {
    // RVA of the first IMAGE_SECTION_HEADER in the PE file
    let section_header_ptr = rva_mut::<IMAGE_SECTION_HEADER>(
        &(*module_nt_headers_ptr).OptionalHeader as *const _ as _,
        (*module_nt_headers_ptr).FileHeader.SizeOfOptionalHeader as usize,
    );

    for i in 0..(*module_nt_headers_ptr).FileHeader.NumberOfSections {
        let mut protection = 0;
        let mut old_protection = 0;

        let section_header_ptr = &*(section_header_ptr).add(i as usize);
        let dst_ptr = base_addr_ptr
            .cast::<u8>()
            .add(section_header_ptr.VirtualAddress as usize);
        let section_raw_size = section_header_ptr.SizeOfRawData as usize;

        let is_executable = section_header_ptr.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let is_readable = section_header_ptr.Characteristics & IMAGE_SCN_MEM_READ != 0;
        let is_writable = section_header_ptr.Characteristics & IMAGE_SCN_MEM_WRITE != 0;

        if !is_executable && !is_readable && !is_writable {
            protection = PAGE_NOACCESS;
        }

        if is_writable {
            protection = PAGE_WRITECOPY;
        }

        if is_readable {
            protection = PAGE_READONLY;
        }

        if is_writable && is_readable {
            protection = PAGE_READWRITE;
        }

        if is_executable {
            protection = PAGE_EXECUTE;
        }

        if is_executable && is_writable {
            protection = PAGE_EXECUTE_WRITECOPY;
        }

        if is_executable && is_readable {
            protection = PAGE_EXECUTE_READ;
        }

        if is_executable && is_writable && is_readable {
            protection = PAGE_EXECUTE_READWRITE;
        }

        // apply the new protection to the current section
        (far_procs.VirtualProtect)(
            dst_ptr as _,
            section_raw_size,
            protection,
            &mut old_protection,
        );
    }

    // flush the instruction cache to ensure the CPU sees the changes made to the memory
    (far_procs.FlushInstructionCache)(-1, null_mut(), 0);
}

#[link_section = ".text"]
unsafe fn get_random(far_procs: &FarProcs) -> Option<u64> {
    let mut buffer = [0u8; 8];
    let status = (far_procs.BCryptGenRandom)(
        BCRYPT_RNG_ALG_HANDLE,
        buffer.as_mut_ptr(),
        buffer.len() as _,
        0,
    );

    if status != STATUS_SUCCESS {
        return None;
    }

    Some(u64::from_le_bytes(buffer))
}

#[link_section = ".text"]
unsafe fn get_peb_ptr() -> *mut PEB {
    // TEB located at offset 0x30 from the GS register on 64-bit
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);

    (*teb).ProcessEnvironmentBlock as *mut PEB
}

#[link_section = ".text"]
unsafe fn get_cstr_len(str_ptr: *const char) -> usize {
    let mut tmp: u64 = str_ptr as u64;

    while *(tmp as *const u8) != 0 {
        tmp += 1;
    }

    (tmp - str_ptr as u64) as _
}

fn rva_mut<T>(base_ptr: *mut u8, offset: usize) -> *mut T {
    (base_ptr as usize + offset) as *mut T
}

fn rva<T>(base_ptr: *mut u8, offset: usize) -> *const T {
    (base_ptr as usize + offset) as *const T
}
