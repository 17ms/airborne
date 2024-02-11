use std::{mem::transmute, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS},
    },
};

pub unsafe fn inject(pid: u32, dll_vec: Vec<u8>) {
    let dll_len = dll_vec.len();

    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if h_process == INVALID_HANDLE_VALUE {
        panic!("failed to open process");
    }

    let base_addr_ptr = VirtualAllocEx(
        h_process,
        null_mut(),
        dll_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if base_addr_ptr.is_null() {
        panic!("failed to allocate memory");
    }

    println!("[+] allocated memory at {:p}", base_addr_ptr);

    if WriteProcessMemory(
        h_process,
        base_addr_ptr,
        dll_vec.as_ptr() as _,
        dll_len,
        null_mut(),
    ) == 0
    {
        panic!("failed to write process memory");
    }

    let h_thread = CreateRemoteThread(
        h_process,
        null_mut(),
        0,
        Some(transmute(base_addr_ptr as usize)),
        null_mut(),
        0,
        null_mut(),
    );

    if h_thread == INVALID_HANDLE_VALUE {
        panic!("failed to create remote thread");
    }

    CloseHandle(h_thread);
    CloseHandle(h_process);
}
