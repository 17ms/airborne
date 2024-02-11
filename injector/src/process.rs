use std::ffi::CStr;

use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    },
};

fn snapshot() -> isize {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if snapshot == INVALID_HANDLE_VALUE {
        panic!("failed to create snapshot");
    }

    snapshot
}

unsafe fn first_proc_entry(snapshot: isize) -> PROCESSENTRY32 {
    let mut pe: PROCESSENTRY32 = std::mem::zeroed();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as _;

    if Process32First(snapshot, &mut pe) == 0 {
        CloseHandle(snapshot);
        panic!("failed to get first process entry");
    }

    pe
}

pub unsafe fn iterate_procs(target_name: &str) -> Option<u32> {
    let snapshot = snapshot();
    let mut pe = first_proc_entry(snapshot);

    loop {
        let proc_name = CStr::from_ptr(pe.szExeFile.as_ptr() as _)
            .to_string_lossy()
            .into_owned();

        if proc_name.to_lowercase() == target_name.to_lowercase() {
            let pid = pe.th32ProcessID;
            println!("[+] {}: {}", pid, proc_name);
            CloseHandle(snapshot);

            return Some(pid);
        } else if Process32Next(snapshot, &mut pe) == 0 {
            break;
        }
    }

    println!("[-] process with name {} not found", target_name);
    CloseHandle(snapshot);

    None
}
