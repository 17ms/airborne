use std::{error::Error, ffi::CStr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    },
};

fn snapshot() -> Result<isize, Box<dyn Error>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if snapshot == INVALID_HANDLE_VALUE {
        return Err("failed to create toolhelp snapshot".into());
    }

    Ok(snapshot)
}

unsafe fn first_proc_entry(snapshot: isize) -> Result<PROCESSENTRY32, Box<dyn Error>> {
    let mut pe: PROCESSENTRY32 = std::mem::zeroed();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as _;

    if Process32First(snapshot, &mut pe) == 0 {
        CloseHandle(snapshot);
        return Err("failed to get first process entry".into());
    }

    Ok(pe)
}

pub unsafe fn iterate_procs(target_name: &str) -> Result<Option<u32>, Box<dyn Error>> {
    let snapshot = snapshot()?;
    let mut pe = first_proc_entry(snapshot)?;

    loop {
        let proc_name = CStr::from_ptr(pe.szExeFile.as_ptr() as _)
            .to_string_lossy()
            .into_owned();

        if proc_name.to_lowercase() == target_name.to_lowercase() {
            let pid = pe.th32ProcessID;
            println!("[+] {}: {}", pid, proc_name);
            CloseHandle(snapshot);

            return Ok(Some(pid));
        }

        if Process32Next(snapshot, &mut pe) == 0 {
            break;
        }
    }

    CloseHandle(snapshot);

    Ok(None)
}
