use std::{ffi::c_void, ptr::null_mut, slice::from_raw_parts, str::from_utf8};

use windows_sys::{
    w,
    Win32::{
        Foundation::HMODULE,
        System::SystemServices::DLL_PROCESS_ATTACH,
        UI::{
            Shell::ShellExecuteW,
            WindowsAndMessaging::{MessageBoxW, MB_OK},
        },
    },
};

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(_module: HMODULE, reason: u32, _reserved: *mut u8) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        ShellExecuteW(0, w!("open"), w!("calc.exe"), null_mut(), null_mut(), 0);
    }

    true
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe fn PrintMessage(user_data_ptr: *mut c_void, user_data_len: u32) {
    let udata_slice = from_raw_parts(user_data_ptr as *const u8, user_data_len as usize);

    // TODO: switch to no_std environment, wstr can be created from u8 by utilizing udata_len as array length

    let mut user_text_wstr = from_utf8(udata_slice)
        .unwrap()
        .encode_utf16() // must be UTF-16 for MessageBoxW
        .collect::<Vec<u16>>();
    user_text_wstr.push(0); // null-termination

    MessageBoxW(0, user_text_wstr.as_ptr() as _, w!("Hello World!"), MB_OK);
}
