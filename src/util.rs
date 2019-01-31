use libc::c_void;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

pub fn read_string_max_size(pid: i32, address: u64, max_size: usize) -> String {
    let mut data = vec![0u8; max_size];
    read_data(pid, address, &mut data);
    let data = data
        .into_iter()
        .take_while(|x| *x != 0)
        .map(|x| x)
        .collect::<Vec<_>>();
    String::from_utf8(data).unwrap()
}

pub fn read_string(pid: i32, address: u64, count: usize) -> String {
    let mut data = vec![0u8; count];
    read_data(pid, address, &mut data);
    String::from_utf8(data).unwrap()
}

pub fn kill(pid: i32, signo: i32) {
    let result = unsafe { libc::kill(pid, signo) };
    assert_eq!(result, 0);
}

pub fn read_data(pid: i32, address: u64, data: &mut [u8]) -> isize {
    let local_iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    let remote_iov = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: data.len(),
    };

    unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) }
}

pub fn show_registers(regs: &libc::user_regs_struct) {
    println!(
        "R15      {:016x}    R14     {:016x}    R13    {:016x}",
        regs.r15, regs.r14, regs.r13
    );
    println!(
        "R12      {:016x}    RBP     {:016x}    RBX    {:016x}",
        regs.r12, regs.rbp, regs.rbx
    );
    println!(
        "R11      {:016x}    R10     {:016x}    R9     {:016x}",
        regs.r11, regs.r10, regs.r9
    );
    println!(
        "R8       {:016x}    RAX     {:016x}    RCX    {:016x}",
        regs.r8, regs.rax, regs.rcx
    );
    println!(
        "RDX      {:016x}    RSI     {:016x}    RDI    {:016x}",
        regs.rdx, regs.rsi, regs.rdi
    );
    println!(
        "ORIG_RAX {:016x}    RIP     {:016x}    CS     {:016x}",
        regs.orig_rax, regs.rip, regs.cs
    );
    println!(
        "EFLAGS   {:016x}    RSP     {:016x}    SS     {:016x}",
        regs.eflags, regs.rsp, regs.ss
    );
    println!(
        "FS_BASE  {:016x}    GS_BASE {:016x}    DS     {:016x}",
        regs.fs_base, regs.gs_base, regs.ds
    );
    println!(
        "ES       {:016x}    FS      {:016x}    GS     {:016x}",
        regs.es, regs.fs, regs.gs
    );
}

pub struct MemoryMap {
    pub offset: u64,
    pub size: u64,
    pub file_offset: u64,
    pub perm: String, // TODO: rwx
    pub path: String,
}

pub fn read_memory_maps(pid: libc::pid_t) -> Vec<MemoryMap> {
    let path = format!("/proc/{}/maps", pid);
    let mut maps = Vec::new();

    let f = File::open(&path).unwrap();
    let f = BufReader::new(f);

    for line in f.lines() {
        let line = line.unwrap();
        let v: Vec<&str> = line.split_whitespace().collect();

        assert!(v.len() == 5 || v.len() == 6);

        if v.len() == 6 {
            let addr: Vec<u64> = v[0]
                .split('-')
                .map(|x| u64::from_str_radix(x, 16).unwrap())
                .collect();
            assert_eq!(addr.len(), 2);

            let map = MemoryMap {
                offset: addr[0],
                size: addr[1] - addr[0],
                file_offset: u64::from_str_radix(v[2], 16).unwrap(),
                perm: v[1].to_owned(),
                path: v[5].to_owned(),
            };

            maps.push(map);
        } else if v.len() == 5 {
            // TODO(bostjan)
        }
    }

    maps
}
