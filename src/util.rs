use crate::{Pid, Registers};
use std::path::PathBuf;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::linux::{get_memory_maps, read_data};

#[cfg(target_os = "freebsd")]
pub use crate::freebsd::{get_memory_maps, read_data};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemoryMap {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub permissions: Permissions,
    pub filepath: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub copy: bool,
}

pub fn read_string_max_size(pid: Pid, address: usize, max_size: usize) -> nix::Result<String> {
    let mut data = vec![0u8; max_size];
    read_data(pid, address, &mut data)?;
    let data = data
        .into_iter()
        .take_while(|x| *x != 0)
        .map(|x| x)
        .collect::<Vec<_>>();
    Ok(String::from_utf8(data).unwrap())
}

pub fn read_string(pid: Pid, address: usize, count: usize) -> nix::Result<String> {
    let mut data = vec![0u8; count];
    read_data(pid, address, &mut data)?;
    Ok(String::from_utf8(data).unwrap())
}

pub fn show_registers<R: Registers>(regs: &R) {
    println!(
        "R15      {:016x}    R14     {:016x}    R13    {:016x}",
        regs.r15(),
        regs.r14(),
        regs.r13()
    );
    println!(
        "R12      {:016x}    RBP     {:016x}    RBX    {:016x}",
        regs.r12(),
        regs.rbp(),
        regs.rbx()
    );
    println!(
        "R11      {:016x}    R10     {:016x}    R9     {:016x}",
        regs.r11(),
        regs.r10(),
        regs.r9()
    );
    println!(
        "R8       {:016x}    RAX     {:016x}    RCX    {:016x}",
        regs.r8(),
        regs.rax(),
        regs.rcx()
    );
    println!(
        "RDX      {:016x}    RSI     {:016x}    RDI    {:016x}",
        regs.rdx(),
        regs.rsi(),
        regs.rdi()
    );
    println!(
        "RIP     {:016x}    CS     {:016x}      EFLAGS   {:016x}",
        regs.rip(),
        regs.cs(),
        regs.rflags()
    );
    println!(
        "RSP     {:016x}    SS     {:016x}      DS     {:016x}",
        regs.rsp(),
        regs.ss(),
        regs.ds()
    );
    println!(
        "ES       {:016x}    FS      {:016x}    GS     {:016x}",
        regs.es(),
        regs.fs(),
        regs.gs()
    );
}
