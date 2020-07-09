use crate::{Pid, Registers};
use std::path::PathBuf;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::linux::{get_memory_maps, read_data, write_data};

#[cfg(target_os = "freebsd")]
pub use crate::freebsd::{get_memory_maps, read_data, write_data};

/// Memory mapping
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MemoryMap {
    /// Start address of mapping
    pub start: u64,
    /// End address of mapping (inclusive)
    pub end: u64,
    /// Offset within mapped module (`filepath`)
    pub offset: u64,
    /// Permission
    pub permissions: Permissions,
    /// Path of mapped module
    pub filepath: Option<PathBuf>,
}

impl MemoryMap {
    /// Check if a given address is within the memory mapping.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }
}

/// Memory map permissions.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Permissions {
    /// Readable
    pub read: bool,
    /// Writeable
    pub write: bool,
    /// Executable
    pub execute: bool,
    /// Copy on write
    pub copy: bool,
}

/// Read a null-terminated UTF-8 string with a length up to `max_size`.
///
/// This will read exactly `max_size` bytes starting at `address` from the specified process.  
/// Read bytes up to first `0` are converted with `String::from_utf8`.  
///
/// Function will **panic** on invalid UTF-8 string.
pub fn read_string_max_size(pid: Pid, address: usize, max_size: usize) -> nix::Result<String> {
    let mut data = vec![0u8; max_size];
    read_data(pid, address, &mut data)?;
    let len = data.iter().position(|x| *x == 0).unwrap_or(max_size);
    data.truncate(len);
    Ok(String::from_utf8(data).unwrap())
}

/// Read a `count` bytes long UTF-8 string from specified process at `address`.
///
/// Read bytes are converted with `String::from_utf8`.  
/// Function will **panic** on invalid UTF-8 string.
pub fn read_string(pid: Pid, address: usize, count: usize) -> nix::Result<String> {
    let mut data = vec![0u8; count];
    read_data(pid, address, &mut data)?;
    Ok(String::from_utf8(data).unwrap())
}

/// Print registers
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
