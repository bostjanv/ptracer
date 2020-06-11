use crate::{
    util::{MemoryMap, Permissions},
    Registers,
};
use log::debug;
use nix::libc::{c_char, c_int, c_long, c_void, pid_t, ptrace, size_t, reg};
use nix::libc::{PT_GETREGS, PT_IO, PT_SETREGS, PT_SYSCALL, PT_VM_ENTRY};
use nix::sys::ptrace::{AddressType, RequestType};
use nix::{errno::Errno, sys::signal::Signal, unistd::Pid, Result};
use std::os::unix::ffi::OsStrExt;
use std::{cmp, ffi::OsStr, mem, ptr};

pub type PtraceData = u32;
pub type PtraceRegisters = reg;

const PIOD_READ_D: c_int = 1;

impl Registers for reg {
    fn r15(&self) -> u64 {
        self.r_r15 as _
    }
    fn r14(&self) -> u64 {
        self.r_r14 as _
    }
    fn r13(&self) -> u64 {
        self.r_r13 as _
    }
    fn r12(&self) -> u64 {
        self.r_r12 as _
    }
    fn rbp(&self) -> u64 {
        self.r_rbp as _
    }
    fn rbx(&self) -> u64 {
        self.r_rbx as _
    }
    fn r11(&self) -> u64 {
        self.r_r11 as _
    }
    fn r10(&self) -> u64 {
        self.r_r10 as _
    }
    fn r9(&self) -> u64 {
        self.r_r9 as _
    }
    fn r8(&self) -> u64 {
        self.r_r8 as _
    }
    fn rax(&self) -> u64 {
        self.r_rax as _
    }
    fn rcx(&self) -> u64 {
        self.r_rcx as _
    }
    fn rdx(&self) -> u64 {
        self.r_rdx as _
    }
    fn rsi(&self) -> u64 {
        self.r_rsi as _
    }
    fn rdi(&self) -> u64 {
        self.r_rdi as _
    }
    fn rip(&self) -> u64 {
        self.r_rip as _
    }
    fn cs(&self) -> u64 {
        self.r_cs as _
    }
    fn rflags(&self) -> u64 {
        self.r_rflags as _
    }
    fn rsp(&self) -> u64 {
        self.r_rsp as _
    }
    fn ss(&self) -> u64 {
        self.r_ss as _
    }
    fn ds(&self) -> u64 {
        self.r_ds as _
    }
    fn es(&self) -> u64 {
        self.r_es as _
    }
    fn fs(&self) -> u64 {
        self.r_fs as _
    }
    fn gs(&self) -> u64 {
        self.r_gs as _
    }

    fn set_r15(&mut self, value: u64) {
        self.r_r15 = value as _;
    }
    fn set_r14(&mut self, value: u64) {
        self.r_r14 = value as _;
    }
    fn set_r13(&mut self, value: u64) {
        self.r_r13 = value as _;
    }
    fn set_r12(&mut self, value: u64) {
        self.r_r12 = value as _;
    }
    fn set_rbp(&mut self, value: u64) {
        self.r_rbp = value as _;
    }
    fn set_rbx(&mut self, value: u64) {
        self.r_rbx = value as _;
    }
    fn set_r11(&mut self, value: u64) {
        self.r_r11 = value as _;
    }
    fn set_r10(&mut self, value: u64) {
        self.r_r10 = value as _;
    }
    fn set_r9(&mut self, value: u64) {
        self.r_r9 = value as _;
    }
    fn set_r8(&mut self, value: u64) {
        self.r_r8 = value as _;
    }
    fn set_rax(&mut self, value: u64) {
        self.r_rax = value as _;
    }
    fn set_rcx(&mut self, value: u64) {
        self.r_rcx = value as _;
    }
    fn set_rdx(&mut self, value: u64) {
        self.r_rdx = value as _;
    }
    fn set_rsi(&mut self, value: u64) {
        self.r_rsi = value as _;
    }
    fn set_rdi(&mut self, value: u64) {
        self.r_rdi = value as _;
    }
    fn set_rip(&mut self, value: u64) {
        self.r_rip = value as _;
    }
    fn set_cs(&mut self, value: u64) {
        self.r_cs = value as _;
    }
    fn set_rflags(&mut self, value: u64) {
        self.r_rflags = value as _;
    }
    fn set_rsp(&mut self, value: u64) {
        self.r_rsp = value as _;
    }
    fn set_ss(&mut self, value: u64) {
        self.r_ss = value as _;
    }
    fn set_ds(&mut self, value: u64) {
        self.r_ds = value as _;
    }
    fn set_es(&mut self, value: u64) {
        self.r_es = value as _;
    }
    fn set_fs(&mut self, value: u64) {
        self.r_fs = value as _;
    }
    fn set_gs(&mut self, value: u64) {
        self.r_gs = value as _;
    }
}

pub fn syscall<T: Into<Option<Signal>>>(pid: Pid, sig: T) -> Result<()> {
    let data = match sig.into() {
        Some(s) => s as c_int,
        None => 0,
    };
    let res = unsafe {
        // Ignore the useless return value
        ptrace(PT_SYSCALL, pid_t::from(pid), 1 as AddressType, data)
    };
    Errno::result(res).map(drop)
}

/// Get user registers, as with `ptrace(PT_GETREGS, ...)`
pub fn getregs(pid: Pid) -> Result<reg> {
    let mut data = mem::MaybeUninit::uninit();
    let res = unsafe {
        ptrace(
            PT_GETREGS as RequestType,
            pid_t::from(pid),
            data.as_mut_ptr() as *mut _,
            0,
        )
    };
    Errno::result(res)?;
    Ok(unsafe { data.assume_init() })
}

/// Set user registers, as with `ptrace(PT_SETREGS, ...)`
pub fn setregs(pid: Pid, regs: reg) -> Result<()> {
    let res = unsafe {
        ptrace(
            PT_SETREGS as RequestType,
            pid_t::from(pid),
            &regs as *const _ as *mut _,
            0,
        )
    };
    Errno::result(res).map(drop)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ptrace_io_desc {
    /// I/O operation
    pub piod_op: c_int,
    /// child offset
    pub piod_offs: *mut c_void,
    /// parent offset
    pub piod_addr: *mut c_void,
    /// request length
    pub piod_len: size_t,
}

pub fn read_data(pid: Pid, address: usize, data: &mut [u8]) -> nix::Result<usize> {
    let io_desc = ptrace_io_desc {
        piod_op: PIOD_READ_D,
        piod_offs: address as *mut _,
        piod_addr: data.as_mut_ptr() as *mut _,
        piod_len: data.len() as _,
    };
    log::trace!("io_desc = {:#?}", io_desc);
    let res = unsafe {
        ptrace(
            PT_IO as RequestType,
            pid_t::from(pid),
            &io_desc as *const _ as *mut _,
            0,
        )
    };
    log::trace!("io_desc = {:#?}", io_desc);
    log::trace!("res = {:#?}", res);
    Errno::result(res).map(|_| io_desc.piod_len as usize)
}

// NOTE: ptrace read is broken for some reason, emulate it with io read
pub fn read(pid: Pid, address: AddressType) -> nix::Result<c_int> {
    let mut data = [0u8; 4];
    let size = read_data(pid, address as _, &mut data)?;
    debug_assert_eq!(size, 4);

    Ok(c_int::from_le_bytes(data))
}

const FILE_NAME_BUFFER_LENGTH: usize = 4096;

pub const VM_PROT_READ: i32 = 0x01;
pub const VM_PROT_WRITE: i32 = 0x02;
pub const VM_PROT_EXECUTE: i32 = 0x04;
pub const VM_PROT_COPY: i32 = 0x08;

#[repr(C)]
#[derive(Debug)]
pub struct vm_entry {
    pub pve_entry: c_int,
    pub pve_timestamp: c_int,
    pub pve_start: c_long,
    pub pve_end: c_long,
    pub pve_offset: c_long,
    pub pve_prot: c_int,
    pub pve_pathlen: c_int,
    pub pve_fileid: c_long,
    pub pve_fsid: u32,
    pub pve_path: *const c_char,
}

impl Default for vm_entry {
    fn default() -> Self {
        Self {
            pve_entry: 0,
            pve_timestamp: 0,
            pve_start: 0,
            pve_end: 0,
            pve_offset: 0,
            pve_prot: 0,
            pve_pathlen: 0,
            pve_fileid: 0,
            pve_fsid: 0,
            pve_path: ptr::null(),
        }
    }
}

/// Read virtual memory entry with `ptrace(PT_VM_ENTRY, ...)`
pub fn read_vm_entry(pid: pid_t, vm_entry: &vm_entry) -> nix::Result<()> {
    let res = unsafe { ptrace(PT_VM_ENTRY, pid, vm_entry as *const _ as *mut _, 0) };
    Errno::result(res).map(drop)
}

impl MemoryMap {
    fn from_vm_entry(entry: &vm_entry, pve_path: &[u8]) -> Self {
        let pve_path = OsStr::from_bytes(pve_path);
        let filepath = if pve_path.len() > 0 {
            Some(pve_path.into())
        } else {
            None
        };

        MemoryMap {
            start: entry.pve_start as u64,
            end: entry.pve_end as u64,
            offset: entry.pve_offset as u64,
            permissions: Permissions::from(entry.pve_prot),
            filepath,
        }
    }
}

impl From<c_int> for Permissions {
    fn from(protection: c_int) -> Self {
        Permissions {
            read: protection & VM_PROT_READ != 0,
            write: protection & VM_PROT_WRITE != 0,
            execute: protection & VM_PROT_EXECUTE != 0,
            copy: protection & VM_PROT_COPY != 0,
        }
    }
}

pub fn get_memory_maps(pid: Pid) -> nix::Result<Vec<MemoryMap>> {
    // By setting pve_pathlen to a non-zero value on entry,
    // the pathname of the backing object is returned in the buffer pointed to by pve_path,
    // provided the entry is backed by a vnode.
    let mut pve_path: Vec<u8> = vec![0; FILE_NAME_BUFFER_LENGTH];
    let path_ptr = pve_path.as_mut_ptr();
    let mut entry = vm_entry::default();
    let mut mmaps = vec![];

    loop {
        // reset path ptr and len
        entry.pve_path = path_ptr as *const _;
        entry.pve_pathlen = FILE_NAME_BUFFER_LENGTH as _;

        match read_vm_entry(pid.as_raw(), &entry) {
            Ok(_) => {
                log::trace!("entry = {:#?}", entry);

                // The pve_pathlen field is updated with the actual length of the pathname
                // (including the terminating null character).
                mem::forget(pve_path);
                pve_path = unsafe {
                    Vec::from_raw_parts(
                        path_ptr,
                        cmp::max(0, entry.pve_pathlen - 1) as usize,
                        FILE_NAME_BUFFER_LENGTH,
                    )
                };

                mmaps.push(MemoryMap::from_vm_entry(&entry, &pve_path));
            }
            Err(e) => {
                debug!("read_vm_entry error: {:#x?}", e);
                break;
            }
        }
    }

    Ok(mmaps)
}
