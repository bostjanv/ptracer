use crate::{
    util::{MemoryMap, Permissions},
    Pid, Registers,
};
use nix::sys::uio::{process_vm_readv, process_vm_writev, IoVec, RemoteIoVec};
use procfs::process::{MMapPath, MemoryMap as ProcMMap, Process};
use procfs::ProcResult;

pub type PtraceData = u64;
pub type PtraceRegisters = nix::libc::user_regs_struct;

impl From<ProcMMap> for MemoryMap {
    fn from(mmap: ProcMMap) -> Self {
        let (start, end) = mmap.address;
        let filepath = match mmap.pathname {
            MMapPath::Path(path) => Some(path),
            _ => None,
        };

        MemoryMap {
            start,
            // make end address inclusive
            end: end - 1,
            offset: mmap.offset,
            permissions: Permissions::from(mmap.perms.as_ref()),
            filepath,
        }
    }
}

impl From<&str> for Permissions {
    fn from(perms: &str) -> Self {
        let mut perm = perms.chars();
        Permissions {
            read: perm.next() == Some('r'),
            write: perm.next() == Some('w'),
            execute: perm.next() == Some('x'),
            copy: perm.next() == Some('p'),
        }
    }
}

/// Get memory mappings of process identified by `pid`.
pub fn get_memory_maps(pid: Pid) -> ProcResult<Vec<MemoryMap>> {
    Ok(Process::new(pid.as_raw())?
        .maps()?
        .into_iter()
        .map(MemoryMap::from)
        .collect())
}

/// Read data from remote process identified by `pid`.
pub fn read_data(pid: Pid, address: usize, data: &mut [u8]) -> nix::Result<usize> {
    let len = data.len();
    let local_iov = IoVec::from_mut_slice(data);
    let remote_iov = RemoteIoVec { base: address, len };

    process_vm_readv(pid, &[local_iov], &[remote_iov])
}

/// Write data to remote process identified by `pid`.
pub fn write_data(pid: Pid, address: usize, data: &[u8]) -> nix::Result<usize> {
    let len = data.len();
    let local_iov = IoVec::from_slice(data);
    let remote_iov = RemoteIoVec { base: address, len };

    process_vm_writev(pid, &[local_iov], &[remote_iov])
}

impl Registers for nix::libc::user_regs_struct {
    #[inline]
    fn r15(&self) -> u64 {
        self.r15
    }
    #[inline]
    fn r14(&self) -> u64 {
        self.r14
    }
    #[inline]
    fn r13(&self) -> u64 {
        self.r13
    }
    #[inline]
    fn r12(&self) -> u64 {
        self.r12
    }
    #[inline]
    fn rbp(&self) -> u64 {
        self.rbp
    }
    #[inline]
    fn rbx(&self) -> u64 {
        self.rbx
    }
    #[inline]
    fn r11(&self) -> u64 {
        self.r11
    }
    #[inline]
    fn r10(&self) -> u64 {
        self.r10
    }
    #[inline]
    fn r9(&self) -> u64 {
        self.r9
    }
    #[inline]
    fn r8(&self) -> u64 {
        self.r8
    }
    #[inline]
    fn rax(&self) -> u64 {
        self.rax
    }
    #[inline]
    fn rcx(&self) -> u64 {
        self.rcx
    }
    #[inline]
    fn rdx(&self) -> u64 {
        self.rdx
    }
    #[inline]
    fn rsi(&self) -> u64 {
        self.rsi
    }
    #[inline]
    fn rdi(&self) -> u64 {
        self.rdi
    }
    #[inline]
    fn rip(&self) -> u64 {
        self.rip
    }
    #[inline]
    fn cs(&self) -> u64 {
        self.cs
    }
    #[inline]
    fn rflags(&self) -> u64 {
        self.eflags
    }
    #[inline]
    fn rsp(&self) -> u64 {
        self.rsp
    }
    #[inline]
    fn ss(&self) -> u64 {
        self.ss
    }
    #[inline]
    fn ds(&self) -> u64 {
        self.ds
    }
    #[inline]
    fn es(&self) -> u64 {
        self.es
    }
    #[inline]
    fn fs(&self) -> u64 {
        self.fs
    }
    #[inline]
    fn gs(&self) -> u64 {
        self.gs
    }

    #[inline]
    fn set_r15(&mut self, value: u64) {
        self.r15 = value;
    }
    #[inline]
    fn set_r14(&mut self, value: u64) {
        self.r14 = value;
    }
    #[inline]
    fn set_r13(&mut self, value: u64) {
        self.r13 = value;
    }
    #[inline]
    fn set_r12(&mut self, value: u64) {
        self.r12 = value;
    }
    #[inline]
    fn set_rbp(&mut self, value: u64) {
        self.rbp = value;
    }
    #[inline]
    fn set_rbx(&mut self, value: u64) {
        self.rbx = value;
    }
    #[inline]
    fn set_r11(&mut self, value: u64) {
        self.r11 = value;
    }
    #[inline]
    fn set_r10(&mut self, value: u64) {
        self.r10 = value;
    }
    #[inline]
    fn set_r9(&mut self, value: u64) {
        self.r9 = value;
    }
    #[inline]
    fn set_r8(&mut self, value: u64) {
        self.r8 = value;
    }
    #[inline]
    fn set_rax(&mut self, value: u64) {
        self.rax = value;
    }
    #[inline]
    fn set_rcx(&mut self, value: u64) {
        self.rcx = value;
    }
    #[inline]
    fn set_rdx(&mut self, value: u64) {
        self.rdx = value;
    }
    #[inline]
    fn set_rsi(&mut self, value: u64) {
        self.rsi = value;
    }
    #[inline]
    fn set_rdi(&mut self, value: u64) {
        self.rdi = value;
    }
    #[inline]
    fn set_rip(&mut self, value: u64) {
        self.rip = value;
    }
    #[inline]
    fn set_cs(&mut self, value: u64) {
        self.cs = value;
    }
    #[inline]
    fn set_rflags(&mut self, value: u64) {
        self.eflags = value;
    }
    #[inline]
    fn set_rsp(&mut self, value: u64) {
        self.rsp = value;
    }
    #[inline]
    fn set_ss(&mut self, value: u64) {
        self.ss = value;
    }
    #[inline]
    fn set_ds(&mut self, value: u64) {
        self.ds = value;
    }
    #[inline]
    fn set_es(&mut self, value: u64) {
        self.es = value;
    }
    #[inline]
    fn set_fs(&mut self, value: u64) {
        self.fs = value;
    }
    #[inline]
    fn set_gs(&mut self, value: u64) {
        self.gs = value;
    }
}
