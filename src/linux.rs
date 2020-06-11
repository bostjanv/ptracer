use crate::{
    util::{MemoryMap, Permissions},
    Pid, Registers,
};
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
            end,
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

pub fn get_memory_maps(pid: Pid) -> ProcResult<Vec<MemoryMap>> {
    Ok(Process::new(pid.as_raw())?
        .maps()?
        .into_iter()
        .map(MemoryMap::from)
        .collect())
}

pub fn read_data(pid: Pid, address: usize, data: &mut [u8]) -> nix::Result<usize> {
    use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};

    let len = data.len();
    let local_iov = IoVec::from_mut_slice(data);
    let remote_iov = RemoteIoVec { base: address, len };

    process_vm_readv(pid, &[local_iov], &[remote_iov])
}

impl Registers for nix::libc::user_regs_struct {
    fn r15(&self) -> u64 {
        self.r15
    }
    fn r14(&self) -> u64 {
        self.r14
    }
    fn r13(&self) -> u64 {
        self.r13
    }
    fn r12(&self) -> u64 {
        self.r12
    }
    fn rbp(&self) -> u64 {
        self.rbp
    }
    fn rbx(&self) -> u64 {
        self.rbx
    }
    fn r11(&self) -> u64 {
        self.r11
    }
    fn r10(&self) -> u64 {
        self.r10
    }
    fn r9(&self) -> u64 {
        self.r9
    }
    fn r8(&self) -> u64 {
        self.r8
    }
    fn rax(&self) -> u64 {
        self.rax
    }
    fn rcx(&self) -> u64 {
        self.rcx
    }
    fn rdx(&self) -> u64 {
        self.rdx
    }
    fn rsi(&self) -> u64 {
        self.rsi
    }
    fn rdi(&self) -> u64 {
        self.rdi
    }
    fn rip(&self) -> u64 {
        self.rip
    }
    fn cs(&self) -> u64 {
        self.cs
    }
    fn rflags(&self) -> u64 {
        self.eflags
    }
    fn rsp(&self) -> u64 {
        self.rsp
    }
    fn ss(&self) -> u64 {
        self.ss
    }
    fn ds(&self) -> u64 {
        self.ds
    }
    fn es(&self) -> u64 {
        self.es
    }
    fn fs(&self) -> u64 {
        self.fs
    }
    fn gs(&self) -> u64 {
        self.gs
    }

    fn set_r15(&mut self, value: u64) {
        self.r15 = value;
    }
    fn set_r14(&mut self, value: u64) {
        self.r14 = value;
    }
    fn set_r13(&mut self, value: u64) {
        self.r13 = value;
    }
    fn set_r12(&mut self, value: u64) {
        self.r12 = value;
    }
    fn set_rbp(&mut self, value: u64) {
        self.rbp = value;
    }
    fn set_rbx(&mut self, value: u64) {
        self.rbx = value;
    }
    fn set_r11(&mut self, value: u64) {
        self.r11 = value;
    }
    fn set_r10(&mut self, value: u64) {
        self.r10 = value;
    }
    fn set_r9(&mut self, value: u64) {
        self.r9 = value;
    }
    fn set_r8(&mut self, value: u64) {
        self.r8 = value;
    }
    fn set_rax(&mut self, value: u64) {
        self.rax = value;
    }
    fn set_rcx(&mut self, value: u64) {
        self.rcx = value;
    }
    fn set_rdx(&mut self, value: u64) {
        self.rdx = value;
    }
    fn set_rsi(&mut self, value: u64) {
        self.rsi = value;
    }
    fn set_rdi(&mut self, value: u64) {
        self.rdi = value;
    }
    fn set_rip(&mut self, value: u64) {
        self.rip = value;
    }
    fn set_cs(&mut self, value: u64) {
        self.cs = value;
    }
    fn set_rflags(&mut self, value: u64) {
        self.eflags = value;
    }
    fn set_rsp(&mut self, value: u64) {
        self.rsp = value;
    }
    fn set_ss(&mut self, value: u64) {
        self.ss = value;
    }
    fn set_ds(&mut self, value: u64) {
        self.ds = value;
    }
    fn set_es(&mut self, value: u64) {
        self.es = value;
    }
    fn set_fs(&mut self, value: u64) {
        self.fs = value;
    }
    fn set_gs(&mut self, value: u64) {
        self.gs = value;
    }
}
