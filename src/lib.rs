//! A debugger library utilizing `ptrace`-syscall.  
//!
//! Supported platforms: linux x86_64 and freebsd x86_64.  
//! *WARNING*: Only one concurrent instance of `Ptracer` is currently supported!  
//!
//! This library is still in early development.  
//! There may still be edge cases where things will break.  
//!
//! See examples for possible usage.

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::path::Path;

use log::{debug, error, trace, warn};
use nix::sys::{ptrace, signal::Signal, wait::WaitStatus};
use nix::unistd::Pid;

pub use nix;
pub mod util;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        use nix::sys::ptrace::syscall;
        pub use nix::sys::ptrace::{write, getevent, getregs, getsiginfo, read, setregs, setsiginfo};
        pub use linux::{PtraceRegisters, PtraceData};
        pub use procfs;

        const ADDR_NO_RANDOMIZE: nix::libc::c_ulong = 0x0040000;
    } else if #[cfg(target_os = "freebsd")] {
        mod freebsd;
        pub use nix::sys::ptrace::{syscall, write};
        pub use freebsd::{getregs, read, setregs};
        pub use freebsd::{PtraceRegisters, PtraceData};
    }
}

/// Ptrace wraps `ptrace` syscalls to enable writing an debugger.
///
/// *WARNING*: Only one concurrent instance is currently supported!
pub struct Ptracer {
    pid: Pid,
    registers: PtraceRegisters,
    threads: HashMap<Pid, ThreadState>,
    event: WaitStatus,
    breakpoints: HashMap<ptrace::AddressType, Breakpoint>,
}

impl Ptracer {
    /// Spawn a new debugee.
    ///
    /// Set ptrace options for exec/fork/exit variants.  
    /// Disable ASLR (linux only).  
    ///
    /// *WARNING*: Only one concurrent instance is currently supported!
    pub fn spawn(path: &Path, args: &[String]) -> nix::Result<Self> {
        let pid = spawn(path.to_str().unwrap(), args)?;

        let event = wait()?;
        debug!("Process (PID={}) spawned: {:?}", pid, event);
        assert_eq!(event.pid(), Some(pid));

        #[cfg(any(target_os = "android", target_os = "linux"))]
        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_EXITKILL
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACEVFORKDONE,
        )?;
        let registers = getregs(pid)?;

        let mut threads = HashMap::new();
        threads.insert(pid, ThreadState::Running);

        Ok(Self {
            pid,
            event,
            breakpoints: HashMap::new(),
            registers,
            threads,
        })
    }

    /// Insert a new breakpoint.
    ///
    /// If breakpoint exists, do nothing.
    pub fn insert_breakpoint(&mut self, address: usize) -> nix::Result<()> {
        if !self
            .breakpoints
            .contains_key(&(address as ptrace::AddressType))
        {
            let data = insert_breakpoint(self.pid, address as ptrace::AddressType)?;
            let breakpoint = Breakpoint {
                address: address as ptrace::AddressType,
                data,
                enabled: true,
            };
            self.breakpoints
                .insert(address as ptrace::AddressType, breakpoint);
        }

        Ok(())
    }

    /// Enable a breakpoint.
    ///
    /// If breakpoint does not exists, do nothing.  
    /// If breakpoint is enabled, do nothing.
    pub fn enable_breakpoint(&mut self, address: usize) -> nix::Result<()> {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&(address as ptrace::AddressType)) {
            if !bp.enabled {
                insert_breakpoint(self.pid, address as ptrace::AddressType)?;
                bp.enabled = true;
            }
        }

        Ok(())
    }

    /// Disable a breakpoint.
    ///
    /// If breakpoint does not exists, do nothing.  
    /// If breakpoint is disabled, do nothing.
    pub fn disable_breakpoint(&mut self, address: usize) -> nix::Result<()> {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&(address as ptrace::AddressType)) {
            if bp.enabled {
                remove_breakpoint(self.pid, address as ptrace::AddressType, bp.data)?;
                bp.enabled = false;
            }
        }

        Ok(())
    }

    /// Remove a breakpoint.
    ///
    /// If breakpoint does not exists, do nothing.
    pub fn remove_breakpoint(&mut self, address: usize) -> nix::Result<()> {
        if let Some(ref b) = self.breakpoints.get(&(address as ptrace::AddressType)) {
            debug!("Removing breakpoint @ RIP={:016x}", address);
            remove_breakpoint(self.pid, address as ptrace::AddressType, b.data)?;
        }

        Ok(())
    }

    /// Continue debugee, see `cont_aux` for details.
    pub fn cont(&mut self, how: ContinueMode) -> nix::Result<()> {
        if self.cont_aux(how, PtraceRequest::Cont)? {
            while self.cont_aux(ContinueMode::Default, PtraceRequest::Cont)? {}
        }

        Ok(())
    }

    /// Singlestep debugee, see `cont_aux` for details.
    pub fn step(&mut self, how: ContinueMode) -> nix::Result<()> {
        if self.cont_aux(how, PtraceRequest::Step)? {
            while self.cont_aux(ContinueMode::Default, PtraceRequest::Step)? {}
        }

        Ok(())
    }

    /// Run until syscall, see `cont_aux` for details.
    pub fn syscall(&mut self, how: ContinueMode) -> nix::Result<()> {
        if self.cont_aux(how, PtraceRequest::Syscall)? {
            while self.cont_aux(ContinueMode::Default, PtraceRequest::Syscall)? {}
        }

        Ok(())
    }

    /// Handle the `ptrace_request` with given `ContinueMode`.
    ///
    /// Returns `true` when more `ptrace` events need to be handled.
    fn cont_aux(&mut self, how: ContinueMode, ptrace_request: PtraceRequest) -> nix::Result<bool> {
        let event = self.event;
        let is_stopped = match event {
            WaitStatus::Exited(_, _) => false,
            WaitStatus::Signaled(_, _, _) => false,
            WaitStatus::Stopped(pid, signal) => {
                let mut is_stopped = true;

                if signal == Signal::SIGTRAP {
                    let pc = self.registers.rip() as ptrace::AddressType;
                    trace!(
                        "Thread (PID={}) received SIGTRAP @ RIP={:016x}",
                        pid,
                        pc as usize
                    );

                    if let Some(bp) = self.breakpoints.get(&pc) {
                        if bp.enabled {
                            if !is_breakpoint_enabled(pid, pc)? {
                                // Reinsert breakpoint
                                debug!("Thread (PID={}) single stepping @ RIP={:016x?}", pid, pc);
                                ptrace::step(pid, None)?;
                                is_stopped = false;

                                match self.threads.get_mut(&pid) {
                                    Some(thread_state) => {
                                        *thread_state = ThreadState::SingleStepping(pc)
                                    }
                                    None => warn!("Thread (PID={}) not found", pid),
                                }
                            } else {
                                debug!(
                                    "Thread (PID={}) hit enabled breakpoint @ RIP={:016x?}",
                                    pid, pc
                                );
                            }
                        }
                    }
                }

                is_stopped
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceEvent(_, _, _) => true,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceSyscall(_) => true,
            WaitStatus::Continued(_) => false,
            WaitStatus::StillAlive => false,
        };
        trace!("Thread (PID={:?}) is_stopped={}", event.pid(), is_stopped);

        if is_stopped {
            // only `WaitStatus::StillAlive` has no pid, `.unwrap()` should be safe here
            let pid = event.pid().unwrap();
            let signal = match how {
                ContinueMode::NoSignal => None,
                ContinueMode::WithSignal(signal) => Some(signal),
                ContinueMode::Default => {
                    let signal = match event {
                        WaitStatus::Signaled(_, signal, _) => Some(signal),
                        WaitStatus::Stopped(_, signal) => Some(signal),
                        #[cfg(any(target_os = "android", target_os = "linux"))]
                        WaitStatus::PtraceEvent(_, signal, _) => Some(signal),
                        _ => None,
                    };

                    match signal {
                        Some(signal) => match signal {
                            Signal::SIGTRAP | Signal::SIGSTOP => None,
                            signal => Some(signal),
                        },
                        None => None,
                    }
                }
            };

            trace!(
                "Thread (PID={}) ptrace_request={:?}, continue signal={:?}",
                pid,
                ptrace_request,
                signal
            );
            match ptrace_request {
                PtraceRequest::Cont => ptrace::cont(pid, signal)?,
                PtraceRequest::Step => ptrace::step(pid, signal)?,
                PtraceRequest::Syscall => syscall(pid, signal)?,
            }
        }

        let event = wait()?;
        self.event = event;
        debug!(
            "Thread (PID={:?}) received ptrace event={:?}",
            event.pid(),
            event
        );

        let pid = match event {
            WaitStatus::StillAlive => return Ok(true),
            // only `WaitStatus::StillAlive` has no pid, `.unwrap()` should be safe here
            event => event.pid().unwrap(),
        };

        match event {
            WaitStatus::Stopped(_, _) => {
                self.registers = getregs(pid)?;
                trace!("Thread (PID={}) registers={:#018x?}", pid, self.registers);
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceEvent(_, _, _) | WaitStatus::PtraceSyscall(_) => {
                self.registers = getregs(pid)?;
                trace!("Thread (PID={}) registers={:#018x?}", pid, self.registers);
            }
            _ => {}
        }

        match event {
            WaitStatus::Exited(_, code) => {
                debug!("Thread (PID={}) exited with return code {}", pid, code);
                match self.threads.remove(&pid) {
                    None => warn!("Thread (PID={}) could not be removed", pid),
                    _ => {}
                };
            }
            WaitStatus::Signaled(_, signal, _) => {
                debug!("Thread (PID={}) exited with signal {}", pid, signal);
                match self.threads.remove(&pid) {
                    None => warn!("Thread (PID={}) could not be removed", pid),
                    _ => {}
                };
            }
            WaitStatus::Stopped(_, _) => {
                trace!("Thread (PID={}) processing WaitStatus::Stopped", pid);
                match self.threads.get_mut(&pid) {
                    Some(thread_state) => {
                        match *thread_state {
                            ThreadState::SingleStepping(pc) => {
                                trace!("Thread (PID={}) single stepping @ RIP={:016x?}", pid, pc);
                                if let Some(bp) = self.breakpoints.get(&pc) {
                                    if bp.enabled {
                                        debug!(
                                            "Thread (PID={}) reinserting breakpoint @ RIP={:016x?}",
                                            pid, pc
                                        );
                                        insert_breakpoint(pid, pc)?;
                                    }
                                } else {
                                    error!(
                                        "Thread (PID={}) breakpoint @ RIP={:016x?} not found",
                                        pid, pc
                                    );
                                    unreachable!();
                                }

                                *thread_state = ThreadState::Running;

                                if ptrace_request != PtraceRequest::Step {
                                    return Ok(true);
                                }
                            }

                            ThreadState::Running => {
                                // Breakpoint reached
                                let pc = (self.registers.rip() - 1) as ptrace::AddressType;
                                trace!("Thread (PID={}) running @ RIP={:016x?}", pid, pc);

                                if let Some(bp) = self.breakpoints.get(&pc) {
                                    debug!(
                                        "Thread (PID={}) removing breakpoint @ RIP={:016x?}",
                                        pid, bp.address
                                    );
                                    self.registers.set_rip(pc as _);

                                    remove_breakpoint(pid, bp.address, bp.data)?;
                                    /*
                                    TODO: only set RIP
                                    ptrace::write(
                                        pid,
                                        nix::libc::RIP as *mut c_void,
                                        pc as *mut c_void,
                                    )?;
                                    */
                                    setregs(pid, self.registers)?;
                                } else {
                                    warn!(
                                        "Thread (PID={}) breakpoint @ RIP={:016x?} not found",
                                        pid,
                                        self.registers.rip()
                                    );
                                }
                            }

                            ThreadState::SyscallEnter | ThreadState::SyscallExit => {
                                trace!("Thread (PID={}) state={:?}", pid, thread_state);
                                *thread_state = ThreadState::Running;
                            }
                        }
                    }
                    None => warn!("Thread (PID={}) not found", pid),
                }
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceEvent(_, _, pevent) => {
                if pevent == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    let new_pid = ptrace::getevent(pid)?;
                    debug!("Thread (PID={}) cloned (new PID={})", pid, new_pid);
                    self.threads
                        .insert(Pid::from_raw(new_pid as i32), ThreadState::Running);
                } else if pevent == ptrace::Event::PTRACE_EVENT_FORK as i32
                    || pevent == ptrace::Event::PTRACE_EVENT_VFORK as i32
                    || pevent == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i32
                {
                    let new_pid = ptrace::getevent(pid)?;
                    debug!("Thread (PID={}) (v)forked with (new PID={})", pid, new_pid);
                    self.threads
                        .insert(Pid::from_raw(new_pid as i32), ThreadState::Running);
                } else if pevent == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    debug!("Thread (PID={}) called exec", pid);
                } else if pevent == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                    debug!("Thread (PID={}) called exit", pid);
                } else if pevent == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
                    debug!("Thread (PID={}) triggered seccomp", pid);
                    match self.threads.get_mut(&pid) {
                        Some(thread_state) => *thread_state = ThreadState::SyscallExit,
                        None => warn!("Thread (PID={}) not found", pid),
                    }
                } else {
                    warn!(
                        "Thread (PID={}) received unknown ptrace event: {}",
                        pid, pevent
                    );
                }
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceSyscall(_) => {
                trace!("Thread (PID={}) processing WaitStatus::PtraceSyscall", pid);
                assert_eq!(ptrace_request, PtraceRequest::Syscall);
                match self.threads.get_mut(&pid) {
                    Some(thread_state) => {
                        *thread_state = match thread_state {
                            ThreadState::SyscallEnter => ThreadState::SyscallExit,
                            _ => ThreadState::SyscallEnter,
                        }
                    }
                    None => warn!("Thread (PID={}) not found", pid),
                }
            }
            WaitStatus::Continued(_) => {
                trace!("Thread (PID={}) processing WaitStatus::Continued", pid);
            }
            WaitStatus::StillAlive => {
                trace!("Thread (PID={}) processing WaitStatus::StillAlive", pid);
                return Ok(true);
            }
        };

        Ok(false)
    }

    /// Detach from debugee.
    ///
    /// All breakpoints are removed before detach.
    pub fn detach(&self, signal: Option<Signal>) -> nix::Result<()> {
        match self.event {
            WaitStatus::Exited(_, _) => return Ok(()),
            _ => {}
        }

        // Remove breakpoints
        for (address, breakpoint) in &self.breakpoints {
            debug!("Removing breakpoint @ RIP={:016x?}", address);
            remove_breakpoint(self.pid, *address, breakpoint.data)?;
        }

        ptrace::detach(self.pid, signal)
    }

    /// Return the debugee pid.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Return the latest register state.
    pub fn registers(&self) -> &PtraceRegisters {
        &self.registers
    }

    /// Return the debugee threads.
    pub fn threads(&self) -> &HashMap<Pid, ThreadState> {
        &self.threads
    }

    /// Return the latest event.
    pub fn event(&self) -> &WaitStatus {
        &self.event
    }

    /// Return all breakpoints.
    pub fn breakpoints(&self) -> &HashMap<ptrace::AddressType, Breakpoint> {
        &self.breakpoints
    }
}

impl fmt::Debug for Ptracer {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Breakpoint")
            .field("pid", &self.pid)
            .field("registers", &self.registers)
            .field("threads", &self.threads)
            .field("event", &self.event)
            .field("breakpoints", &self.breakpoints)
            .finish()
    }
}

/// Spawn a new process.
///
/// Disable ASLR (linux only).
fn spawn(path: &str, args: &[String]) -> nix::Result<Pid> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    use nix::libc::personality;
    use nix::unistd::{execv, fork, ForkResult};

    let path = CString::new(path).expect("CString::new failed");

    let args = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap())
        .collect::<Vec<_>>();
    let mut args = args.iter().map(|arg| arg.as_c_str()).collect::<Vec<_>>();
    args.insert(0, path.as_c_str());

    match fork() {
        Ok(ForkResult::Parent { child, .. }) => Ok(child),
        Ok(ForkResult::Child) => {
            ptrace::traceme()?;
            #[cfg(any(target_os = "android", target_os = "linux"))]
            unsafe {
                personality(ADDR_NO_RANDOMIZE);
            }
            execv(&path, &args)?;
            unreachable!();
        }
        Err(err) => Err(err),
    }
}

/// Wait for (any) child
fn wait() -> nix::Result<WaitStatus> {
    use nix::sys::wait::{waitpid, WaitPidFlag};
    #[cfg(any(target_os = "android", target_os = "linux", target_os = "redox"))]
    return waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL));

    #[cfg(target_os = "freebsd")]
    return waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WUNTRACED));
}

/// Breakpoint
pub struct Breakpoint {
    /// Address
    address: ptrace::AddressType,
    /// Original data
    data: PtraceData,
    /// Enabled
    enabled: bool,
}

impl Breakpoint {
    /// Address of breakpoint
    pub fn address(&self) -> usize {
        self.address as usize
    }

    /// Breakpoint enabled status
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

impl fmt::Debug for Breakpoint {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Breakpoint")
            .field("address", &self.address)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Insert `int3` instruction
fn insert_breakpoint(pid: Pid, address: ptrace::AddressType) -> nix::Result<PtraceData> {
    let data = read(pid, address)? as PtraceData;
    let new_data = (data & !0xff) | 0xcc;
    write(pid, address, new_data as _)?;
    Ok(data)
}

/// Restore original byte
fn remove_breakpoint(
    pid: Pid,
    address: ptrace::AddressType,
    orig_data: PtraceData,
) -> nix::Result<()> {
    let data = read(pid, address)? as PtraceData;
    let new_data = (data & !0xff) | (orig_data & 0xff);
    write(pid, address, new_data as _)
}

/// Check if `int3` instruction is present
fn is_breakpoint_enabled(pid: Pid, address: ptrace::AddressType) -> nix::Result<bool> {
    let data = read(pid, address)? as u64;
    let enabled = (data & 0xff) == 0xcc;
    Ok(enabled)
}

/// Ptrace request
#[derive(Debug, PartialEq, Copy, Clone)]
enum PtraceRequest {
    /// Continue
    Cont,
    /// Singlestep
    Step,
    /// Syscall
    Syscall,
}

/// Debugee continue mode
#[derive(Debug)]
pub enum ContinueMode {
    /// Received signals will be forwarded to debugee, except `SIGTRAP` and `SIGSTOP`.
    Default,
    /// Don't forward any signal to debugee.
    NoSignal,
    /// Send given signal to debugee.
    WithSignal(Signal),
}

/// Thread state
#[derive(Debug, PartialEq)]
pub enum ThreadState {
    /// Thread is currently running.
    Running,
    /// Thread is currently single stepping on `pc`.
    ///
    /// This is used to temporarily remove breakpoints and execute the instruction at the breakpoint.
    SingleStepping(ptrace::AddressType),
    /// Thread is entering a syscall
    SyscallEnter,
    /// Thread has exited a syscall
    SyscallExit,
}

/// Abstraction trait for x86_64 registers.
///
/// Platforms differ in naming and availablity of registers.
/// This trait is implemented on register structs to unify them.
pub trait Registers {
    fn r15(&self) -> u64;
    fn r14(&self) -> u64;
    fn r13(&self) -> u64;
    fn r12(&self) -> u64;
    fn rbp(&self) -> u64;
    fn rbx(&self) -> u64;
    fn r11(&self) -> u64;
    fn r10(&self) -> u64;
    fn r9(&self) -> u64;
    fn r8(&self) -> u64;
    fn rax(&self) -> u64;
    fn rcx(&self) -> u64;
    fn rdx(&self) -> u64;
    fn rsi(&self) -> u64;
    fn rdi(&self) -> u64;
    fn rip(&self) -> u64;
    fn cs(&self) -> u64;
    fn rflags(&self) -> u64;
    fn rsp(&self) -> u64;
    fn ss(&self) -> u64;
    fn ds(&self) -> u64;
    fn es(&self) -> u64;
    fn fs(&self) -> u64;
    fn gs(&self) -> u64;

    fn set_r15(&mut self, value: u64);
    fn set_r14(&mut self, value: u64);
    fn set_r13(&mut self, value: u64);
    fn set_r12(&mut self, value: u64);
    fn set_rbp(&mut self, value: u64);
    fn set_rbx(&mut self, value: u64);
    fn set_r11(&mut self, value: u64);
    fn set_r10(&mut self, value: u64);
    fn set_r9(&mut self, value: u64);
    fn set_r8(&mut self, value: u64);
    fn set_rax(&mut self, value: u64);
    fn set_rcx(&mut self, value: u64);
    fn set_rdx(&mut self, value: u64);
    fn set_rsi(&mut self, value: u64);
    fn set_rdi(&mut self, value: u64);
    fn set_rip(&mut self, value: u64);
    fn set_cs(&mut self, value: u64);
    fn set_rflags(&mut self, value: u64);
    fn set_rsp(&mut self, value: u64);
    fn set_ss(&mut self, value: u64);
    fn set_ds(&mut self, value: u64);
    fn set_es(&mut self, value: u64);
    fn set_fs(&mut self, value: u64);
    fn set_gs(&mut self, value: u64);
}
