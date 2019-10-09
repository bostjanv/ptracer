use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::fmt;
use std::path::Path;

use log::{debug, trace};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

pub mod util;
pub use nix::sys::ptrace::{getevent, getregs, getsiginfo, read, setregs, setsiginfo, write};

const ADDR_NO_RANDOMIZE: nix::libc::c_ulong = 0x0040000;

pub struct Ptracer {
    pub pid: Pid,
    pub registers: nix::libc::user_regs_struct,
    pub threads: HashMap<Pid, ThreadState>,
    event: WaitStatus,
    breakpoints: HashMap<ptrace::AddressType, Breakpoint>,
}

impl Ptracer {
    pub fn spawn(path: &Path, args: &[String]) -> nix::Result<Self> {
        let pid = spawn(path.to_str().unwrap(), args)?;

        let event = wait()?;
        debug!("spawn: event: {:?}", event);
        assert_eq!(event.pid(), Some(pid));

        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_EXITKILL
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACEVFORKDONE
                | ptrace::Options::PTRACE_O_TRACESYSGOOD,
        )?;

        let registers = ptrace::getregs(pid)?;

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

    pub fn enable_breakpoint(&mut self, address: usize) -> nix::Result<()> {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&(address as ptrace::AddressType)) {
            if !bp.enabled {
                insert_breakpoint(self.pid, address as ptrace::AddressType)?;
                bp.enabled = true;
            }
        }

        Ok(())
    }

    pub fn disable_breakpoint(&mut self, address: ptrace::AddressType) -> nix::Result<()> {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&address) {
            if bp.enabled {
                remove_breakpoint(self.pid, address, bp.data)?;
                bp.enabled = false;
            }
        }

        Ok(())
    }

    pub fn remove_breakpoint(&mut self, address: ptrace::AddressType) -> nix::Result<()> {
        if let Some(ref b) = self.breakpoints.get(&address) {
            debug!("Removing breakpoint {:#016x?}", address);
            remove_breakpoint(self.pid, address, b.data)?;
        }

        Ok(())
    }

    pub fn cont(&mut self, how: ContinueMode) -> nix::Result<()> {
        if self.cont_aux(how, PtraceRequest::Cont)? {
            while self.cont_aux(ContinueMode::Default, PtraceRequest::Cont)? {}
        }

        Ok(())
    }

    pub fn step(&mut self, how: ContinueMode) -> nix::Result<()> {
        if self.cont_aux(how, PtraceRequest::Step)? {
            while self.cont_aux(ContinueMode::Default, PtraceRequest::Step)? {}
        }

        Ok(())
    }

    pub fn syscall(&mut self, how: ContinueMode) -> nix::Result<()> {
        if self.cont_aux(how, PtraceRequest::Syscall)? {
            while self.cont_aux(ContinueMode::Default, PtraceRequest::Syscall)? {}
        }

        Ok(())
    }

    fn cont_aux(&mut self, how: ContinueMode, ptrace_request: PtraceRequest) -> nix::Result<bool> {
        let event = self.event;
        let is_stopped = match event {
            WaitStatus::Exited(_, _) => false,
            WaitStatus::Signaled(_, _, _) => false,
            WaitStatus::Stopped(_, signal) => {
                let mut is_stopped = true;

                if signal == Signal::SIGTRAP {
                    let pc = self.registers.rip as ptrace::AddressType;
                    trace!("pc = {:#016x}", pc as usize);

                    if let Some(bp) = self.breakpoints.get(&pc) {
                        if bp.enabled {
                            // Reinsert breakpoint
                            let pid = event.pid().unwrap();
                            debug!("Single stepping @ {:#016x?} (PID={})", pc, pid);
                            ptrace::step(pid, None)?;
                            is_stopped = false;

                            let thread_state = self.threads.get_mut(&pid).unwrap();
                            *thread_state = ThreadState::SingleStepping(pc);
                        }
                    }
                }

                is_stopped
            }
            WaitStatus::PtraceEvent(_, _, _) => true,
            WaitStatus::PtraceSyscall(_) => true,
            WaitStatus::Continued(_) => false,
            WaitStatus::StillAlive => false,
        };
        trace!("is_stopped = {}", is_stopped);

        if is_stopped {
            let pid = event.pid().unwrap();
            let signal = match how {
                ContinueMode::NoSignal => None,
                ContinueMode::WithSignal(signal) => Some(signal),
                ContinueMode::Default => {
                    let signal = match event {
                        WaitStatus::Signaled(_, signal, _) => Some(signal),
                        WaitStatus::Stopped(_, signal) => Some(signal),
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
                "ptrace_request = {:?}, pid = {}, signal = {:?}",
                ptrace_request,
                pid,
                signal
            );
            match ptrace_request {
                PtraceRequest::Cont => ptrace::cont(pid, signal)?,
                PtraceRequest::Step => ptrace::step(pid, signal)?,
                PtraceRequest::Syscall => ptrace::syscall(pid)?,
            }
        }

        let event = wait()?;
        self.event = event;
        debug!("event: {:?}", event);

        let pid = match event {
            WaitStatus::StillAlive => return Ok(true),
            event => event.pid().unwrap(),
        };
        trace!("pid = {:?}", pid);

        match event {
            WaitStatus::Stopped(_, _)
            | WaitStatus::PtraceEvent(_, _, _)
            | WaitStatus::PtraceSyscall(_) => {
                self.registers = ptrace::getregs(pid)?;
                trace!("self.registers = {:#016x?}", self.registers);
            }
            _ => {}
        }

        match event {
            WaitStatus::Exited(_, code) => {
                debug!("Process {} exited with code {}", pid, code);
                self.threads.remove(&pid).unwrap();
            }
            WaitStatus::Signaled(_, signal, _) => {
                debug!("Process {} exited with signal {}", pid, signal);
                self.threads.remove(&pid).unwrap();
            }
            WaitStatus::Stopped(_, _) => {
                trace!("WaitStatus::Stopped");
                let thread_state = self.threads.get_mut(&pid).unwrap();
                match *thread_state {
                    ThreadState::SingleStepping(pc) => {
                        if let Some(bp) = self.breakpoints.get(&pc) {
                            if bp.enabled {
                                debug!("Reinserting breakpoint @ {:#016x?} (PID={})", pc, pid);
                                insert_breakpoint(pid, pc)?;
                            }
                        } else {
                            debug!("??? Breakpoint @ {:#016x?} not found", pc);
                            unreachable!();
                        }

                        *thread_state = ThreadState::Running;

                        if ptrace_request != PtraceRequest::Step {
                            return Ok(true);
                        }
                    }

                    ThreadState::Running => {
                        // Breakpoint reached
                        let pc = (self.registers.rip - 1) as ptrace::AddressType;
                        trace!("pc = {:#016x}", pc as usize);

                        if let Some(bp) = self.breakpoints.get(&pc) {
                            debug!("Removing breakpoint @ {:#016x?} (PID={})", bp.address, pid);
                            remove_breakpoint(pid, bp.address, bp.data)?;

                            self.registers.rip = pc as u64;
                            unsafe {
                                #[allow(deprecated)]
                                ptrace::ptrace(ptrace::Request::PTRACE_SETREGSET, pid, nix::libc::RIP as *mut c_void, pc as *mut c_void)?;
                            }
                        } else {
                            debug!(
                                "??? breakpoint not found (pc = {:#016x?})",
                                self.registers.rip
                            );
                            unreachable!();
                        }
                    }

                    ThreadState::InSyscall => {
                        *thread_state = ThreadState::Running;
                    }
                }
            }
            WaitStatus::PtraceEvent(_, _, pevent) => {
                trace!("PtraceEvent = {:?}", pevent);
                if pevent == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    debug!("Process cloned with pid {}", pid);
                    self.threads.insert(pid, ThreadState::Running);
                } else if pevent == ptrace::Event::PTRACE_EVENT_FORK as i32
                    || pevent == ptrace::Event::PTRACE_EVENT_VFORK as i32
                    || pevent == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i32
                {
                    debug!("Process (v)forked with pid {}", pid);
                } else if pevent == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    debug!("Process {} called exec", pid);
                } else if pevent == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                    debug!("Process {} called exit", pid);
                } else if pevent == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
                    debug!("Process {} triggered seccomp", pid);
                } else {
                    debug!("Process {} triggered unknown ptrace event {}", pid, pevent);
                }
            }
            WaitStatus::PtraceSyscall(_) => {
                assert_eq!(ptrace_request, PtraceRequest::Syscall);
                let thread_state = self.threads.get_mut(&pid).unwrap();
                *thread_state = ThreadState::InSyscall;
            }
            WaitStatus::Continued(_) => {
                trace!("WaitStatus::Continued");
            }
            WaitStatus::StillAlive => return Ok(true),
        };

        Ok(false)
    }

    pub fn detach(&self) -> nix::Result<()> {
        match self.event {
            WaitStatus::Exited(_, _) => return Ok(()),
            _ => {}
        }

        // Remove breakpoints
        for (address, breakpoint) in &self.breakpoints {
            debug!("Removing breakpoint {:#016x?}", address);
            remove_breakpoint(self.pid, *address, breakpoint.data)?;
        }

        ptrace::detach(self.pid)
    }

    pub fn event(&self) -> &WaitStatus {
        &self.event
    }

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

fn spawn(path: &str, args: &[String]) -> nix::Result<Pid> {
    use nix::libc::personality;
    use nix::unistd::{execv, fork, ForkResult};

    let path = CString::new(path).expect("CString::new failed");

    let mut args = args
        .iter()
        .map(|x| CString::new(x.as_str()).unwrap())
        .collect::<Vec<_>>();
    args.insert(0, path.clone());

    match fork() {
        Ok(ForkResult::Parent { child, .. }) => Ok(child),
        Ok(ForkResult::Child) => {
            ptrace::traceme()?;
            unsafe {
                personality(ADDR_NO_RANDOMIZE);
            }
            execv(&path, &args)?;
            unreachable!();
        }
        Err(err) => Err(err),
    }
}

fn wait() -> nix::Result<WaitStatus> {
    use nix::sys::wait::{waitpid, WaitPidFlag};
    waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL))
}

pub struct Breakpoint {
    address: ptrace::AddressType,
    data: u64,
    enabled: bool,
}

impl Breakpoint {
    pub fn address(&self) -> usize {
        self.address as usize
    }

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

fn insert_breakpoint(pid: Pid, address: ptrace::AddressType) -> nix::Result<u64> {
    let data = read(pid, address)? as u64;
    let new_data = (data & !0xff) | 0xcc;
    write(pid, address, new_data as *mut c_void)?;
    Ok(data)
}

fn remove_breakpoint(pid: Pid, address: ptrace::AddressType, orig_data: u64) -> nix::Result<()> {
    let data = read(pid, address)? as u64;
    let new_data = (data & !0xff) | (orig_data & 0xff);
    write(pid, address, new_data as *mut c_void)
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum PtraceRequest {
    Cont,
    Step,
    Syscall,
}

#[derive(Debug)]
pub enum ContinueMode {
    Default,
    NoSignal,
    WithSignal(Signal),
}

#[derive(Debug, PartialEq)]
pub enum ThreadState {
    Running,
    SingleStepping(ptrace::AddressType),
    InSyscall,
}
