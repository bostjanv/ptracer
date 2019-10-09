use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::path::Path;
use std::fmt;

use nix::unistd::Pid;
use nix::sys::signal::Signal;
use nix::sys::ptrace;
use nix::sys::wait::WaitStatus;
use log::debug;

pub mod util;
pub use nix::sys::ptrace::{getevent, getregs, getsiginfo, read, setregs, setsiginfo, write};

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

        ptrace::setoptions(pid, 
            ptrace::Options::PTRACE_O_EXITKILL
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACEVFORKDONE
                | ptrace::Options::PTRACE_O_TRACESYSGOOD
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

    pub fn insert_breakpoint(&mut self, address: ptrace::AddressType) -> nix::Result<()> {
        if !self.breakpoints.contains_key(&address) {
            let data = insert_breakpoint(self.pid, address)?;
            let breakpoint = Breakpoint {
                address,
                data,
                enabled: true,
            };
            self.breakpoints.insert(address, breakpoint);
        }

        Ok(())
    }

    pub fn enable_breakpoint(&mut self, address: ptrace::AddressType) -> nix::Result<()> {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&address) {
            if !bp.enabled {
                insert_breakpoint(self.pid, address)?;
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
        let event = self.event();

        let mut is_stopped = match event {
            WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _) | WaitStatus::PtraceSyscall(_) => true,
            _ => false
        };

        let is_stopped = match self.event() {
            // WaitStatus::Exited(_, _) => false,
            // WaitStatus::Signaled(_, signal, _) => false,
            WaitStatus::Stopped(_, signal) => {
                let mut is_stopped = true;
                if *signal == Signal::SIGTRAP {
                    let pc = self.registers.rip as ptrace::AddressType;
                    let pid = event.pid().unwrap();

                    if let Some(bp) = self.breakpoints.get(&pc) {
                        if bp.enabled {
                            // Reinsert breakpoint
                            debug!("Single stepping @ {:#016x?} (PID={})", pc, pid);
                            ptrace::step(pid, None);
                            is_stopped = false;

                            let thread_state = self.threads.get_mut(&pid).unwrap();
                            *thread_state = ThreadState::SingleStepping(pc);
                        }
                    }
                }

                is_stopped
            },
            WaitStatus::PtraceEvent(_, signal, _) => true,
            WaitStatus::PtraceSyscall(_) => true,
            // WaitStatus::Continued(_) => false,
            // WaitStatus::StillAlive => false
            _ => false
        };

        if is_stopped {
            let pid = event.pid().unwrap();
            let signal = match how {
                ContinueMode::NoSignal => None,
                ContinueMode::WithSignal(signal) => Some(signal),
                ContinueMode::Default => {
                    let signal = match event {
                        WaitStatus::Signaled(_, signal, _) => Some(*signal),
                        WaitStatus::Stopped(_, signal) => Some(*signal),
                        WaitStatus::PtraceEvent(_, signal, _) => Some(*signal),
                        _ => None
                    };

                    match signal {
                        Some(signal) => match signal {
                            Signal::SIGTRAP | Signal::SIGSTOP => None,
                            signal => Some(signal)
                        }
                    }
                }
            };

            match ptrace_request {
                PtraceRequest::Cont => ptrace::cont(pid, signal)?,
                PtraceRequest::Step => ptrace::step(pid, signal)?,
                PtraceRequest::Syscall => ptrace::syscall(pid)?,
            }
        }

        let event = wait();
        debug!("event: {:?}", event);

        let mut repeat = false;

        if let Ok(event) = &event {
            match event.tracee_state {
                TraceeState::Stopped => {
                    let mut regs = get_general_purpose_registers(event.pid);

                    match event.stop_signal {
                        StopSignal::Trap => match event.trap_event {
                            TrapEvent::Clone(cloned_pid) => {
                                self.threads.insert(cloned_pid, ThreadState::Running);
                            }

                            TrapEvent::None => {
                                let thread_state = self.threads.get_mut(&event.pid).unwrap();
                                match *thread_state {
                                    ThreadState::SingleStepping(pc) => {
                                        if let Some(bp) = self.breakpoints.get(&pc) {
                                            if bp.enabled {
                                                debug!(
                                                    "Reinserting breakpoint @ {:#016x?} (PID={})",
                                                    pc,
                                                    event.pid
                                                );
                                                insert_breakpoint(event.pid, pc);
                                            }
                                        } else {
                                            debug!("??? Breakpoint @ {:#016x?} not found", pc);
                                            unreachable!();
                                        }

                                        *thread_state = ThreadState::Running;

                                        if ptrace_request != PtraceRequest::Step {
                                            repeat = true;
                                        }
                                    }

                                    ThreadState::Running => {
                                        // Breakpoint reached
                                        if let Some(bp) = self.breakpoints.get(&(regs.rip - 1)) {
                                            debug!(
                                                "Removing breakpoint @ {:#016x?} (PID={})",
                                                bp.address,
                                                event.pid
                                            );
                                            regs.rip -= 1;
                                            remove_breakpoint(event.pid, bp.address, bp.data);
                                            set_register(event.pid, Register::RIP, regs.rip);
                                        } else {
                                            if event.is_syscall {
                                                assert_eq!(ptrace_request, PtraceRequest::Syscall);
                                                *thread_state = ThreadState::InSyscall;
                                            } else if ptrace_request == PtraceRequest::Cont {
                                                debug!(
                                                    "??? breakpoint not found (pc = {:#016x?})",
                                                    regs.rip
                                                );
                                                unreachable!();
                                            }
                                        }
                                    }

                                    ThreadState::InSyscall => {
                                        *thread_state = ThreadState::Running;
                                    }
                                }
                            }

                            _ => {
                                debug!("XXX {:?}", event.trap_event);
                                unreachable!();
                            }
                        },

                        StopSignal::Stop
                        | StopSignal::Term
                        | StopSignal::Usr1
                        | StopSignal::Int => {
                            //debug!("Stop");
                        }

                        _ => unreachable!(),
                    }

                    self.registers = regs;
                }

                TraceeState::Exited => {
                    debug!("Exited");
                    self.threads.remove(&event.pid).unwrap();
                }

                TraceeState::Signaled => {
                    debug!("Signaled");
                    self.threads.remove(&event.pid).unwrap();
                }

                _ => unimplemented!(),
            }
        } else {
            assert_eq!(self.threads.len(), 0);
        }

        self.event = event;
        repeat
    }

    pub fn detach(&self) -> nix::Result<()> {
        // TODO:
        /*
        if let Ok(ref event) = self.event {
            if event.tracee_state == TraceeState::Exited {
                return;
            }
        } else {
            return;
        }
        */

        // Remove breakpoints
        for (address, breakpoint) in &self.breakpoints {
            debug!("Removing breakpoint {:#016x?}", address);
            remove_breakpoint(self.pid, *address, breakpoint.data);
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
    use nix::unistd::{fork, ForkResult, execv};

    let path = CString::new(path).expect("CString::new failed");

    let args = args
        .iter()
        .map(|x| CString::new(x.as_str()).unwrap())
        .collect::<Vec<_>>();
    args.insert(0, path);

    match fork() {
        Ok(ForkResult::Parent { child, .. }) => Ok(child),
        Ok(ForkResult::Child) => {
            ptrace::traceme()?;
            execv(&path, &args)?;
            unreachable!();
        },
        Err(err) => Err(err)
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
    pub fn address(&self) -> ptrace::AddressType {
        self.address
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

#[derive(Debug, PartialEq)]
pub enum TraceeState {
    Exited(i32),
    Stopped(Signal),
    Signaled(Signal),
    PtraceEvent(Signal, ptrace::Event),
    PtraceSyscall,
    Continued,
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
