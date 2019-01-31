use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::io::Error;
use std::path::Path;
use std::ptr;

pub mod util;

#[cfg(feature = "my_debug")]
macro_rules! dprint {
    ($( $args:expr ),*) => { print!( $( $args ),* ); }
}

#[cfg(feature = "my_debug")]
macro_rules! dprintln {
    ($( $args:expr ),*) => { println!( $( $args ),* ); }
}

#[cfg(not(feature = "my_debug"))]
macro_rules! dprint {
    ($( $args:expr ),*) => {};
}

#[cfg(not(feature = "my_debug"))]
macro_rules! dprintln {
    ($( $args:expr ),*) => {};
}

const NT_PRSTATUS: libc::c_int = 1;

pub struct Ptracer {
    pub pid: i32,
    pub gp_regs: libc::user_regs_struct,
    pub threads: HashMap<i32, ThreadState>,
    event: Result<WaitEvent, Error>,
    breakpoints: HashMap<u64, Breakpoint>,
}

impl Ptracer {
    pub fn spawn(path: &Path, args: &[String]) -> Result<Self, Error> {
        let pid = spawn(path.to_str().unwrap(), args)?;

        let event = wait()?;
        dprintln!("spawn: event: {:?}", event);
        assert_eq!(event.pid, pid);
        ptrace_wrap1(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            libc::PTRACE_O_EXITKILL
                | libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_TRACEEXEC
                | libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEVFORK
                | libc::PTRACE_O_TRACEVFORKDONE
                | libc::PTRACE_O_TRACESYSGOOD,
        )?;

        let gp_regs = get_general_purpose_registers(pid);

        let mut threads = HashMap::new();
        threads.insert(pid, ThreadState::Running);

        Ok(Self {
            pid,
            event: Ok(event),
            breakpoints: HashMap::new(),
            gp_regs,
            threads,
        })
    }

    pub fn insert_breakpoint(&mut self, address: u64) {
        if !self.breakpoints.contains_key(&address) {
            let data = insert_breakpoint(self.pid, address);
            let breakpoint = Breakpoint {
                address,
                data,
                enabled: true,
            };
            self.breakpoints.insert(address, breakpoint);
        }
    }

    pub fn enable_breakpoint(&mut self, address: u64) {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&address) {
            if !bp.enabled {
                insert_breakpoint(self.pid, address);
                bp.enabled = true;
            }
        }
    }

    pub fn disable_breakpoint(&mut self, address: u64) {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&address) {
            if bp.enabled {
                remove_breakpoint(self.pid, address, bp.data);
                bp.enabled = false;
            }
        }
    }

    pub fn remove_breakpoint(&mut self, address: u64) {
        if let Some(ref b) = self.breakpoints.get(&address) {
            dprintln!("Removing breakpoint {}", address);
            remove_breakpoint(self.pid, address, b.data);
        }
    }

    /*
        // debug
        let siginfo = get_siginfo(pid);
        eprintln!(
            "siginfo: {}, {}, {}",
            siginfo.si_signo, siginfo.si_errno, siginfo.si_code
        );
    */

    pub fn cont(&mut self, how: ContinueMode) -> &Result<WaitEvent, Error> {
        if let Ok(_event) = &self.event {
            if self.cont_aux(how, PtraceRequest::Cont) {
                while self.cont_aux(ContinueMode::Default, PtraceRequest::Cont) {}
            }
        }

        &self.event
    }

    pub fn step(&mut self, how: ContinueMode) -> &Result<WaitEvent, Error> {
        if let Ok(_event) = &self.event {
            if self.cont_aux(how, PtraceRequest::Step) {
                while self.cont_aux(ContinueMode::Default, PtraceRequest::Step) {}
            }
        }

        &self.event
    }

    pub fn syscall(&mut self, how: ContinueMode) -> &Result<WaitEvent, Error> {
        if let Ok(_event) = &self.event {
            if self.cont_aux(how, PtraceRequest::Syscall) {
                while self.cont_aux(ContinueMode::Default, PtraceRequest::Syscall) {}
            }
        }

        &self.event
    }

    fn cont_aux(&mut self, how: ContinueMode, ptrace_request: PtraceRequest) -> bool {
        let event = self.event.as_ref().unwrap();

        let mut is_stopped = if event.tracee_state == TraceeState::Stopped {
            true
        } else {
            false
        };

        if event.stop_signal == StopSignal::Trap && event.trap_event == TrapEvent::None {
            let pc = self.gp_regs.rip;

            if let Some(bp) = self.breakpoints.get(&pc) {
                if bp.enabled {
                    // Reinsert breakpoint
                    dprintln!("Single stepping @ 0x{:x} (PID={})", pc, event.pid);
                    ptrace_wrap(libc::PTRACE_SINGLESTEP, event.pid).unwrap();
                    is_stopped = false;

                    let thread_state = self.threads.get_mut(&event.pid).unwrap();
                    *thread_state = ThreadState::SingleStepping(pc);
                }
            }
        }

        if is_stopped {
            let signo = match how {
                ContinueMode::NoSignal => 0,
                ContinueMode::WithSignal(signo) => signo,
                ContinueMode::Default => {
                    if event.tracee_state == TraceeState::Stopped {
                        match event.stop_signal {
                            StopSignal::Trap | StopSignal::Stop => 0,
                            _ => i32::from(event.stop_signal),
                        }
                    } else {
                        0
                    }
                }
            };
            ptrace_wrap1(ptrace_request.into(), event.pid, 0, signo).unwrap();
        }

        let event = wait();
        dprintln!("\nevent: {:?}", event);

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
                                                dprintln!(
                                                    "Reinserting breakpoint @ 0x{:x} (PID={})",
                                                    pc,
                                                    event.pid
                                                );
                                                insert_breakpoint(event.pid, pc);
                                            }
                                        } else {
                                            dprintln!("??? Breakpoint @ 0x{:x} not found", pc);
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
                                            dprintln!(
                                                "Removing breakpoint @ 0x{:x} (PID={})",
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
                                                dprintln!(
                                                    "??? breakpoint not found (pc = 0x{:x})",
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
                                dprintln!("XXX {:?}", event.trap_event);
                                unreachable!();
                            }
                        },

                        StopSignal::Stop
                        | StopSignal::Term
                        | StopSignal::Usr1
                        | StopSignal::Int => {
                            //dprintln!("Stop");
                        }

                        _ => unreachable!(),
                    }

                    self.gp_regs = regs;
                }

                TraceeState::Exited => {
                    dprintln!("Exited");
                    self.threads.remove(&event.pid).unwrap();
                }

                TraceeState::Signaled => {
                    dprintln!("Signaled");
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

    pub fn detach(&self) {
        if let Ok(ref event) = self.event {
            if event.tracee_state == TraceeState::Exited {
                return;
            }
        } else {
            return;
        }

        // Remove breakpoints
        for (address, breakpoint) in &self.breakpoints {
            dprintln!("Removing breakpoint {}", address);
            remove_breakpoint(self.pid, *address, breakpoint.data);
        }

        ptrace_wrap(libc::PTRACE_DETACH, self.pid).unwrap();
    }
}

fn spawn(path: &str, args: &[String]) -> Result<libc::pid_t, Error> {
    let path = CString::new(path).expect("CString::new failed");

    let args = args
        .iter()
        .map(|x| CString::new(x.as_str()).unwrap())
        .collect::<Vec<_>>();
    let mut argv = Vec::new();
    argv.push(path.as_ptr());
    for arg in &args {
        argv.push(arg.as_ptr());
    }
    argv.push(ptr::null());

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(Error::from_raw_os_error(read_errno())),
        0 => {
            // son
            ptrace_wrap(libc::PTRACE_TRACEME, 0)?;

            clear_errno();
            let result = unsafe { libc::execv(path.as_ptr(), argv.as_ptr()) };
            assert_eq!(result, -1);
            std::process::exit(read_errno());
        }
        _ => Ok(pid), // father
    }
}

#[derive(Debug)]
pub struct WaitEvent {
    pub pid: i32,
    pub tracee_state: TraceeState,
    pub stop_signal: StopSignal,
    pub trap_event: TrapEvent,
    pub is_syscall: bool,
}

fn wait() -> Result<WaitEvent, Error> {
    let mut stat = 0;
    clear_errno();
    let pid = unsafe { libc::waitpid(-1, &mut stat, libc::__WALL) };
    let errno = read_errno();

    if errno == libc::ECHILD {
        Err(Error::from_raw_os_error(errno))
    } else {
        assert_eq!(errno, 0);

        let wif = (
            unsafe { libc::WIFEXITED(stat) },
            unsafe { libc::WIFSTOPPED(stat) },
            unsafe { libc::WIFSIGNALED(stat) },
            unsafe { libc::WIFCONTINUED(stat) },
        );
        dprintln!("wif: {:?}", wif);

        let signo = unsafe { libc::WSTOPSIG(stat) };
        dprintln!("signo: {}", signo);
        let is_syscall = signo & 0x80 == 0x80;
        let signal = StopSignal::from(signo & !0x80);

        let event = if wif.1 && signal == StopSignal::Trap && (stat >> 16) != 0 {
            let child_pid = get_eventmsg(pid) as i32;
            trap_event(stat, child_pid)
        } else {
            TrapEvent::None
        };

        let state = match wif {
            (true, false, false, false) => TraceeState::Exited,
            (false, true, false, false) => TraceeState::Stopped,
            (false, false, true, false) => TraceeState::Signaled,
            (false, false, false, true) => TraceeState::Continued,
            _ => unreachable!(),
        };

        Ok(WaitEvent {
            pid,
            tracee_state: state,
            stop_signal: signal,
            trap_event: event,
            is_syscall,
        })
    }
}

fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

fn read_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn ptrace_wrap(request: libc::c_uint, pid: libc::pid_t) -> Result<u64, Error> {
    clear_errno();
    let result = unsafe {
        libc::ptrace(
            request,
            pid,
            ptr::null::<*const c_void>(),
            ptr::null::<*const c_void>(),
        )
    };
    //assert_eq!(result, 0);
    let errno = read_errno();
    if errno != 0 {
        dprintln!("ptrace_wrap: errno: {}", errno);
        Err(Error::from_raw_os_error(errno))
    } else {
        Ok(result as u64)
    }
}

fn ptrace_wrap1<T1, T2>(
    request: libc::c_uint,
    pid: libc::pid_t,
    addr: T1,
    data: T2,
) -> Result<u64, Error> {
    clear_errno();
    let result = unsafe { libc::ptrace(request, pid, addr, data) };
    let errno = read_errno();
    if errno != 0 {
        dprintln!("ptrace_wrap1: errno: {}", errno);
        Err(Error::from_raw_os_error(errno))
    } else {
        Ok(result as u64)
    }
}

fn get_general_purpose_registers(pid: libc::pid_t) -> libc::user_regs_struct {
    let mut regs: libc::user_regs_struct;
    regs = unsafe { std::mem::uninitialized() };
    let mut iovec = libc::iovec {
        iov_base: &mut regs as *mut libc::user_regs_struct as *mut c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };

    ptrace_wrap1(libc::PTRACE_GETREGSET, pid, NT_PRSTATUS as u64, &mut iovec).unwrap();
    regs
}

fn set_general_purpose_registers(pid: libc::pid_t, regs: &libc::user_regs_struct) {
    let iovec = libc::iovec {
        iov_base: regs as *const libc::user_regs_struct as *mut c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    ptrace_wrap1(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS, &iovec).unwrap();
}

struct Breakpoint {
    address: u64,
    data: u64,
    enabled: bool,
}

fn insert_breakpoint(pid: libc::pid_t, address: u64) -> u64 {
    let data = ptrace_wrap1(libc::PTRACE_PEEKDATA, pid, address, 0).unwrap();
    ptrace_wrap1(libc::PTRACE_POKEDATA, pid, address, (data & !0xff) | 0xcc).unwrap();
    data
}

fn remove_breakpoint(pid: libc::pid_t, address: u64, orig_data: u64) {
    let mut data = ptrace_wrap1(libc::PTRACE_PEEKDATA, pid, address, 0).unwrap();
    data = (data & !0xff) | (orig_data & 0xff);
    ptrace_wrap1(libc::PTRACE_POKEDATA, pid, address, data).unwrap();
}

fn read_word(pid: i32, address: u64) -> u64 {
    ptrace_wrap1(libc::PTRACE_PEEKDATA, pid, address, 0).unwrap()
}

fn get_register(pid: i32, reg: Register) -> u64 {
    ptrace_wrap1(
        libc::PTRACE_PEEKUSER,
        pid,
        reg as usize * std::mem::size_of::<u64>(),
        0,
    )
    .unwrap()
}

fn set_register(pid: i32, reg: Register, value: u64) -> u64 {
    ptrace_wrap1(
        libc::PTRACE_POKEUSER,
        pid,
        reg as usize * std::mem::size_of::<u64>(),
        value,
    )
    .unwrap()
}

fn get_siginfo(pid: i32) -> libc::siginfo_t {
    let mut siginfo = unsafe { std::mem::uninitialized() };
    ptrace_wrap1(libc::PTRACE_GETSIGINFO, pid, 0, &mut siginfo).unwrap();
    siginfo
}

fn get_eventmsg(pid: i32) -> u64 {
    let mut data = 0u64;
    ptrace_wrap1(libc::PTRACE_GETEVENTMSG, pid, 0, &mut data).unwrap();
    data
}

#[allow(non_camel_case_types)]
enum Register {
    R15 = libc::R15 as isize,
    R14 = libc::R14 as isize,
    R13 = libc::R13 as isize,
    R12 = libc::R12 as isize,
    RBP = libc::RBP as isize,
    RBX = libc::RBX as isize,
    R11 = libc::R11 as isize,
    R10 = libc::R10 as isize,
    R9 = libc::R9 as isize,
    R8 = libc::R8 as isize,
    RAX = libc::RAX as isize,
    RCX = libc::RCX as isize,
    RDX = libc::RDX as isize,
    RSI = libc::RSI as isize,
    RDI = libc::RDI as isize,
    ORIG_RAX = libc::ORIG_RAX as isize,
    RIP = libc::RIP as isize,
    CS = libc::CS as isize,
    EFLAGS = libc::EFLAGS as isize,
    RSP = libc::RSP as isize,
    SS = libc::SS as isize,
    FS_BASE = libc::FS_BASE as isize,
    GS_BASE = libc::GS_BASE as isize,
    DS = libc::DS as isize,
    ES = libc::ES as isize,
    FS = libc::FS as isize,
    GS = libc::GS as isize,
}

#[derive(Debug, PartialEq)]
pub enum TrapEvent {
    None,
    Fork(i32),
    VFork(i32),
    Clone(i32),
    Exec(i32),
    VForkDone(i32),
}

fn trap_event(stat: i32, pid: i32) -> TrapEvent {
    match stat >> 16 {
        libc::PTRACE_EVENT_FORK => TrapEvent::Fork(pid),
        libc::PTRACE_EVENT_VFORK => TrapEvent::VFork(pid),
        libc::PTRACE_EVENT_CLONE => TrapEvent::Clone(pid),
        libc::PTRACE_EVENT_EXEC => TrapEvent::Exec(pid),
        libc::PTRACE_EVENT_VFORK_DONE => TrapEvent::VForkDone(pid),
        _ => unreachable!(),
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum StopSignal {
    Trap,
    Term,
    Cont,
    Stop,
    Usr1,
    Int,
    None,
}

impl From<i32> for StopSignal {
    fn from(signo: i32) -> StopSignal {
        match signo {
            libc::SIGTRAP => StopSignal::Trap,
            libc::SIGTERM => StopSignal::Term,
            libc::SIGCONT => StopSignal::Cont,
            libc::SIGSTOP => StopSignal::Stop,
            libc::SIGUSR1 => StopSignal::Usr1,
            libc::SIGINT => StopSignal::Int,
            0 => StopSignal::None,
            _ => unimplemented!(),
        }
    }
}

impl From<StopSignal> for i32 {
    fn from(signal: StopSignal) -> i32 {
        match signal {
            StopSignal::Trap => libc::SIGTRAP,
            StopSignal::Term => libc::SIGTERM,
            StopSignal::Cont => libc::SIGCONT,
            StopSignal::Stop => libc::SIGSTOP,
            StopSignal::Usr1 => libc::SIGUSR1,
            StopSignal::Int => libc::SIGINT,
            StopSignal::None => 0,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum PtraceRequest {
    Cont,
    Step,
    Syscall,
}

impl From<u32> for PtraceRequest {
    fn from(reqno: u32) -> PtraceRequest {
        match reqno {
            libc::PTRACE_CONT => PtraceRequest::Cont,
            libc::PTRACE_SINGLESTEP => PtraceRequest::Step,
            libc::PTRACE_SYSCALL => PtraceRequest::Syscall,
            _ => unimplemented!(),
        }
    }
}

impl From<PtraceRequest> for u32 {
    fn from(ptrace_request: PtraceRequest) -> u32 {
        match ptrace_request {
            PtraceRequest::Cont => libc::PTRACE_CONT,
            PtraceRequest::Step => libc::PTRACE_SINGLESTEP,
            PtraceRequest::Syscall => libc::PTRACE_SYSCALL,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TraceeState {
    Exited,
    Stopped,
    Signaled,
    Continued,
}

#[derive(Debug)]
pub enum ContinueMode {
    Default,
    NoSignal,
    WithSignal(i32),
}

#[derive(Debug, PartialEq)]
pub enum ThreadState {
    Running,
    SingleStepping(u64),
    InSyscall,
}
