use nix::sys::wait::WaitStatus;
use ptracer::util;
use ptracer::{ContinueMode, Ptracer, Registers};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn main() {
    env_logger::init();

    if env::args().len() < 2 {
        eprintln!("usage: {} PROGRAM [ARGS]", env::args().next().unwrap());
        return;
    }

    let args = env::args().skip(1).collect::<Vec<_>>();
    let path = Path::new(&args[0]);
    let ptracer = Ptracer::spawn(&path, &args[1..]);
    if let Err(err) = ptracer {
        eprintln!("Error: {}", err);
        return;
    }

    let mut ptracer = ptracer.unwrap();

    println!(
        "Process (PID={}) spawned @ RIP={:016x}",
        ptracer.pid,
        ptracer.registers.rip()
    );

    let mmaps = util::get_memory_maps(ptracer.pid).unwrap();

    let base_address = mmaps[0].start as usize;
    println!("Base address: {:#018x}", base_address);

    let show_bytes = |address, size| {
        let mut data = vec![0 as u8; size];
        util::read_data(ptracer.pid, address, &mut data).unwrap();
        print!("Memory @ {:#018x}:", address);
        for b in &data {
            print!(" {:02x}", b);
        }
        println!();
    };

    let entry_offset = {
        let mut fd = File::open(path).unwrap();
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer).unwrap();
        let binary = goblin::elf::Elf::parse(&buffer).unwrap();
        binary.entry as usize
    };

    show_bytes(base_address + entry_offset, 16);

    println!();
    util::show_registers(&ptracer.registers);
    println!();

    // Break at entry point
    ptracer
        .insert_breakpoint(base_address + entry_offset)
        .unwrap();

    ptracer.cont(ContinueMode::Default).as_ref().unwrap();
    let event = ptracer.event();
    let pid = ptracer.pid;
    println!(
        ">>>>> First breakpoint: RIP={:#018x}, PID={}, Event={:?}",
        ptracer.registers.rip(),
        pid,
        event
    );

    ptracer
        .remove_breakpoint(base_address + entry_offset)
        .unwrap();

    while let Ok(_) = ptracer.syscall(ContinueMode::Default) {
        print!(">>>>> ");

        match ptracer.event() {
            WaitStatus::Exited(pid, code) => {
                println!("Thread (PID={}) exited with return code {}", pid, code);
            }
            WaitStatus::Signaled(pid, signal, coredump) => {
                println!(
                    "Thread (PID={}) exited with signal {}, cordump={:?}",
                    pid, signal, coredump
                );
            }
            WaitStatus::Stopped(pid, signal) => {
                println!("Thread (PID={}) received signal {}", pid, signal);
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceEvent(pid, _, pevent) => {
                use nix::sys::ptrace;

                if *pevent == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    println!("Thread (PID={}) cloned", pid);
                } else if *pevent == ptrace::Event::PTRACE_EVENT_FORK as i32
                    || *pevent == ptrace::Event::PTRACE_EVENT_VFORK as i32
                    || *pevent == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i32
                {
                    println!("Thread (PID={}) (v)forked", pid);
                } else if *pevent == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    println!("Thread (PID={}) called exec", pid);
                } else if *pevent == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                    println!("Thread (PID={}) called exit", pid);
                } else if *pevent == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
                    println!("Thread (PID={}) triggered seccomp", pid);
                } else {
                    println!(
                        "Thread (PID={}) received unknown ptrace event: {}",
                        pid, pevent
                    );
                }
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            WaitStatus::PtraceSyscall(pid) => {
                use ptracer::ThreadState;
                print!("Thread (PID={}) PtraceSyscall ", pid);

                if let Some(thread_state) = ptracer.threads.get(pid) {
                    match *thread_state {
                        ThreadState::SyscallEnter => print!("enter "),
                        ThreadState::SyscallExit => print!("exit "),
                        _ => {}
                    }
                }

                let rip = ptracer.registers.rip;
                let rax = ptracer.registers.rax;
                let orig_rax = ptracer.registers.orig_rax;
                println!(
                    "RIP={:016x}, RAX={:016x}, ORIG_RAX={:016x}",
                    rip, rax, orig_rax
                );
            }
            WaitStatus::Continued(pid) => {
                println!("Thread (PID={}) WaitStatus::Continued", pid);
            }
            WaitStatus::StillAlive => {
                println!("Thread WaitStatus::StillAlive");
            }
        }
    }

    ptracer.detach(None).unwrap();
}
