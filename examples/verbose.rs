use nix::{sys::ptrace, sys::wait::WaitStatus};
use ptracer::{util, ContinueMode, Ptracer, ThreadState};
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

    println!("PID: {}", ptracer.pid);
    println!("RIP: 0x{:x}", ptracer.registers.rip);

    let mmaps = util::read_memory_maps(ptracer.pid);

    let base_address = mmaps[0].offset;
    println!("Base address: 0x{:x}", base_address);

    let show_bytes = |address, size| {
        let mut data = vec![0 as u8; size];
        util::read_data(ptracer.pid, address, &mut data).unwrap();
        print!("Memory @ 0x{:x}:", address);
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
        ">>>>> First breakpoint: RIP=0x{:x}, PID={}, Event={:?}",
        ptracer.registers.rip, pid, event
    );

    ptracer
        .remove_breakpoint(base_address + entry_offset)
        .unwrap();

    while let Ok(_) = ptracer.syscall(ContinueMode::Default) {
        print!(">>>>> ");

        match ptracer.event() {
            WaitStatus::Exited(pid, code) => {
                println!("Process {} exited with code {}", pid, code);
            }
            WaitStatus::Signaled(pid, signal, coredump) => {
                println!(
                    "Process {} exited with signal {}, cordump={:?}",
                    pid, signal, coredump
                );
            }
            WaitStatus::Stopped(pid, signal) => {
                println!("Process {} received signal {}", pid, signal);
            }
            WaitStatus::PtraceEvent(pid, _, pevent) => {
                if *pevent == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    println!("Process cloned");
                } else if *pevent == ptrace::Event::PTRACE_EVENT_FORK as i32
                    || *pevent == ptrace::Event::PTRACE_EVENT_VFORK as i32
                    || *pevent == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i32
                {
                    println!("Process (v)forked");
                } else if *pevent == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
                    println!("Process {} called exec", pid);
                } else if *pevent == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                    println!("Process {} called exit", pid);
                } else if *pevent == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
                    println!("Process {} triggered seccomp", pid);
                } else {
                    println!("Process {} triggered unknown ptrace event {}", pid, pevent);
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                print!("Process {} PtraceSyscall ", pid);

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
                println!("Process {} WaitStatus::Continued", pid);
            }
            WaitStatus::StillAlive => {
                println!("WaitStatus::StillAlive");
            }
        }
    }

    ptracer.detach().unwrap();
}
