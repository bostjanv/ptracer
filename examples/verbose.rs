use ptracer::{util, ContinueMode, Ptracer, StopSignal, ThreadState, TraceeState, TrapEvent};
use std::env;
use std::path::Path;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let path = Path::new(&args[0]);
    let ptracer = Ptracer::spawn(&path, &args[1..]);
    if let Err(err) = ptracer {
        eprintln!("Error: {}", err);
        return;
    }

    let mut ptracer = ptracer.unwrap();

    println!("PID: {}", ptracer.pid);
    println!("RIP: 0x{:x}", ptracer.gp_regs.rip);

    let mmaps = util::read_memory_maps(ptracer.pid);

    let base_address = mmaps[0].offset;
    println!("Base address: 0x{:x}", base_address);

    let show_bytes = |address, size| {
        let mut data = vec![0 as u8; size];
        util::read_data(ptracer.pid, address, &mut data);
        print!("Memory @ 0x{:x}:", address);
        for b in &data {
            print!(" {:02x}", b);
        }
        println!();
    };

    let entry_offset = 0x5ae0;

    show_bytes(base_address + entry_offset, 16);

    println!();
    util::show_registers(&ptracer.gp_regs);
    println!();

    // Break at entry point
    ptracer.insert_breakpoint(base_address + entry_offset);

    let event = ptracer.cont(ContinueMode::Default).as_ref().unwrap();
    let pid = event.pid;
    assert_eq!(event.tracee_state, TraceeState::Stopped);
    assert_eq!(event.trap_event, TrapEvent::None);
    println!(
        ">>>>> First breakpoint: RIP=0x{:x}, PID={}",
        ptracer.gp_regs.rip, pid,
    );

    ptracer.remove_breakpoint(base_address + entry_offset);

    while let Ok(event) = ptracer.syscall(ContinueMode::Default) {
        print!(">>>>> ");
        let pid = event.pid;

        match event.tracee_state {
            TraceeState::Stopped => {
                if !event.is_syscall {
                    match event.trap_event {
                        TrapEvent::None => match event.stop_signal {
                            StopSignal::Stop => print!("Initial entry point"),
                            StopSignal::Trap => print!("Breakpoint"),
                            StopSignal::Term => print!("Received TERM signal"),
                            StopSignal::Usr1 => print!("Received USR1 signal"),
                            StopSignal::Int => print!("Received INT signal"),
                            _ => unimplemented!(),
                        },
                        TrapEvent::Clone(pid) => print!("New thread (PID={})", pid),
                        _ => unimplemented!(),
                    }

                    println!(": RIP=0x{:x}, PID={}", ptracer.gp_regs.rip, pid);
                } else {
                    assert_eq!(event.trap_event, TrapEvent::None);

                    let rax = match ptracer.threads.get(&pid).unwrap() {
                        ThreadState::InSyscall => {
                            print!("Syscall enter");
                            ptracer.gp_regs.orig_rax
                        }
                        ThreadState::Running => {
                            print!("Syscall leave");
                            ptracer.gp_regs.rax
                        }
                        _ => unreachable!(),
                    };

                    println!(
                        ": RAX={}, RIP=0x{:x}, PID={}",
                        rax, ptracer.gp_regs.rip, pid
                    );
                }
            }

            TraceeState::Exited => {
                println!("Exited: PID={}", pid);
            }

            TraceeState::Signaled => {
                println!("Signaled: PID={}", pid);
            }

            _ => unimplemented!(),
        }
    }

    ptracer.detach();
}
