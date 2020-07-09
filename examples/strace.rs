use nix::{libc, sys::wait::WaitStatus, unistd::Pid};
use ptracer::util;
use ptracer::{ContinueMode, Ptracer, Registers, ThreadState};
use std::env;
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

    println!("Process (PID={}) spawned", ptracer.pid());
    util::show_registers(ptracer.registers());
    println!();

    while let Ok(_) = ptracer.syscall(ContinueMode::Default) {
        match ptracer.event() {
            WaitStatus::PtraceSyscall(pid) => {
                // only log syscall enter
                if let Some(thread_state) = ptracer.threads().get(pid) {
                    if *thread_state != ThreadState::SyscallEnter {
                        continue;
                    }
                }

                let rax = ptracer.registers().orig_rax as i64;

                match rax {
                    libc::SYS_write => handle_sys_write(&ptracer, *pid),
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

fn handle_sys_write(ptracer: &Ptracer, pid: Pid) {
    let rsi = ptracer.registers().rsi();
    let rdx = ptracer.registers().rdx();
    println!(
        "sys_write: {:?}",
        util::read_string(pid, rsi as usize, rdx as usize)
    );
}
