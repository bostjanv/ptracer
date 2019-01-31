use ptracer::util;
use ptracer::{ContinueMode, Ptracer, ThreadState, TraceeState};
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
    util::show_registers(&ptracer.gp_regs);
    println!();

    while let Ok(event) = ptracer.syscall(ContinueMode::Default) {
        if event.tracee_state == TraceeState::Stopped && event.is_syscall {
            let pid = event.pid;
            let thread_state = *ptracer.threads.get(&pid).as_ref().unwrap();
            if *thread_state == ThreadState::InSyscall {
                let rax = ptracer.gp_regs.orig_rax as i64;

                match rax {
                    libc::SYS_write => handle_sys_write(&ptracer, pid),
                    _ => {}
                }
            }
        }
    }
}

fn handle_sys_write(ptracer: &Ptracer, pid: i32) {
    let rsi = ptracer.gp_regs.rsi;
    let rdx = ptracer.gp_regs.rdx;
    let mut buf = util::read_string(pid, rsi, rdx as usize);
    for r in &[('\n', "\\n"), ('\t', "\\t")] {
        buf = buf.replace(r.0, r.1);
    }
    println!("sys_write: \"{}\"", buf);
}
