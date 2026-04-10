mod agent;
mod cli;
mod key;

use clap::Parser;
use cli::{AgentCommands, Cli, Commands, KeyCommands};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Agent { command } => match command {
            AgentCommands::List => cmd_agent_status(),
            AgentCommands::Start { quiet } => cmd_agent_start(quiet),
            AgentCommands::Key { command } => match command {
                KeyCommands::List { pid } => cmd_agent_list(pid),
                KeyCommands::Add { key, pid } => cmd_agent_key(pid, &key),
                KeyCommands::Remove { key, pid } => cmd_agent_key_remove(pid, &key),
            },
            AgentCommands::Stop { pid, all } => cmd_agent_stop(pid, all),
        },
        Commands::Create { output, key_type, comment } => {
            cmd_create(output.as_deref(), key_type, comment.as_deref());
        }
    }
}

fn cmd_agent_start(quiet: bool) {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("ssh-agent");
    cmd.stdin(Stdio::null());
    if quiet {
        cmd.stdout(Stdio::null());
    }

    // Double-fork to fully detach ssh-agent from the shell's job control:
    //   pre_exec runs in Child 1 (after fork, before exec):
    //     - setsid()  →  Child 1 becomes a new session leader
    //     - fork()    →  Child 2 returns Ok(()), execs ssh-agent as the daemon
    //                    Child 1 calls _exit(0) immediately
    //   We wait() for Child 1 (exits right away), then ssh-key exits and the
    //   prompt returns while ssh-agent runs in its own detached session.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            match libc::fork() {
                -1 => Err(std::io::Error::last_os_error()),
                0 => Ok(()), // Child 2: continue to exec ssh-agent
                _ => {
                    libc::_exit(0); // Child 1: exit immediately
                }
            }
        });
    }

    match cmd.spawn() {
        Ok(mut child) => {
            // Reap Child 1 (exits immediately after the second fork).
            let _ = child.wait();
        }
        Err(e) => {
            eprintln!("Failed to start ssh-agent: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_create(output: Option<&str>, key_type: key::KeyType, comment: Option<&str>) {
    match key::generate(key_type, output, comment.unwrap_or("")) {
        Ok((priv_path, pub_path)) => {
            println!("Private key: {}", priv_path);
            println!("Public key:  {}", pub_path);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn resolve_agent_socket(pid: Option<u32>) -> String {
    if let Some(pid) = pid {
        match agent::find_socket_for_pid(pid) {
            Some(p) => p,
            None => {
                eprintln!("No ssh-agent with PID {} found", pid);
                std::process::exit(1);
            }
        }
    } else {
        let agents = agent::find_agents();
        match agents.len() {
            0 => {
                eprintln!("No ssh-agent is running");
                std::process::exit(1);
            }
            1 => match &agents[0].socket_path {
                Some(p) => p.clone(),
                None => {
                    eprintln!("ssh-agent (PID {}) socket not found", agents[0].pid);
                    std::process::exit(1);
                }
            },
            _ => {
                eprintln!(
                    "Multiple ssh-agent processes running; use --pid to specify one: {}",
                    agents.iter().map(|a| a.pid.to_string()).collect::<Vec<_>>().join(", ")
                );
                std::process::exit(1);
            }
        }
    }
}

fn cmd_agent_list(pid: Option<u32>) {
    let socket_path = resolve_agent_socket(pid);

    match agent::list_keys(&socket_path) {
        Ok(keys) if keys.is_empty() => println!("No keys loaded."),
        Ok(keys) => {
            for key in &keys {
                println!("{} {} ({})", key.fingerprint, key.comment, key.algorithm);
            }
        }
        Err(e) => {
            eprintln!("Error querying agent: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_agent_key_remove(pid: Option<u32>, key: &str) {
    let socket_path = resolve_agent_socket(pid);
    if let Err(e) = agent::remove_key(&socket_path, key) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_agent_key(pid: Option<u32>, add: &str) {
    let socket_path = resolve_agent_socket(pid);
    if let Err(e) = agent::add_key(&socket_path, add) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_agent_stop(pid: Option<u32>, all: bool) {
    let pids: Vec<u32> = if all {
        agent::find_agents().into_iter().map(|a| a.pid).collect()
    } else {
        pid.into_iter().collect()
    };

    if pids.is_empty() {
        println!("No ssh-agent processes found.");
        return;
    }

    let mut failed = false;
    for p in pids {
        let ret = unsafe { libc::kill(p as libc::pid_t, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("Failed to stop agent {}: {}", p, err);
            failed = true;
        }
    }

    if failed {
        std::process::exit(1);
    }
}

fn cmd_agent_status() {
    let agents = agent::find_agents();

    if agents.is_empty() {
        println!("No ssh-agent processes found.");
        return;
    }

    println!("Found {} ssh-agent process(es)\n", agents.len());

    for a in &agents {
        println!("PID:      {}", a.pid);

        match &a.username {
            Some(name) => println!("User:     {} (uid {})", name, a.uid),
            None => println!("UID:      {}", a.uid),
        }

        match &a.socket_path {
            Some(path) => println!("Socket:   {}", path),
            None => println!("Socket:   (not found)"),
        }

        match a.key_lifetime {
            Some(secs) => println!("Lifetime: {} ({})", secs, agent::format_duration(secs)),
            None => println!("Lifetime: unlimited"),
        }

        match a.uptime_secs {
            Some(secs) => println!("Uptime:   {}", agent::format_duration(secs)),
            None => println!("Uptime:   unknown"),
        }

        println!("Args:     {}", a.cmdline.join(" "));
        println!();
    }
}
