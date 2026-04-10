use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Information about a running ssh-agent process.
#[derive(Debug)]
pub struct SshAgentInfo {
    pub pid: u32,
    pub uid: u32,
    pub username: Option<String>,
    /// Path to the Unix domain socket (SSH_AUTH_SOCK).
    pub socket_path: Option<String>,
    /// Raw argv (e.g. ["ssh-agent", "-D", "-t", "3600"]).
    pub cmdline: Vec<String>,
    /// Key lifetime passed via `-t`, in seconds, if present.
    pub key_lifetime: Option<u64>,
    /// Seconds the agent has been running.
    pub uptime_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan /proc and return all running ssh-agent processes.
pub fn find_agents() -> Vec<SshAgentInfo> {
    let unix_sockets = read_unix_socket_map();
    let boot_time = read_boot_time();

    let mut agents = Vec::new();

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return agents,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Only process numeric directories (PIDs).
        let pid: u32 = match path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse().ok())
        {
            Some(p) => p,
            None => continue,
        };

        let cmdline = read_cmdline(pid);
        if !is_ssh_agent(&cmdline) {
            continue;
        }

        let uid = read_uid(pid).unwrap_or(0);
        let username = resolve_username(uid);
        let socket_path = find_socket_path(pid, &unix_sockets);
        let key_lifetime = parse_key_lifetime(&cmdline);
        let uptime_secs = boot_time.and_then(|bt| compute_uptime(pid, bt));

        agents.push(SshAgentInfo {
            pid,
            uid,
            username,
            socket_path,
            cmdline,
            key_lifetime,
            uptime_secs,
        });
    }

    // Sort by PID for deterministic output.
    agents.sort_by_key(|a| a.pid);
    agents
}

// ---------------------------------------------------------------------------
// /proc helpers
// ---------------------------------------------------------------------------

/// Read argv from /proc/<pid>/cmdline (NUL-separated).
fn read_cmdline(pid: u32) -> Vec<String> {
    let bytes = match fs::read(format!("/proc/{}/cmdline", pid)) {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Return true if the first argv entry is `ssh-agent`.
fn is_ssh_agent(cmdline: &[String]) -> bool {
    cmdline
        .first()
        .map(|s| {
            Path::new(s)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(s.as_str())
                == "ssh-agent"
        })
        .unwrap_or(false)
}

/// Read the real UID from /proc/<pid>/status (line "Uid: ruid euid suid fsuid").
fn read_uid(pid: u32) -> Option<u32> {
    read_status_field(pid, "Uid:")
}

fn read_status_field(pid: u32, field: &str) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse().ok())
}

/// Read the process start time (field 22 in /proc/<pid>/stat, in clock ticks since boot).
fn read_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past the comm field "(name)" which may contain spaces/parens.
    let after_comm = stat.rfind(')')?.checked_add(2)?;
    let rest = &stat[after_comm..];
    // Remaining fields are space-separated; starttime is the 20th (0-indexed: 19).
    rest.split_whitespace()
        .nth(19)
        .and_then(|s| s.parse().ok())
}

/// Read system boot time (Unix timestamp) from /proc/stat.
fn read_boot_time() -> Option<u64> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    stat.lines()
        .find(|l| l.starts_with("btime"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// Compute agent uptime in seconds.
fn compute_uptime(pid: u32, boot_time: u64) -> Option<u64> {
    let start_ticks = read_start_ticks(pid)?;
    let clk_tck: u64 = 100; // sysconf(_SC_CLK_TCK), almost always 100 on Linux
    let start_secs = boot_time + start_ticks / clk_tck;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    now.checked_sub(start_secs)
}

// ---------------------------------------------------------------------------
// Unix socket resolution
// ---------------------------------------------------------------------------

/// Build an inode → socket-path map from /proc/net/unix.
///
/// /proc/net/unix columns (space-separated):
///   Num  RefCount  Protocol  Flags  Type  St  Inode  [Path]
fn read_unix_socket_map() -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let content = match fs::read_to_string("/proc/net/unix") {
        Ok(c) => c,
        Err(_) => return map,
    };
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 8 {
            if let Ok(inode) = parts[6].parse::<u64>() {
                map.insert(inode, parts[7].to_string());
            }
        }
    }
    map
}

/// Find the ssh-agent socket path for the given PID.
///
/// Strategy 1 – inode correlation via /proc/<pid>/fd + /proc/net/unix.
/// Strategy 2 – UID-matched scan of /proc/net/unix for ssh-agent socket paths.
/// Strategy 3 – direct filesystem scan of /tmp/ssh-*/agent.* matched by UID
///               (most reliable on WSL2 where /proc/net/unix lacks path info).
///
/// Note: matching by PID/PPID is unreliable because ssh-agent creates the
/// socket before forking; after the parent exits the daemon is re-parented,
/// making its PPID unrelated to the socket name.
fn find_socket_path(pid: u32, unix_sockets: &HashMap<u64, String>) -> Option<String> {
    if let Some(path) = find_socket_via_fd(pid, unix_sockets) {
        return Some(path);
    }

    let uid = read_uid(pid)?;

    // Strategy 2 – scan /proc/net/unix for any ssh-agent socket owned by the
    // same UID as this process.
    for (_, path) in unix_sockets {
        if path.contains("/tmp/ssh-") && path.contains("/agent.") {
            if socket_dir_uid(path) == Some(uid) {
                return Some(path.clone());
            }
        }
    }

    // Strategy 3 – scan the filesystem directly.
    find_socket_via_tmpdir(uid)
}

/// Return the UID of the directory containing the given socket path.
fn socket_dir_uid(socket_path: &str) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(Path::new(socket_path).parent()?)
        .ok()
        .map(|m| m.uid())
}

/// Scan /tmp/ssh-*/ for an agent.* socket whose parent directory is owned
/// by `uid`.
fn find_socket_via_tmpdir(uid: u32) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    for dir_entry in fs::read_dir("/tmp").ok()?.flatten() {
        let dir = dir_entry.path();
        if !dir.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("ssh-")).unwrap_or(false) {
            continue;
        }
        if fs::metadata(&dir).ok().map(|m| m.uid()) != Some(uid) {
            continue;
        }
        for sock_entry in fs::read_dir(&dir).ok()?.flatten() {
            let sock = sock_entry.path();
            if sock.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("agent.")).unwrap_or(false) {
                return Some(sock.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn find_socket_via_fd(pid: u32, unix_sockets: &HashMap<u64, String>) -> Option<String> {
    let entries = fs::read_dir(format!("/proc/{}/fd", pid)).ok()?;
    for entry in entries.flatten() {
        let target = match fs::read_link(entry.path()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let s = target.to_string_lossy();
        if let Some(inode_str) = s
            .strip_prefix("socket:[")
            .and_then(|t| t.strip_suffix(']'))
        {
            if let Ok(inode) = inode_str.parse::<u64>() {
                if let Some(path) = unix_sockets.get(&inode) {
                    if path.contains("ssh") || path.contains("agent") {
                        return Some(path.clone());
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// /etc/passwd username resolution
// ---------------------------------------------------------------------------

fn resolve_username(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.splitn(7, ':');
        let name = fields.next()?;
        fields.next(); // password
        let id: u32 = fields.next()?.parse().ok()?;
        if id == uid {
            return Some(name.to_owned());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// cmdline argument parsing
// ---------------------------------------------------------------------------

/// Parse `-t <lifetime>` or `-t<lifetime>` from argv.
/// The value may be a plain number (seconds) or a suffix: s, m, h, d, w.
fn parse_key_lifetime(cmdline: &[String]) -> Option<u64> {
    let mut iter = cmdline.iter().skip(1); // skip argv[0]
    while let Some(arg) = iter.next() {
        if arg == "-t" {
            let val = iter.next()?;
            return parse_lifetime_value(val);
        }
        if let Some(val) = arg.strip_prefix("-t") {
            return parse_lifetime_value(val);
        }
    }
    None
}

fn parse_lifetime_value(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (digits, suffix) = s.split_at(s.len() - 1);
    let multiplier: u64 = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return s.parse().ok(), // plain number, no suffix
    };
    digits.parse::<u64>().ok().map(|n| n * multiplier)
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Format a duration in seconds as a human-readable string (e.g. "2d 3h", "45m 12s").
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ---------------------------------------------------------------------------
// Agent socket helpers
// ---------------------------------------------------------------------------

/// Return the socket path for the agent with the given PID, if found.
pub fn find_socket_for_pid(pid: u32) -> Option<String> {
    find_agents().into_iter().find(|a| a.pid == pid)?.socket_path
}

// ---------------------------------------------------------------------------
// SSH agent protocol – list loaded keys
// ---------------------------------------------------------------------------

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;

pub struct LoadedKey {
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: String,
}

/// Query an ssh-agent socket and return all loaded keys.
pub fn list_keys(socket_path: &str) -> Result<Vec<LoadedKey>, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;

    // Send SSH_AGENTC_REQUEST_IDENTITIES: length=1, opcode=11
    stream.write_all(&[0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES])?;

    // Read the response: uint32 length, then body
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let body_len = u32::from_be_bytes(len_buf) as usize;

    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body)?;

    if body.first().copied() != Some(SSH_AGENT_IDENTITIES_ANSWER) {
        return Err("unexpected response type from agent".into());
    }

    let nkeys = read_u32(&body, &mut 1)? as usize;
    let mut offset = 5;
    let mut keys = Vec::with_capacity(nkeys);

    for _ in 0..nkeys {
        let blob = read_string(&body, &mut offset)?;
        let comment = String::from_utf8_lossy(&read_string(&body, &mut offset)?).into_owned();

        let algorithm = parse_algorithm(&blob);
        let fingerprint = compute_fingerprint(&blob);

        keys.push(LoadedKey { algorithm, fingerprint, comment });
    }

    Ok(keys)
}

fn read_u32(buf: &[u8], offset: &mut usize) -> Result<u32, Box<dyn std::error::Error>> {
    if *offset + 4 > buf.len() {
        return Err("buffer underflow reading u32".into());
    }
    let v = u32::from_be_bytes(buf[*offset..*offset + 4].try_into()?);
    *offset += 4;
    Ok(v)
}

fn read_string(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let len = read_u32(buf, offset)? as usize;
    if *offset + len > buf.len() {
        return Err("buffer underflow reading string".into());
    }
    let data = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(data)
}

/// Extract the algorithm name string from the start of an SSH wire-format key blob.
fn parse_algorithm(blob: &[u8]) -> String {
    let mut offset = 0;
    match read_string(blob, &mut offset) {
        Ok(name) => String::from_utf8_lossy(&name).into_owned(),
        Err(_) => "unknown".to_owned(),
    }
}

/// Compute the SHA-256 fingerprint of a raw key blob (matches `ssh-add -l`).
fn compute_fingerprint(blob: &[u8]) -> String {
    use sshkey::{HashAlg, PublicKey};

    match PublicKey::from_bytes(blob) {
        Ok(key) => key.fingerprint(HashAlg::Sha256).to_string(),
        Err(_) => "(unknown fingerprint)".to_owned(),
    }
}
