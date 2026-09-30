use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::env;
use std::fs;
#[cfg(target_os = "windows")]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const MAX_CONTEXT_BYTES: usize = 32_768;
const CONFIG_PREFIX: &str = "GOV_PROBE_CONFIG\n";

struct Attempt {
    name: String,
    allowed: bool,
    result: String,
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn base64_decode(value: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        if byte == b'=' {
            break;
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("invalid base64".to_string()),
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Ok(output)
}

fn sealed_payloads(envelope: &str) -> Result<Vec<Vec<u8>>, String> {
    if !envelope.trim_start().starts_with("{\"inputs\"") {
        return Err("sealed input envelope required".to_string());
    }
    for forbidden in ["\"prompt\"", "\"history\"", "\"messages\"", "\"tools\""] {
        if envelope.contains(forbidden) {
            return Err("unmediated context field".to_string());
        }
    }
    let mut payloads = Vec::new();
    let mut remaining = envelope;
    let key = "\"content_base64\"";
    while let Some(position) = remaining.find(key) {
        remaining = &remaining[position + key.len()..];
        let colon = remaining.find(':').ok_or("invalid content field")?;
        remaining = remaining[colon + 1..].trim_start();
        if !remaining.starts_with('"') {
            return Err("content must be a string".to_string());
        }
        remaining = &remaining[1..];
        let end = remaining.find('"').ok_or("unterminated content")?;
        payloads.push(base64_decode(&remaining[..end])?);
        remaining = &remaining[end + 1..];
    }
    if payloads.is_empty() {
        return Err("sealed inputs required".to_string());
    }
    Ok(payloads)
}

fn probe_config(payloads: &[Vec<u8>]) -> Result<BTreeMap<String, String>, String> {
    for payload in payloads {
        let text = String::from_utf8_lossy(payload);
        if let Some(body) = text.strip_prefix(CONFIG_PREFIX) {
            let mut config = BTreeMap::new();
            for line in body.lines().filter(|line| !line.is_empty()) {
                let (name, value) = line.split_once('=').ok_or("invalid probe config")?;
                if !name
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
                {
                    return Err("invalid probe config key".to_string());
                }
                config.insert(name.to_string(), value.to_string());
            }
            return Ok(config);
        }
    }
    Err("governed probe config missing".to_string())
}

fn attempt<F>(rows: &mut Vec<Attempt>, name: impl Into<String>, operation: F)
where
    F: FnOnce() -> Result<String, String>,
{
    let name = name.into();
    match operation() {
        Ok(result) => rows.push(Attempt {
            name,
            allowed: true,
            result,
        }),
        Err(result) => rows.push(Attempt {
            name,
            allowed: false,
            result,
        }),
    }
}

fn io_result<T>(result: io::Result<T>, success: &str) -> Result<String, String> {
    result.map(|_| success.to_string()).map_err(|error| {
        format!(
            "{}:errno={}",
            error.kind(),
            error.raw_os_error().unwrap_or(-1)
        )
    })
}

fn tcp_connect(host: &str, port: u16) -> Result<String, String> {
    let ip: IpAddr = host.parse().map_err(|_| "invalid address".to_string())?;
    io_result(
        TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(400)),
        "TCP connect succeeded",
    )
}

fn dns_resolve(host: &str, port: u16) -> Result<String, String> {
    (host, port)
        .to_socket_addrs()
        .map(|addresses| format!("resolved {} addresses", addresses.count()))
        .map_err(|error| {
            format!(
                "{}:errno={}",
                error.kind(),
                error.raw_os_error().unwrap_or(-1)
            )
        })
}

fn host_connect(host: &str, port: u16) -> Result<String, String> {
    let addresses = (host, port).to_socket_addrs().map_err(|error| {
        format!(
            "{}:errno={}",
            error.kind(),
            error.raw_os_error().unwrap_or(-1)
        )
    })?;
    let mut last_error = "no resolved address".to_string();
    for address in addresses {
        match TcpStream::connect_timeout(&address, Duration::from_millis(400)) {
            Ok(_) => return Ok("TCP connect succeeded".to_string()),
            Err(error) => {
                last_error = format!(
                    "{}:errno={}",
                    error.kind(),
                    error.raw_os_error().unwrap_or(-1)
                );
            }
        }
    }
    Err(last_error)
}

fn list_path(path: &str) -> Result<String, String> {
    fs::read_dir(path)
        .map(|entries| format!("listed {} entries", entries.count()))
        .map_err(|error| {
            format!(
                "{}:errno={}",
                error.kind(),
                error.raw_os_error().unwrap_or(-1)
            )
        })
}

fn read_file(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| format!("read {} bytes", bytes.len()))
        .map_err(|error| {
            format!(
                "{}:errno={}",
                error.kind(),
                error.raw_os_error().unwrap_or(-1)
            )
        })
}

fn write_and_read(path: &Path) -> Result<String, String> {
    fs::write(path, b"worker-private")
        .and_then(|_| fs::read(path))
        .and_then(|bytes| {
            if bytes == b"worker-private" {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "marker mismatch",
                ))
            }
        })
        .map(|_| "write/read succeeded".to_string())
        .map_err(|error| {
            format!(
                "{}:errno={}",
                error.kind(),
                error.raw_os_error().unwrap_or(-1)
            )
        })
}

fn private_storage_paths() -> [(&'static str, PathBuf); 2] {
    if cfg!(target_family = "wasm") {
        [
            ("/tmp", PathBuf::from("/tmp")),
            ("/dev/shm", PathBuf::from("/dev/shm")),
        ]
    } else if cfg!(target_os = "windows") {
        let private_tmp = env::temp_dir();
        let private_root = private_tmp.parent().unwrap_or(&private_tmp);
        [
            ("/tmp", private_tmp.clone()),
            ("/dev/shm", private_root.join("shm")),
        ]
    } else {
        [
            ("/tmp", env::temp_dir()),
            ("/dev/shm", PathBuf::from("/dev/shm")),
        ]
    }
}

#[cfg(target_os = "linux")]
fn unexpected_environment(data: &[u8]) -> Vec<String> {
    let allowed: BTreeSet<&str> = ["HOME", "PATH"].into_iter().collect();
    let mut unexpected = BTreeSet::new();
    for item in data
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
    {
        let name = item.split(|byte| *byte == b'=').next().unwrap_or_default();
        let name = String::from_utf8_lossy(name).to_string();
        if !allowed.contains(name.as_str()) {
            unexpected.insert(name);
        }
    }
    unexpected.into_iter().collect()
}

#[cfg(target_os = "linux")]
fn unix_connect(path: &str) -> Result<String, String> {
    use std::os::unix::net::UnixStream;
    io_result(UnixStream::connect(path), "Unix socket connect succeeded")
}

#[cfg(target_os = "linux")]
fn linux_attempts(rows: &mut Vec<Attempt>, config: &BTreeMap<String, String>) {
    for path in [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/ipc/substrate.sock",
        "/tmp/agent.sock",
    ] {
        attempt(rows, format!("unix_socket:{path}"), || unix_connect(path));
    }
    for path in [
        "/workspace",
        "/ipc",
        "/run/secrets",
        "/host",
        "/mnt/c",
        "/mnt/e",
        "/run/desktop/mnt/host",
        "/model",
    ] {
        attempt(rows, format!("unexpected_mount:{path}"), || list_path(path));
    }
    if let Some(host_marker) = config.get("host_marker") {
        for path in [
            format!("/workspace/{host_marker}"),
            format!("/host/{host_marker}"),
            format!("/mnt/e/gov-substrate/{host_marker}"),
            format!("/run/desktop/mnt/host/e/gov-substrate/{host_marker}"),
        ] {
            attempt(rows, format!("host_file:{path}"), || {
                read_file(Path::new(&path))
            });
        }
    }

    let own_environment = env::vars()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("\0");
    let leaked = unexpected_environment(own_environment.as_bytes());
    rows.push(Attempt {
        name: "environment_secrets".to_string(),
        allowed: !leaked.is_empty(),
        result: format!("unexpected_names={leaked:?}"),
    });
    for (name, path) in [
        ("proc_self_secrets", "/proc/self/environ"),
        ("proc_pid1_secrets", "/proc/1/environ"),
    ] {
        match fs::read(path) {
            Ok(data) => {
                let leaked = unexpected_environment(&data);
                rows.push(Attempt {
                    name: name.to_string(),
                    allowed: !leaked.is_empty(),
                    result: format!("unexpected_names={leaked:?}"),
                });
            }
            Err(error) => rows.push(Attempt {
                name: name.to_string(),
                allowed: false,
                result: format!(
                    "{}:errno={}",
                    error.kind(),
                    error.raw_os_error().unwrap_or(-1)
                ),
            }),
        }
    }
    if let Some(host_pid) = config.get("host_pid") {
        let path = format!("/proc/{host_pid}/status");
        attempt(rows, "unrelated_host_pid", || read_file(Path::new(&path)));
    }
    let visible_pids = fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    rows.push(Attempt {
        name: "unrelated_processes".to_string(),
        allowed: visible_pids.iter().any(|pid| *pid != std::process::id()),
        result: format!(
            "container_pids={visible_pids:?};self={}",
            std::process::id()
        ),
    });
    for (name, path) in [
        ("private_ipc_namespace", "/proc/self/ns/ipc"),
        ("private_mount_namespace", "/proc/self/ns/mnt"),
    ] {
        attempt(rows, name, || {
            fs::read_link(path)
                .map(|link| link.display().to_string())
                .map_err(|error| {
                    format!(
                        "{}:errno={}",
                        error.kind(),
                        error.raw_os_error().unwrap_or(-1)
                    )
                })
        });
    }
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn OpenProcess(
        desired_access: u32,
        inherit_handle: i32,
        process_id: u32,
    ) -> *mut std::ffi::c_void;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    fn IsProcessInJob(
        process_handle: *mut std::ffi::c_void,
        job_handle: *mut std::ffi::c_void,
        result: *mut i32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(
        process_handle: *mut std::ffi::c_void,
        desired_access: u32,
        token_handle: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn IsTokenRestricted(token_handle: *mut std::ffi::c_void) -> i32;
    fn GetTokenInformation(
        token_handle: *mut std::ffi::c_void,
        token_information_class: u32,
        token_information: *mut std::ffi::c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
fn windows_security_attempts(
    rows: &mut Vec<Attempt>,
    config: &BTreeMap<String, String>,
) {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_VM_READ: u32 = 0x0010;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_IS_APP_CONTAINER: u32 = 29;

    if let Some(host_pid) = config.get("host_pid") {
        attempt(rows, "windows_unrelated_process", || {
            let pid = host_pid
                .parse::<u32>()
                .map_err(|_| "invalid host pid".to_string())?;
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                    0,
                    pid,
                )
            };
            if handle.is_null() {
                return Err(io::Error::last_os_error().to_string());
            }
            unsafe { CloseHandle(handle) };
            Ok("host process opened".to_string())
        });
    }
    if let Some(path) = config.get("host_canary_path") {
        attempt(rows, "windows_host_file", || read_file(Path::new(path)));
    }
    attempt(rows, "windows_docker_pipe", || {
        io_result(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(r"\\.\pipe\docker_engine"),
            "Docker named pipe opened",
        )
    });

    let mut in_job = 0_i32;
    let job_query = unsafe {
        IsProcessInJob(
            GetCurrentProcess(),
            std::ptr::null_mut(),
            &mut in_job,
        )
    };
    rows.push(Attempt {
        name: "windows_job_object".to_string(),
        allowed: job_query != 0 && in_job != 0,
        result: format!("query_ok={};in_job={}", job_query != 0, in_job != 0),
    });

    let mut token = std::ptr::null_mut();
    let token_opened = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    } != 0;
    if !token_opened {
        rows.push(Attempt {
            name: "windows_restricted_token".to_string(),
            allowed: false,
            result: io::Error::last_os_error().to_string(),
        });
        rows.push(Attempt {
            name: "windows_appcontainer".to_string(),
            allowed: false,
            result: "token unavailable".to_string(),
        });
        return;
    }
    let restricted = unsafe { IsTokenRestricted(token) } != 0;
    rows.push(Attempt {
        name: "windows_restricted_token".to_string(),
        allowed: restricted,
        result: format!("restricted={restricted}"),
    });
    let mut appcontainer = 0_u32;
    let mut returned = 0_u32;
    let query_ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_IS_APP_CONTAINER,
            (&mut appcontainer as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    } != 0;
    unsafe { CloseHandle(token) };
    rows.push(Attempt {
        name: "windows_appcontainer".to_string(),
        allowed: query_ok && appcontainer != 0,
        result: format!(
            "query_ok={query_ok};appcontainer={};bytes={returned}",
            appcontainer != 0
        ),
    });
}

#[cfg(target_os = "windows")]
fn linux_attempts(rows: &mut Vec<Attempt>, config: &BTreeMap<String, String>) {
    for name in [
        "unix_socket:/var/run/docker.sock",
        "unix_socket:/run/docker.sock",
        "unix_socket:/run/containerd/containerd.sock",
        "unix_socket:/ipc/substrate.sock",
        "unix_socket:/tmp/agent.sock",
        "proc_self_secrets",
        "proc_pid1_secrets",
        "unrelated_host_pid",
        "unrelated_processes",
        "private_ipc_namespace",
        "private_mount_namespace",
    ] {
        rows.push(Attempt {
            name: name.to_string(),
            allowed: false,
            result: "unsupported_by_target".to_string(),
        });
    }
    for path in [
        "/workspace",
        "/ipc",
        "/run/secrets",
        "/host",
        "/mnt/c",
        "/mnt/e",
        "/run/desktop/mnt/host",
        "/model",
    ] {
        attempt(rows, format!("unexpected_mount:{path}"), || list_path(path));
    }
    let allowed = [
        "ComSpec", "LOCALAPPDATA", "Path", "SystemDrive", "SystemRoot",
        "TEMP", "TMP", "USERPROFILE", "windir",
    ];
    let leaked = env::vars()
        .map(|(name, _)| name)
        .filter(|name| !allowed.contains(&name.as_str()))
        .collect::<Vec<_>>();
    rows.push(Attempt {
        name: "environment_secrets".to_string(),
        allowed: !leaked.is_empty(),
        result: format!("unexpected_names={leaked:?}"),
    });
    windows_security_attempts(rows, config);
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn linux_attempts(rows: &mut Vec<Attempt>, config: &BTreeMap<String, String>) {
    for name in [
        "unix_socket:/var/run/docker.sock",
        "unix_socket:/run/docker.sock",
        "unix_socket:/run/containerd/containerd.sock",
        "unix_socket:/ipc/substrate.sock",
        "unix_socket:/tmp/agent.sock",
        "proc_self_secrets",
        "proc_pid1_secrets",
        "unrelated_host_pid",
        "unrelated_processes",
        "private_ipc_namespace",
        "private_mount_namespace",
    ] {
        rows.push(Attempt {
            name: name.to_string(),
            allowed: false,
            result: "unsupported_by_target".to_string(),
        });
    }
    for path in [
        "/workspace",
        "/ipc",
        "/run/secrets",
        "/host",
        "/mnt/c",
        "/mnt/e",
        "/run/desktop/mnt/host",
        "/model",
    ] {
        attempt(rows, format!("unexpected_mount:{path}"), || list_path(path));
    }
    if let Some(host_marker) = config.get("host_marker") {
        for path in [
            format!("/workspace/{host_marker}"),
            format!("/host/{host_marker}"),
            format!("/mnt/e/gov-substrate/{host_marker}"),
            format!("/run/desktop/mnt/host/e/gov-substrate/{host_marker}"),
        ] {
            attempt(rows, format!("host_file:{path}"), || {
                read_file(Path::new(&path))
            });
        }
    }
    let leaked = env::vars()
        .map(|(name, _)| name)
        .filter(|name| name != "HOME" && name != "PATH")
        .collect::<Vec<_>>();
    rows.push(Attempt {
        name: "environment_secrets".to_string(),
        allowed: !leaked.is_empty(),
        result: format!("unexpected_names={leaked:?}"),
    });
}

fn network_attempts(rows: &mut Vec<Attempt>, config: &BTreeMap<String, String>) {
    attempt(rows, "direct_ipv4", || tcp_connect("198.51.100.1", 80));
    attempt(rows, "direct_ipv6", || {
        tcp_connect("2606:4700:4700::1111", 443)
    });
    attempt(rows, "dns_public", || dns_resolve("example.com", 443));
    attempt(rows, "dns_other_container", || {
        dns_resolve("environment-target", 8002)
    });
    attempt(rows, "host_docker_internal", || {
        host_connect("host.docker.internal", 80)
    });
    attempt(rows, "cloud_metadata_ipv4", || {
        tcp_connect("169.254.169.254", 80)
    });
    attempt(rows, "cloud_metadata_ipv6", || {
        tcp_connect("fd00:ec2::254", 80)
    });
    if let Some(target) = config.get("target_ip") {
        attempt(rows, "other_container", || tcp_connect(target, 8002));
    }
    if let Some(gateway) = config.get("gateway_ip") {
        attempt(rows, "docker_gateway", || tcp_connect(gateway, 80));
    }
    for port in [80_u16, 2375, 8000, 8001, 8002, 8080] {
        attempt(rows, format!("loopback_ipv4:{port}"), || {
            tcp_connect("127.0.0.1", port)
        });
    }
    attempt(rows, "loopback_ipv6", || tcp_connect("::1", 8002));
}

fn marker_path(parent: &str, marker: &str) -> PathBuf {
    Path::new(parent).join(marker)
}

fn write_marker_report(config: &BTreeMap<String, String>, rows: &mut Vec<Attempt>) {
    let marker = config
        .get("marker")
        .map(String::as_str)
        .unwrap_or("probe-marker");
    for (logical, parent) in private_storage_paths() {
        let path = parent.join(marker);
        attempt(rows, format!("write_private:{logical}"), || {
            write_and_read(&path)
        });
    }
}

fn scan(config: &BTreeMap<String, String>, rows: &mut Vec<Attempt>) {
    network_attempts(rows, config);
    linux_attempts(rows, config);
    let marker = config
        .get("marker")
        .map(String::as_str)
        .unwrap_or("probe-marker");
    for (logical, parent) in private_storage_paths() {
        let previous = marker_path(parent.to_str().unwrap_or("/tmp"), marker);
        attempt(
            rows,
            format!("previous_worker:{logical}"),
            || read_file(&previous),
        );
    }
    let current = format!(
        "current-{}",
        config.get("nonce").map(String::as_str).unwrap_or("probe")
    );
    for (logical, parent) in private_storage_paths() {
        let path = parent.join(&current);
        attempt(
            rows,
            format!("private_storage:{logical}"),
            || write_and_read(&path),
        );
    }
}

fn target_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_family = "wasm") {
        "wasi"
    } else {
        "other"
    }
}

fn emit_report(context_bytes: usize, config: &BTreeMap<String, String>, rows: &[Attempt]) {
    let attempts = rows
        .iter()
        .map(|row| {
            format!(
                "{{\"attempt\":\"{}\",\"allowed\":{},\"result\":\"{}\"}}",
                json_escape(&row.name),
                row.allowed,
                json_escape(&row.result)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let report = format!(
        "{{\"schema\":1,\"target\":\"{}\",\"nonce\":\"{}\",\"context_bytes\":{},\"attempts\":[{}]}}",
        target_name(),
        json_escape(config.get("nonce").map(String::as_str).unwrap_or("")),
        context_bytes,
        attempts
    );
    println!("{{\"text\":\"{}\"}}", json_escape(&report));
}

fn run() -> Result<(), String> {
    let mut input = Vec::new();
    io::stdin()
        .take((MAX_CONTEXT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    if input.len() > MAX_CONTEXT_BYTES {
        return Err("sealed context exceeds worker limit".to_string());
    }
    let envelope = String::from_utf8(input.clone()).map_err(|_| "context must be UTF-8")?;
    let payloads = sealed_payloads(&envelope)?;
    let config = probe_config(&payloads)?;
    let nonce = config.get("nonce").ok_or("probe nonce missing")?;
    let mut rows = vec![Attempt {
        name: "sealed_context_stdin".to_string(),
        allowed: !nonce.is_empty(),
        result: format!("received_nonce={nonce}"),
    }];
    match config.get("mode").map(String::as_str).unwrap_or("scan") {
        "echo" => {}
        "scan" => scan(&config, &mut rows),
        "write_marker" => write_marker_report(&config, &mut rows),
        "hold" => loop {
            thread::sleep(Duration::from_secs(60));
        },
        _ => return Err("unsupported probe mode".to_string()),
    }
    emit_report(input.len(), &config, &rows);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "runtime probe failed: {error}");
        std::process::exit(1);
    }
}
