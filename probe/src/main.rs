//! OpenBSD 沙箱探针：在真实 7.9 VM 里验证 Stalwart 用的 unveil/pledge 策略。
//!
//! 它复用 `crates/common/src/manager/sandbox.rs` 的真实代码路径（同文件拷贝），
//! 然后模拟邮件服务器运行时会做的系统调用，确认：
//!   1. 默认 promise 集不会让进程被内核杀掉；
//!   2. 已登记的写目录能正常读写改删；
//!   3. 未登记的目录写操作必须被拒绝（unveil 真的生效）；
//!   4. 绑定端口、unix socket、fork/exec、读系统文件都还能用。

mod sandbox;

use sandbox::{SandboxPaths, DEFAULT_PLEDGE};
use std::io::Write;

fn step(name: &str, result: Result<String, String>, failures: &mut Vec<String>) {
    match result {
        Ok(msg) => println!("  ok   {name}: {msg}"),
        Err(err) => {
            println!("  FAIL {name}: {err}");
            failures.push(format!("{name}: {err}"));
        }
    }
}

fn main() {
    let data_dir = std::env::var("PROBE_DATA_DIR").unwrap_or_else(|_| "/tmp/probe-data".to_string());
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    // 用环境变量喂给真实代码：只登记 data_dir、可执行文件等
    std::env::set_var(
        "STALWART_UNVEIL_EXTRA",
        format!("{data_dir}:rwc,/bin/echo:rx,/bin/sh:rx"),
    );
    let sandbox = SandboxPaths::from_env();
    println!("sandbox: {}", sandbox.describe());
    assert!(sandbox.is_enabled(), "sandbox should be enabled on OpenBSD");

    let mut failures = Vec::new();

    if let Err(err) = sandbox.lock_filesystem() {
        println!("  FAIL unveil: {err}");
        std::process::exit(1);
    }
    println!("  ok   unveil: locked");

    if let Err(err) = sandbox.apply_pledge() {
        println!("  FAIL pledge: {err}");
        std::process::exit(1);
    }
    println!("  ok   pledge: {}", DEFAULT_PLEDGE);

    // 存储目录里的常态操作（RocksDB / SQLite / 日志轮转）
    step(
        "write file in data dir",
        std::fs::write(format!("{data_dir}/db.sst"), b"hello")
            .map(|_| "wrote".to_string())
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "read file in data dir",
        std::fs::read(format!("{data_dir}/db.sst"))
            .map(|bytes| format!("{} bytes", bytes.len()))
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "rename in data dir",
        std::fs::rename(format!("{data_dir}/db.sst"), format!("{data_dir}/db.sst.tmp"))
            .map(|_| "renamed".to_string())
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "unlink in data dir",
        std::fs::remove_file(format!("{data_dir}/db.sst.tmp"))
            .map(|_| "removed".to_string())
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "append to log file",
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{data_dir}/stalwart.log"))
            .and_then(|mut file| file.write_all(b"log line\n"))
            .map(|_| "appended".to_string())
            .map_err(|err| err.to_string()),
        &mut failures,
    );

    // 只读的系统文件（unveil "/" r 覆盖）
    step(
        "read /etc/resolv.conf",
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|text| format!("{} bytes", text.len()))
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "read /etc/ssl",
        std::fs::read_dir("/etc/ssl")
            .map(|dir| format!("{} entries", dir.count()))
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "read /etc/services",
        std::fs::read_to_string("/etc/services")
            .map(|text| format!("{} bytes", text.len()))
            .map_err(|err| err.to_string()),
        &mut failures,
    );

    // 网络
    step(
        "tcp bind",
        std::net::TcpListener::bind("127.0.0.1:0")
            .map(|listener| listener.local_addr().map(|a| a.to_string()).unwrap_or_default())
            .map_err(|err| err.to_string()),
        &mut failures,
    );
    step(
        "unix socket bind",
        std::os::unix::net::UnixListener::bind(format!("{data_dir}/probe.sock"))
            .map(|_| "bound".to_string())
            .map_err(|err| err.to_string()),
        &mut failures,
    );

    // 脚本插件用的 fork/exec
    step(
        "fork/exec /bin/echo",
        std::process::Command::new("/bin/echo")
            .arg("sandbox-ok")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .map_err(|err| err.to_string()),
        &mut failures,
    );

    // getpw：读用户/组信息
    step(
        "getpwuid(getuid)",
        getpw(),
        &mut failures,
    );

    // 反例：未登记的目录必须写不进去（否则 unveil 没生效）
    let outside = "/var/probe-should-fail";
    match std::fs::write(outside, b"x") {
        Ok(_) => {
            let _ = std::fs::remove_file(outside);
            println!("  FAIL unveil enforcement: writing to {outside} succeeded");
            failures.push("unveil enforcement: write outside allowed".to_string());
        }
        Err(err) => println!("  ok   unveil enforcement: {outside} -> {err}"),
    }

    println!();
    if failures.is_empty() {
        println!("ALL CHECKS PASSED");
    } else {
        println!("{} CHECK(S) FAILED", failures.len());
        for failure in &failures {
            println!("  - {failure}");
        }
        std::process::exit(1);
    }
}

fn getpw() -> Result<String, String> {
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let name = std::ffi::CStr::from_ptr((*pw).pw_name);
        Ok(format!("uid {uid} -> {}", name.to_string_lossy()))
    }
}
