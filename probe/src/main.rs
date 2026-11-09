//! OpenBSD 沙箱探针：在真实 7.9 VM 里验证 Stalwart 用的 unveil/pledge 策略。
//!
//! 它复用 `crates/common/src/manager/sandbox.rs` 的真实代码路径（同文件拷贝），
//! 然后模拟邮件服务器运行时会做的系统调用，确认：
//!   1. 默认 promise 集不会让进程被内核杀掉；
//!   2. 已登记的写目录能正常读写改删；
//!   3. 未登记的目录写操作必须被拒绝（unveil 真的生效）；
//!   4. 绑定端口、unix socket、fork/exec、读系统文件都还能用。

mod sandbox;

// libc crate 只在 openbsd target 上导出 pledge，这里自己声明一份，方便本地类型检查
extern "C" {
    fn pledge(promises: *const libc::c_char, execpromises: *const libc::c_char) -> libc::c_int;
}

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
    let mut sandbox = SandboxPaths::from_env();
    println!("sandbox: {}", sandbox.describe());
    assert!(sandbox.is_enabled(), "sandbox should be enabled on OpenBSD");

    let mut failures = Vec::new();

    // 逐个承诺做诊断：fork 一个子进程单独 pledge 它，看内核对哪个返回 EINVAL
    println!("  -- per-promise check --");
    for (promise, accepted) in check_promises() {
        if accepted {
            println!("  ok   promise {promise}");
        } else {
            // 只作参考：不同 OpenBSD 版本的承诺集不同（例如 tmppath 已移除），
            // 真正的门槛是下面那次完整 pledge
            println!("  note promise {promise}: not accepted by this kernel");
        }
    }

    // 相对路径登记必须在锁定之前：沙箱要把它解析成启动时 cwd 下的绝对路径
    step(
        "relative path registration",
        relative_write(&mut sandbox),
        &mut failures,
    );

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

    // mkstemp：需要 tmppath 承诺 + 临时目录可写
    step(
        "mkstemp in temp dir",
        mkstemp(),
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

/// 逐个验证 promise 是否被当前内核接受（fork 子进程，避免污染主进程的 pledge 状态）。
fn check_promises() -> Vec<(String, bool)> {
    DEFAULT_PLEDGE
        .split_whitespace()
        .map(|promise| {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                let c = match std::ffi::CString::new(promise) {
                    Ok(c) => c,
                    Err(_) => unsafe { libc::_exit(2) },
                };
                let rc = unsafe { pledge(c.as_ptr(), std::ptr::null()) };
                unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
            }
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            (promise.to_string(), status == 0)
        })
        .collect()
}

fn mkstemp() -> Result<String, String> {
    let dir = std::env::temp_dir();
    let mut template: Vec<u8> = format!("{}/probe-XXXXXX", dir.display()).into_bytes();
    template.push(0);
    unsafe {
        let fd = libc::mkstemp(template.as_mut_ptr() as *mut libc::c_char);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let path = std::ffi::CStr::from_ptr(template.as_ptr() as *const libc::c_char)
            .to_string_lossy()
            .into_owned();
        libc::close(fd);
        let _ = std::fs::remove_file(&path);
        Ok(path)
    }
}

/// 在 /tmp 下起一个子进程？不行——直接验证：把 cwd 切到临时目录，
/// 用相对路径登记一个目录，沙箱应把它解析成绝对路径并允许写入。
fn relative_write(sandbox: &mut SandboxPaths) -> Result<String, String> {
    let base = std::env::temp_dir().join("probe-relative");
    std::fs::create_dir_all(&base).map_err(|err| err.to_string())?;
    std::env::set_current_dir(&base).map_err(|err| err.to_string())?;
    std::fs::create_dir_all("data").map_err(|err| err.to_string())?;

    sandbox.allow_write("data");
    let expected = base.join("data");
    if !sandbox
        .write_paths()
        .iter()
        .any(|path| path == &expected.to_string_lossy())
    {
        return Err(format!(
            "relative path was not resolved to {} (got {:?})",
            expected.display(),
            sandbox.write_paths()
        ));
    }
    Ok(format!("resolved to {}", expected.display()))
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
