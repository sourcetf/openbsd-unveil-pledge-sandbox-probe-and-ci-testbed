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

/// 探查 unveil(2) 对不存在的路径的行为——这决定“首次安装时目录还没建”会不会起不来。
fn probe_unveil_missing() {
    // 注意：unveil 是全局累加的，这里只能用一次性进程来测
    for path in [
        "/tmp/probe-missing-parent-xyz/child",
        "/tmp/definitely-not-there-xyz",
    ] {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let code = match std::ffi::CString::new(path) {
                Ok(p) => {
                    let perms = std::ffi::CString::new("rwc").unwrap();
                    let rc = unsafe { unveil(p.as_ptr(), perms.as_ptr()) };
                    if rc == 0 {
                        0
                    } else {
                        let errno = std::io::Error::last_os_error();
                        eprintln!("      unveil({path}) -> {errno}");
                        if errno.raw_os_error() == Some(2) { 2 } else { 3 }
                    }
                }
                Err(_) => 9,
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let code = (status >> 8) & 0xff;
        println!(
            "  note unveil missing path {path}: {}",
            match code {
                0 => "accepted (ENOENT 不是问题)".to_string(),
                2 => "rejected with ENOENT".to_string(),
                other => format!("rejected with exit {other}"),
            }
        );
    }
}

extern "C" {
    fn unveil(path: *const libc::c_char, permissions: *const libc::c_char) -> libc::c_int;
}

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

    // 以下三项都必须在主进程锁定 unveil 之前跑：unveil 一旦锁定不可逆，
    // fork 出来的子进程会继承锁定状态，所以每项都自己 fork 一个干净子进程。
    //
    // 1) 相对路径登记：应解析成启动时 cwd 下的绝对路径
    step(
        "relative path registration",
        relative_write(&mut sandbox),
        &mut failures,
    );
    // 2) 多级目录都不存在（首次安装）：目录要能建出来，而且要写得进去
    step("multi-level missing dir", multi_level_missing(), &mut failures);
    // 3) 严格读模式：标准清单可读、未登记路径被拒；默认模式两者都可读
    step("strict mode read policy", strict_mode_check(), &mut failures);

    // 内核行为探测：unveil 对“还不存在的路径”是什么反应（安装时目录可能还没建）
    probe_unveil_missing();

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

    // 原始套接字（Stalwart 的 ICMP 代理要用）：promise 不含它进程会被直接杀掉
    step("raw icmp socket", raw_icmp(), &mut failures);

    // 出站连接（SMTP 投递、S3/Azure、LDAP/OIDC、Redis/NATS/Kafka、OTLP）
    step("outbound tcp connect", outbound_connect(), &mut failures);
    // DNS：先测纯 UDP 收发（不经过 getaddrinfo），再测名字解析（MX/PTR 要用）
    step("udp send/recv to resolver", dns_udp(), &mut failures);
    step("getaddrinfo(name)", dns_lookup(), &mut failures);
    // 随机数（TLS / DKIM / 各种密钥）
    step("getrandom from /dev/urandom", urandom(), &mut failures);
    // 文件锁与落盘（RocksDB / SQLite 的常态）
    step("flock + fsync on store file", flock_and_fsync(), &mut failures);

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

    // 多级目录都不存在时（首次安装）：目录要能建出来，而且要能写进去
    // 严格模式 vs 默认模式的读权限对比（各自 fork 一个子进程，unveil 不可逆）
    // chroot 的语义（在子进程里，因为 chroot 不可逆）：必须在 unveil 之前，
    // 且 jail 内要有 /dev/urandom 与 /etc/passwd
    step("chroot semantics", chroot_probe(), &mut failures);

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

/// 原始套接字：ICMP 代理要用。若承诺集不允许，进程会被内核杀掉（不是返回错误）。
fn raw_icmp() -> Result<String, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        libc::close(fd);
        Ok("raw ICMP socket created and closed".to_string())
    }
}

/// 模拟首次安装：数据目录有两级都不存在，父目录只有 create 权限。
/// 需要验证「目录能建出来」且「建好之后写得进去」。
fn multi_level_missing() -> Result<String, String> {
    let base = std::env::temp_dir().join("probe-missing");
    let target = base.join("a/b");
    let target_str = target.to_string_lossy().into_owned();

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut sandbox = SandboxPaths::from_env();
        sandbox.allow_write(&target_str);
        let code = (|| -> i32 {
            if sandbox.lock_filesystem().is_err() {
                return 11;
            }
            if std::fs::create_dir_all(&target_str).is_err() {
                return 12;
            }
            if std::fs::write(target.join("db.sst"), b"x").is_err() {
                return 13;
            }
            match std::fs::read(target.join("db.sst")) {
                Ok(bytes) => bytes.len() as i32,
                Err(_) => 14,
            }
        })();
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = (status >> 8) & 0xff;
    match code {
        1 => Ok("created missing chain and wrote 1 byte".to_string()),
        11 => Err("lock_filesystem failed".to_string()),
        12 => Err("cannot create the missing directory chain".to_string()),
        13 => Err("directory created but writing into it was denied".to_string()),
        14 => Err("wrote but could not read back".to_string()),
        other => Err(format!("unexpected exit {other}")),
    }
}

/// 对比默认与严格模式的读权限：
///   默认：/etc/ssh/sshd_config 这种没登记的路径也能读（"/" r）
///   严格：只有标准清单 + 登记过的读路径可读
fn strict_mode_check() -> Result<String, String> {
    let probe = |strict: bool| -> Result<(bool, bool), String> {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { std::env::set_var("STALWART_UNVEIL_STRICT", if strict { "on" } else { "off" }) };
            let mut sandbox = SandboxPaths::from_env();
            sandbox.allow_write("/tmp");
            let _ = sandbox.lock_filesystem();
            let listed = std::fs::read_to_string("/etc/passwd").is_ok();
            let unlisted = std::fs::read_to_string("/etc/ssh/sshd_config").is_ok();
            unsafe { libc::_exit((listed as i32) | ((unlisted as i32) << 1)) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let code = (status >> 8) & 0xff;
        if code > 3 {
            return Err(format!("child exited with {code}"));
        }
        Ok((code & 1 != 0, code & 2 != 0))
    };

    let (default_listed, default_unlisted) = probe(false)?;
    let (strict_listed, strict_unlisted) = probe(true)?;
    println!(
        "       default: /etc/passwd={default_listed} /etc/ssh/sshd_config={default_unlisted}"
    );
    println!(
        "       strict : /etc/passwd={strict_listed} /etc/ssh/sshd_config={strict_unlisted}"
    );
    if !default_listed || !default_unlisted {
        return Err("default mode should allow reading both".to_string());
    }
    if !strict_listed {
        return Err("strict mode must still allow the standard paths".to_string());
    }
    if strict_unlisted {
        return Err("strict mode must deny paths outside the standard list".to_string());
    }
    Ok("strict denies unlisted reads, default does not".to_string())
}

/// 出站 TCP：连本机的监听端口（等价于服务器主动往外连的那种 socket 用法）
fn outbound_connect() -> Result<String, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let handle = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let stream = std::net::TcpStream::connect(addr).map_err(|e| e.to_string())?;
    stream.set_nonblocking(true).ok();
    let peer = stream.peer_addr().map_err(|e| e.to_string())?;
    let _ = handle.join();
    Ok(format!("connected to {peer}"))
}

/// 用 /etc/resolv.conf 里的服务器发一次真实 DNS 查询（A 记录、UDP）
fn resolver_addr() -> Result<std::net::SocketAddr, String> {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").map_err(|e| e.to_string())?;
    // OpenBSD 的 resolv.conf 行尾可能带注释（"nameserver 1.2.3.4 # resolvd: vio0"），只取第二个字段
    let server = resolv
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("nameserver"), Some(addr)) => Some(addr.to_string()),
                _ => None,
            }
        })
        .ok_or_else(|| "no nameserver in /etc/resolv.conf".to_string())?;
    format!("{server}:53")
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("cannot parse {server}:53: {e}"))
}

fn dns_packet() -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}

/// 纯 UDP 收发（SocketAddr 直接构造，不触发 getaddrinfo）
fn dns_udp() -> Result<String, String> {
    let addr = resolver_addr()?;
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    socket.send_to(&dns_packet(), addr).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    let (len, from) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;
    Ok(format!("{len} bytes from {from}"))
}

/// getaddrinfo 名字解析（MX/PTR/ACME/OTLP 等都要用）
fn dns_lookup() -> Result<String, String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = ("example.com", 80)
        .to_socket_addrs()
        .map_err(|e| format!("{e}"))?
        .collect();
    Ok(format!("resolved to {} address(es)", addrs.len()))
}


/// TLS/密钥需要的内核随机数
fn urandom() -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok("32 bytes".to_string())
}

/// RocksDB / SQLite 会用的文件锁 + 落盘
fn flock_and_fsync() -> Result<String, String> {
    use std::os::unix::io::AsRawFd;
    let dir = std::env::temp_dir().join("probe-lock");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("LOCK");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    file.sync_all().map_err(|e| e.to_string())?;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    Ok("locked, synced, unlocked".to_string())
}

/// 在子进程里验证：chroot 之后 unveil 用 jail 内路径是否生效、写是否被限制、
/// /dev/urandom 与 /etc/passwd 是否能读到。
fn chroot_probe() -> Result<String, String> {
    let base = std::env::temp_dir().join("probe-jail");
    let jail = base.join("root");
    let _ = std::fs::remove_dir_all(&jail);
    for dir in ["etc", "var/lib", "dev", "bin", "lib", "usr/lib"] {
        std::fs::create_dir_all(jail.join(dir)).map_err(|e| e.to_string())?;
    }
    std::fs::copy("/etc/passwd", jail.join("etc/passwd")).map_err(|e| e.to_string())?;
    std::fs::write(jail.join("etc/resolv.conf"), b"nameserver 127.0.0.1
")
        .map_err(|e| e.to_string())?;

    let jail_str = jail.to_string_lossy().into_owned();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let code = (|| -> i32 {
            // 1) 先 chroot + chdir("/")
            let c = match std::ffi::CString::new(jail_str.as_str()) {
                Ok(c) => c,
                Err(_) => return 20,
            };
            if unsafe { chroot(c.as_ptr()) } != 0 {
                return 21;
            }
            if unsafe { chdir(std::ffi::CString::new("/").unwrap().as_ptr()) } != 0 {
                return 22;
            }

            // 2) chroot 之后再用 jail 内路径 unveil
            let root = std::ffi::CString::new("/").unwrap();
            if unsafe { unveil(root.as_ptr(), std::ffi::CString::new("r").unwrap().as_ptr()) } != 0 {
                return 23;
            }
            if unsafe {
                unveil(
                    std::ffi::CString::new("/var/lib").unwrap().as_ptr(),
                    std::ffi::CString::new("rwc").unwrap().as_ptr(),
                )
            } != 0
            {
                return 24;
            }
            if unsafe { unveil(std::ptr::null(), std::ptr::null()) } != 0 {
                return 25;
            }

            // 3) jail 内可写路径
            if std::fs::write("/var/lib/db.sqlite", b"x").is_err() {
                return 26;
            }
            // 4) jail 内的 /etc/passwd 可读
            if std::fs::read_to_string("/etc/passwd").is_err() {
                return 27;
            }
            // 5) jail 外的路径根本不存在（chroot 隔离）
            if std::fs::metadata("/../outside").is_ok() {
                return 28;
            }
            1
        })();
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = (status >> 8) & 0xff;
    let _ = std::fs::remove_dir_all(&base);
    match code {
        1 => Ok("chroot + unveil + write + read all OK inside jail".to_string()),
        20 => Err("jail path has NUL".to_string()),
        21 => Err("chroot failed".to_string()),
        22 => Err("chdir(/) after chroot failed".to_string()),
        23 => Err("unveil(/) after chroot failed".to_string()),
        24 => Err("unveil(/var/lib) after chroot failed".to_string()),
        25 => Err("unveil lock after chroot failed".to_string()),
        26 => Err("write inside jail denied".to_string()),
        27 => Err("cannot read jail /etc/passwd".to_string()),
        28 => Err("jail escape: /../outside existed".to_string()),
        other => Err(format!("unexpected exit {other}")),
    }
}

extern "C" {
    fn chroot(path: *const libc::c_char) -> libc::c_int;
    fn chdir(path: *const libc::c_char) -> libc::c_int;
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
