//! OpenBSD 沙箱：unveil(2) + pledge(2)，以及可选的 chroot(2)。
//!
//! 路径不是一份全局配置，而是由各组件在启动时登记自己的目录（见
//! `BootManager` 里对 data/blob/search 存储、cache swap、tracer 日志、
//! ACME 工作目录的收集）。默认对整个文件系统只给读权限——配置里的路径可以
//! 是任意位置，逐个枚举并不现实；写权限只给上面登记过的目录。
//!
//! 环境变量：
//!   STALWART_SANDBOX=off                 完全关闭沙箱（默认开启）
//!   STALWART_CHROOT=/jail                先 chroot（要求配置里的路径都在 jail 内，
//!                                        且必须在放弃 root 权限前调用）
//!   STALWART_PLEDGE="stdio rpath ..."    自定义 pledge 承诺集
//!   STALWART_UNVEIL_EXTRA="/opt/x:rx,/srv/y:rwc"
//!                                        追加 unveil 条目，权限用 r/w/c/d/x 表示
//!
//! 注意：pledge 之后进程只能使用承诺集里的系统调用，越界会被内核直接杀掉。
//! 默认承诺集刻意给得比较宽（含 exec、proc 等，脚本插件要用），需要收紧时
//! 用 STALWART_PLEDGE 覆盖并自行验证。
//!
//! 已知限制（unveil 一旦锁定就不能再放开，这是内核行为）：
//!   * 通过 Web 控制台把存储/日志等**改成新的目录**时，新目录要等重启进程后
//!     才可写；运行中会报权限错误。改配置后重启即可，或临时用
//!     STALWART_UNVEIL_EXTRA 把它加进来。
//!   * 脚本插件的 `exec` 需要被执行的文件带 `x` 权限，而命令是脚本里动态指定的，
//!     无法预先枚举：要用它请显式登记，例如
//!     STALWART_UNVEIL_EXTRA="/bin/sh:rx,/usr/local/bin/your-tool:rx"。
//!   * chroot 需自行保证配置里的路径在 jail 内（相对路径按启动时的 cwd 解析）。

use std::fmt;

/// 默认 pledge 承诺集：覆盖邮件服务器的常见需求（文件、网络、DNS、UNIX socket、
/// 读取用户/组信息、fork/exec 脚本插件、伪终端、进程/内存信息）。
/// 逐一在 OpenBSD 7.9 上验证过：这些名字都被内核接受（`tmppath` 已被移除，
/// 7.9 上 pledge 会报 EINVAL，不要加）。
pub const DEFAULT_PLEDGE: &str = "stdio rpath wpath cpath dpath fattr flock inet unix dns getpw id proc exec tty ps vminfo";

#[derive(Debug, Default, Clone)]
#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
pub struct SandboxPaths {
    enabled: bool,
    read: Vec<String>,
    write: Vec<String>,
    exec: Vec<String>,
    chroot: Option<String>,
    pledge: Option<String>,
}

impl SandboxPaths {
    /// 从环境变量构造。默认启用；非 OpenBSD 平台上登记路径是无害的空操作。
    pub fn from_env() -> Self {
        let enabled = cfg!(target_os = "openbsd")
            && !matches!(
                std::env::var("STALWART_SANDBOX").as_deref(),
                Ok("off") | Ok("0") | Ok("false") | Ok("no")
            );

        let mut sb = Self {
            enabled,
            ..Default::default()
        };

        if !enabled {
            return sb;
        }

        sb.chroot = var("STALWART_CHROOT");
        sb.pledge = var("STALWART_PLEDGE");

        if let Some(extra) = var("STALWART_UNVEIL_EXTRA") {
            for entry in extra.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (path, perms) = entry.split_once(':').unwrap_or((entry, "r"));
                for perm in perms.trim().chars() {
                    match perm {
                        'r' => sb.allow_read(path),
                        'w' | 'c' | 'd' => sb.allow_write(path),
                        'x' => sb.allow_exec(path),
                        _ => {}
                    }
                }
            }
        }

        sb
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 已登记的可写路径（用于启动时的自检/告警）。
    pub fn write_paths(&self) -> &[String] {
        &self.write
    }

    /// 登记一个只读路径（例如配置文件、证书）。
    pub fn allow_read(&mut self, path: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        push_unique(&mut self.read, path.as_ref());
    }

    /// 登记一个可写路径。父目录会一并登记，因为存储目录往往还不存在，
    /// 创建/替换它需要父目录的 cpath 权限。
    pub fn allow_write(&mut self, path: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        let path = path.as_ref();
        push_unique(&mut self.write, path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            let parent = parent.to_string_lossy().into_owned();
            if parent.starts_with('/') && parent != "/" {
                push_unique(&mut self.write, &parent);
            }
        }
    }

    /// 登记一个可执行路径（只会被 exec 的东西才需要）。
    pub fn allow_exec(&mut self, path: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        push_unique(&mut self.exec, path.as_ref());
    }

    /// chroot（可选）与 unveil，最后用 `unveil(NULL, NULL)` 锁定。
    /// 必须在放弃 root 权限、打开存储之前调用。
    pub fn lock_filesystem(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "openbsd")]
        {
            if let Some(jail) = &self.chroot {
                let jail = cstr(jail)?;
                if unsafe { libc::chroot(jail.as_ptr()) } != 0 {
                    return Err(format!(
                        "chroot: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let root = cstr("/")?;
                if unsafe { libc::chdir(root.as_ptr()) } != 0 {
                    return Err(format!(
                        "chdir after chroot: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }

            // 其余位置一律只读：配置里的路径可以是任意位置
            unveil("/", "r")?;
            for path in &self.read {
                unveil(path, "r")?;
            }
            for path in &self.write {
                unveil(path, "rwc")?;
            }
            for path in &self.exec {
                unveil(path, "rx")?;
            }

            if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } != 0 {
                return Err(format!(
                    "unveil lock: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        Ok(())
    }

    /// 上 pledge。调用点要在启动流程走完之后（监听已绑定、权限已放弃）。
    pub fn apply_pledge(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "openbsd")]
        {
            let promises = cstr(self.pledge.as_deref().unwrap_or(DEFAULT_PLEDGE))?;
            if unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) } != 0 {
                return Err(format!(
                    "pledge: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        Ok(())
    }

    /// 用于启动日志：列出实际登记的路径，便于确认“按组件收集”真的生效了。
    pub fn describe(&self) -> String {
        if !self.enabled {
            return "disabled".to_string();
        }
        let mut out = format!(
            "unveil({} r + {} rwc + {} rx), pledge({})",
            self.read.len(),
            self.write.len(),
            self.exec.len(),
            self.pledge.as_deref().unwrap_or(DEFAULT_PLEDGE)
        );
        if let Some(jail) = &self.chroot {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!(", chroot({jail})"));
        }
        for (label, list) in [("rwc", &self.write), ("rx", &self.exec)] {
            if !list.is_empty() {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("
  {label}: {}", list.join(" ")),
                );
            }
        }
        out
    }
}

impl fmt::Display for SandboxPaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// `stalwart --sandbox-check`：只为验证当前系统上 unveil/pledge 能正常应用，
/// 供 CI 在 OpenBSD VM 里冒烟测试。
pub fn self_check() -> Result<(), String> {
    #[cfg(target_os = "openbsd")]
    {
        let mut sb = SandboxPaths {
            enabled: true,
            ..Default::default()
        };
        sb.allow_write("/tmp");
        sb.allow_read("/etc");

        sb.lock_filesystem()?;
        sb.apply_pledge()?;

        // 触发几种被承诺覆盖的系统调用，若承诺集有问题进程会在此前后被内核杀掉
        std::fs::metadata("/etc")
            .map_err(|err| format!("stat /etc after pledge: {err}"))?;
        std::fs::read_dir("/tmp")
            .map_err(|err| format!("readdir /tmp after pledge: {err}"))?
            .next()
            .transpose()
            .map_err(|err| format!("readdir /tmp after pledge: {err}"))?;

        Ok(())
    }

    #[cfg(not(target_os = "openbsd"))]
    {
        Ok(())
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// 登记前把路径规范化成绝对路径：配置里可以写相对路径（相对于启动时的 cwd），
/// unveil(2) 只接受绝对路径，静默丢掉会导致运行时写入被拒。
fn push_unique(list: &mut Vec<String>, path: &str) {
    let path = path.trim();
    if path.is_empty() {
        return;
    }

    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path).to_string_lossy().into_owned(),
            Err(_) => {
                eprintln!("OpenBSD sandbox: cannot resolve relative path {path:?}, skipping");
                return;
            }
        }
    };

    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    if !list.iter().any(|existing| existing == path) {
        list.push(path.to_string());
    }
}

#[cfg(target_os = "openbsd")]
fn cstr(value: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(value).map_err(|_| format!("path contains a NUL byte: {value:?}"))
}

#[cfg(target_os = "openbsd")]
fn unveil(path: &str, perms: &str) -> Result<(), String> {
    let path_c = cstr(path)?;
    let perms_c = cstr(perms)?;
    if unsafe { libc::unveil(path_c.as_ptr(), perms_c.as_ptr()) } != 0 {
        return Err(format!(
            "unveil({path}, {perms}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
