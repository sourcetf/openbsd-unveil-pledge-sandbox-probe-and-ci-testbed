# OpenBSD unveil/pledge 沙箱探针（一次性 CI 测试床）

这个库只做一件事：在 GitHub 提供的 OpenBSD 7.9 虚拟机里，验证 Stalwart 邮件服务器
OpenBSD 构建要用的 unveil(2)/pledge(2) 策略是否正确。

- `probe/src/sandbox.rs` 是 `sourcetf/stm` 里 `crates/common/src/manager/sandbox.rs`
  的同文件拷贝（真实代码路径，不是简化版）。
- `probe/src/main.rs` 用同一套环境变量接口登记路径，然后模拟服务器运行时的操作：
  存储目录读写改删、日志追加、读 `/etc/resolv.conf` 与 `/etc/ssl`、绑定 TCP 与
  unix socket、fork/exec、`getpwuid`，最后反向确认“未登记的目录写不进去”。

目的是快速迭代 promise 集：本地没有 OpenBSD，只有这里能真跑（stm 的 CI 要先把
整个项目编 90 分钟）。

用完后可以直接删库。
