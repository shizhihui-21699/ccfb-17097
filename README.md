# credops

在共享 Linux 服务器上找出通过命令行参数、环境变量和 shell 历史泄露的凭证，
并把它们迁移到受保护的通道上。

设计上只坚持一条原则：**输出的任何一行都不能包含可恢复的凭证**。
报告里只有掩码预览、加盐指纹和脱敏后的上下文行，可以直接贴进工单或邮件。

## 它解决什么问题

同一台机器上任何普通用户都能读 `/proc/<pid>/cmdline`（权限是 `0444`）：

```console
$ mysql -u app -p'B4ckupPass!2024' mydb &
$ ps -o args= -p $!
mysql -u app -pB4ckupPass!2024 mydb
```

而且这个值还会留在脚本、crontab、systemd unit、shell 历史和审计日志里。
creditops 的职责是：**定位到具体是哪个脚本/哪个任务**，给出**可直接粘贴的替代写法**，
并按风险和可执行性排序成迁移计划。

## 关键判断

工具的可信度取决于它**不报什么**。下面这些区分是核心，都有测试锁定：

| 写法 | 判定 | 原因 |
|---|---|---|
| `mysql -p` | 不是泄露 | 这是交互式提示，值不在 argv 里 |
| `mysql -p'secret'` | 泄露 | 值粘在参数上 |
| `mysql -p"$DB_PASS"`（脚本里） | 不是泄露 | 脚本里只有引用 |
| `mysql -p"$DB_PASS"`（argv/environ 里） | 泄露 | shell 已展开，内存里就是明文 |
| `--password-file=/run/secrets/db` | 不是泄露 | 值是引用，不是口令 |
| `-port=3306` | 不是泄露 | 是长选项，不是 `-p ort=3306` |
| `mysql -pchangeme` / `-pxxxxxx` | 不是泄露 | 占位符和掩码 |
| `sudo -u x timeout 30 mysql -pfoo` | 泄露 | 包装器会被剥开再判断 |

严重度还按**谁能读到它**调整：世界可读的脚本里 > 仅属主可读的脚本里 >
`environ`（属主和 root 可读）> `audit` 日志（仅 root）。同一个值在
不同写法下指纹相同，所以能跨主机、跨形态聚合。

## 三个难点的实际处理

### 1. 进程可能只活几毫秒

轮询 `/proc` 对短命进程几乎必然漏掉，所以默认**不靠轮询**：

- **auditd（推荐）**：内核在每次 `execve` 时写 `EXECVE`（argv 的 `a0`、`a1`…）
  和 `PROCTITLE`（NUL 分隔的完整命令行），没有采样问题，不需要额外工具链。

  ```console
  # /etc/audit/rules.d/credops.rules
  -a always,exit -F arch=b64 -S execve -F uid>=1000 -k credops
  ```

  ```console
  credops scan --audit-log /var/log/audit/audit.log
  ```

  解析器处理了真实格式里的坑：引号内的空格、转义的 `\"`、超长参数的
  `a2_len=… a2[0]=…` 分片，以及 `proctitle` 的十六进制解码（用它还原真实的
  NUL 边界）。**记录被截断时明确报"无法断言"，不会拼出一个错误位置的口令。**

- **eBPF**：`sched_process_exec` + ringbuf 是更好的方案，但需要 clang/libbpf/BTF
  和 `CAP_BPF`。`src/collect/bpf.rs` 里有完整的设计说明（含 BPF C 代码骨架），
  并支持直接消费现成 agent 输出的 JSON-lines 事件流（`--ebpf-feed`），
  这样本工具不必绑定内核工具链。

- **`/proc` 轮询（兜底）**：只对长命进程有效（守护进程、tmux、交互 shell）。
  代码和文档都不假装它能抓短命进程。找到后会顺着 `ppid` 链往上走，
  标注"由 cron/systemd 拉起"。

### 2. 凭证写法千奇百怪

分层，因为每层的失效方式不同：

1. **工具规则表**（`src/scan/knowledge.rs`，25+ 个真实工具）：精确度高。
   知道 `mysql -p` 的三种写法、`curl -u user:pass`、`openssl -pass pass:`、
   `smbclient -U 'a%b'`、`lftp -u a,b`、`ansible --extra-vars` 等。
2. **键名启发式**：按 `_`/`-`/驼峰拆词，再按"强/弱/引用"分类。
   `--db-password` 是强，`--key` 是弱（还要求值看起来像随机串），
   `--password-file` 是引用。
3. **已知凭证格式**：AWS key id、GitHub/GitLab/Slack token、Stripe/Google key、
   JWT、私钥块、URL 里的 `user:pass@`。
4. **引用/占位符过滤**：`$VAR`、`file:`、`fd:`、`env:`、`@file`、`/run/secrets/`、
   `changeme`、`<password>`、`xxxxxx`。这一层和第一层一起决定了输出可不可信。

Shell 词法不是 `split_whitespace()`：会保留每个字符回到原始字节的映射（所以
脱敏不会错位），区分单/双引号、转义、`$(...)`/`${...}` 嵌套，多字节 UTF-8 有测试。

### 3. 第三方工具只认命令行参数

**这一点必须说实话**：如果一个程序只从自己的 argv 读口令，就没有办法既把值传给它、
又不让它在 argv 里出现。任何声称两者都能做到的工具都是错的。

所以现实的目标要窄一些，但更有用：

1. **不让它被写下来**——这是脚本里那份拷贝，会跟着备份、Git 历史活很多年。
   `credops run` 在 exec 时注入，值从不进入脚本、crontab、unit 或 history：

   ```console
   credops run --secret-file db=/etc/credops/db.pass -- mysql -u app -p'{db}' mydb
   ```

   包装器自己的命令行里只有文件名；它用 `execvp` 直接替换自己，不留下常驻父进程；
   加载的口令会 `mlock`、清空 `PR_SET_DUMPABLE`，并用后立即擦除。
   引用的密钥如果没提供、或提供了没引用（通常是拼错），都会直接拒绝执行而不是猜。

2. **收窄谁能读到 argv**——对无法改造的残留：

   ```console
   mount -o remount,hidepid=2 /proc     # 或 systemd: ProtectProc=invisible
   ```

   之后 `cmdline` 只有属主和 root 能读，和 `environ` 同级别。用专用服务 uid
   可以把"root 能读"进一步收窄成"这个服务账号能读"。

计划里这部分标为 `argv (unavoidable)`，残余暴露也照实写，不美化。

## 命令

```console
# 扫一台主机：脚本、cron、systemd、history、配置文件
credops scan --root /opt --root /etc --histories --salt "$CREDOPS_SALT"

# 只扫运行时（长命进程）或审计日志
credops scan --proc
credops scan --audit-log /var/log/audit/audit.log

# 给 CI 用：命中 high 就以非零退出，输出 SARIF
credops scan --root . --format sarif --fail-on high > credops.sarif

# 单文件 / 单行（编辑器钩子、回归测试）
credops check deploy.sh --fail-on high
echo 'mysql -pHunter2Secret db' | credops check - --line --argv

# 生成迁移计划（按 旋转 → 清除静态拷贝 → 换通道 → 加固主机 → 验证 排序）
credops plan --root /opt --salt "$CREDOPS_SALT"
```

**`--salt`**（或 `CREDOPS_SALT`）务必设置并保密。指纹是
`sha256(salt || value)` 截断，用来跨主机关联同一个口令而不暴露它；
不设盐时指纹可被字典反查，JSON 输出会打印警告。

## 部署形态

单机扫描器是最简单的形态。要"持续采集各台服务器"，两种做法：

- **推模式**：每台机器上由 systemd timer 跑 `credops scan --format json`，
  上报到中心汇总；用相同的 `--salt` 就能把同一凭证的多处出现合并。
- **拉模式**：中心通过 SSH 在每台上跑一次只读扫描，无 agent。

运行时采集需要 root（读 `/proc/<pid>/environ`、读审计日志）。静态扫描不需要特权，
普通用户就能看到大量问题。

## 构建与测试

```console
cargo build --release
cargo test                     # 113 个测试，纯逻辑部分在 macOS/Linux 上都能跑
cargo check --target x86_64-unknown-linux-gnu   # /proc 实现只在 Linux 上编译
```

依赖只有 `anyhow`、`clap`、`regex`、`serde`/`serde_json`、`sha2`，以及 Unix 上的
`libc`。没有内核工具链依赖。

## 局限（写在明处）

- auditd 规则需要先在目标机上配置；没配就只能靠 `/proc` 轮询，短命进程会漏。
- 值如果被工具自己重新 exec 成子进程，argv 里会再次出现——那是工具的属性，不是扫描器能修的。
- `credops run` 只解决"写下来"的部分，不解决进程存活期间的 argv 暴露。
- 启发式对自研脚本的覆盖面取决于键名是否可识别；对无法识别的键名会用低置信度报告，
  而不是静默丢掉。
- 指纹是"同一个值"的判断；不同口令恰好相同会被合并，这是刻意的取舍。
