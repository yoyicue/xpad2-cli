# XPad2 CLI 设计

状态：v0.6.0 已实现；v0.1.1 完成 BoomInstaller 依赖身份和公开分发材料，v0.1.2
增加可验证的 OTA 冻结策略与 Root 前强制门禁，v0.1.3 对齐 KernelSU 驱动与
官方生产签名 Manager 的 32547 构建号，v0.1.4 升级 late-load v0.2.1，恢复
`u:r:ksu:s0` Manager Root 且保持全局 SELinux Enforcing；v0.1.5 将 BoomInstaller
升级到 Root 主服务 + 隔离 UID 1000 APK broker，并增加开机 Root/ADB 恢复链；v0.2.0
增加 production RSA 签名的在线/离线自更新、候选双自检、版本隔离 cache 与失败回滚；
v0.2.1 为 GitHub 多跳下载增加三次有界网络重试；v0.2.2 改用 GitHub Releases API
发现 asset，并增加 15 秒下载进度；v0.2.3 锁定恢复标准 Shizuku 客户端兼容性和
一次性授权迁移的 BoomInstaller r11；v0.3.0 把 0044 备用安装身份工程化为正式签名
anchor、状态机、自动恢复和跨 PackageManager 重写验证；v0.4.0 加入互斥的 SukiSU
Ultra 40796 runtime、官方 Manager 与 `suu-full` profile，同时保持 `full` 默认选择 KSU
的兼容行为；v0.4.1 将所有只读 installer 探针移出 31317，加入原设置精确恢复、逐阶段
核心 PID 日志、本 boot 熔断和 xpad-install 实时日志（2026-07-16）。
v0.4.2 将 BoomInstaller 控制面收敛到标准 Root/ADB-shell，把目标 APK 严格限制在 0044
身份中，31317 只负责补回 0044，并将 Boom 自启动状态与结构化安装日志纳入 `xpad2log`。
v0.4.3 取消把测试机 UID 10072 当作 0044 协议常量，改为逐设备读取并交叉验证真实 OEM
installer UID；UID 10070、10072 等现场均使用同一状态机，且健康 alias 不触发 31317。
v0.4.4 锁定 BoomInstaller r13：APK 内置并逐次校验 xpad-install v0.2.4，安装与普通重启
恢复均不依赖 xpad2 或外部 `/data/local/tmp/xpad-install`；xpad2 仅作为可选分发入口。
v0.4.5 去除普通命令启动时对全部内嵌制品的重复哈希；候选 ELF 自行导出 cache，托管
release 通过全局 SHA blob 的受校验引用去重并只保留一个回滚版本；网络下载支持 Range 续传、
暂态错误分类以及 GitHub 限流等待，正常在线更新不再下载重复 cache ZIP。
v0.4.6 增加独立生产签名的 delta 索引；只有当前 ELF 的版本、大小和 SHA-256 精确匹配
发布基线时才应用 zstd patch，重建目标仍需通过签名 manifest 身份和候选自检，否则自动
回退完整 ELF。
v0.4.7 作为首个真实增量目标，要求从精确 v0.4.6 基线完成无完整 ELF 的离线重建、损坏
patch 安全失败，以及 GitHub Release 在线 delta 更新和最终收据验证。
v0.4.8 锁定 BoomInstaller r14，将 Android 全局权限所有权收敛到 Boom namespace；保留
Shizuku 内部类/AIDL/Binder 身份，并验证官方 Shizuku 已安装时仍能经 0044 安装和启动。
v0.4.9 锁定 xpad-installer v0.2.5 与 BoomInstaller r15；31317 成功提交新版 anchor 后，
在有界时间内等待 `packages.list` alias 达到完整健康状态，避免即时验证把尚在收敛的
成功修复误判为失败，同时继续禁止 31317 直接接收目标 APK。
v0.4.10 将独立 xpad-installer 和 BoomInstaller r16 的内嵌引擎统一锁定到 v0.2.6，
把 0044 alias 收敛验证扩展为最长 60 秒并每五秒记录进度。
v0.4.11 锁定 BoomInstaller r17，修正内嵌 v0.2.6 ELF 的运行时大小门禁，并把该常量
纳入发布边界检查，防止 lock、APK asset 与 Java 校验常量再次漂移。
v0.4.12 锁定 xpad-install v0.2.7 与 BoomInstaller r18，将已提交但仍未收敛的修复
识别为 exit 76 pending，并只允许通过 `xpad2 status` 做只读复检。
v0.4.13 将底层轮询严格调整为每 5 秒一次，并锁定 xpad-install v0.2.8 与 BoomInstaller r19。
v0.4.14 加固控制面：确认所有自更新写操作都在全局操作锁内；所有 xpad-install 执行
先过锁定 ELF/哈希门；损坏的默认托管缓存安全回退内嵌制品；ELF 复制改为流式原子写，
失败回滚使用同目录预置副本并至少保留两个永久备份。
v0.5.0 将 XPad2 fingerprint incremental 从精确 `/260` 扩为 canonical `/19`–`/260`
闭区间，并集成 `xpad2-ionstack-poc release/xpad2-19-260` 的 `v19-a`、`v19-b`、`v260`
三套 runner/preload。设备/Android 前缀、release-keys 后缀、精确 kernel build 与 ABI 仍
fail closed；精确 `/260` 保留为旧 updater 的网络 manifest 兼容锚点。
v0.5.1 修正 v0.5.0 将精确 `uname -v` 错放到控制面入口的问题：范围内未知 build 先以
共同 perf target 做只读 offset discovery，至少两个独立 anchor 唯一命中后选择 profile，
再通过 runner 的 preflight、validate 和显式 compatible-write 状态；精确 build 保留快速路径。
v0.5.2 将设备门拆为产品族门与 Root 技术门：签名 XPad2 fingerprint family + arm64
允许自更新、OTA、CLI/APK、0044 和 Manager 控制面；只有 `root`/`ksu`/`suu` 才额外要求
`/19`–`/260` 与 `4.19.191`。范围外 timestamp build 不再阻断无 Root 能力，范围内未知
`uname -v` 仍由 POC discovery 状态机决定能否进入写入阶段。
v0.5.3 锁定 xpad-installer v0.2.13 与 BoomInstaller r23：Root broker 保持真实 UID 0，
经学而思 OEM Provider 提交 APK；Provider 可读副本随机、短生命周期且事务结束即删除。
ADB-shell 路径继续使用受管 0044，31317 仍只允许修复 0044，不接收目标 APK。
v0.5.4 锁定 xpad-installer v0.2.14 与 BoomInstaller r24：APK 与 DEX 暂存改用每次事务
唯一文件名并在成功或失败后清理，历史只读残留不再导致下一次 0044 安装以 staging I/O
错误提前退出；错误仍保留机器可读的 artifact、path 与 errno 供远程诊断。
v0.6.0 增加真机验证的 KSU + NeoZygisk v2.3 + Vector v2.0 链路：Neo socket 与模块
memfd 复用 `ksu_file`，锁定的官方 MagiskPolicy v30.7 只加载 system_server self execmem
最小规则；Vector Bridge 在 Enforcing SELinux 下完成验收。显式 Hook
安装事务在 live rule 写入后恢复 Enforcing，但保留临时 su 到 Bridge 验活之后才释放。
v0.6.0 发布修订收敛 CLI 职责：移除具体应用进程与业务 Hook 日志观察，Vector 健康状态只验证
通用 Zygisk、lspd、system_server Bridge 和最小 live policy，不携带或修改应用 Hook，
不管理应用 scope。

验收覆盖单 ELF、只读状态探针、3-worker IonStack 临时 Root、KSU/SUU late-load、
CLI/APK 身份验证、临时 Root 安全收口、同 boot 幂等重跑、普通重启后恢复、RSA 签名
离线缓存、损坏缓存安全失败、签名自更新和 `xpad2log` 导出。发布组合以
`assets.lock.json`、`sources.lock.json` 与 `xpad2-update.json` 为准。

## 1. 产品定义

`xpad2` 是运行在 XPad2 Android 设备上的、能够按需获得临时 Root 的安装器。

唯一的产品入口是 Android ARM64 CLI：

```text
/data/local/tmp/xpad2
```

电脑端不提供 `xpad2ctl`、桌面 GUI 或桌面 CLI。电脑只使用 ADB 选择设备、推送
`xpad2` 并调用设备命令：

```sh
adb -s SERIAL push xpad2 /data/local/tmp/xpad2
adb -s SERIAL shell chmod 700 /data/local/tmp/xpad2
adb -s SERIAL shell /data/local/tmp/xpad2 install
```

`xpad2` 支持安装两类制品：

1. CLI 制品：Android ELF 命令，例如 `xpad-install`。
2. APK 制品：Android 应用，例如 KSU/SUU Manager 和 BoomInstaller。

KernelSU 或 SukiSU Ultra 是当前启动周期的互斥 runtime 能力，不归入 CLI/APK 两类制品；临时 Root 是
安装事务使用的能力边界，也不是一个持久安装包。

## 2. 非目标

- 不开发 `xpad2.apk`。
- 不开发 XPad2 Manager GUI。
- 不开发 `xpad2ctl`。
- 不替代 Android 的通用软件仓库或 PackageManager。
- 不修改 AVB、boot image 或 system 分区。
- 不在线卸载、替换或切换已经加载的 KSU/SUU 模块。
- 不把任意远端 JSON 当作可变包索引；组件组合仍必须随完整 xpad2 Release 发布。

## 3. 总体架构

```text
ADB shell
   |
   v
xpad2 Android CLI
   |
   +-- Profile / State Probe
   +-- Transaction Planner
   +-- Local Directory Cache
   +-- Signed HTTPS / Offline Self-Updater
   +-- IonStack Temporary Root Provider
   +-- KSU / SukiSU Ultra Late-load Providers (mutually exclusive)
   +-- CLI Artifact Installer
   +-- APK Artifact Installer (xpad-install)
   +-- Verification / Receipt / xpad2log
```

Root 路径复用 `xpad2-ionstack-poc` 已验证的纯 C 设备链。`xpad2` 单文件内嵌所需
设备组件并负责解包、启动、Boot ID 守卫和独立 `su -c id` 验证，不要求电脑端运行
另一套控制程序。

APK 安装复用 `xpad-install` 的现有身份通道选择：

```text
0044 run-as znxrun -> 已有临时 Root transport -> 31317 system runner
```

安装普通 APK 不把 Root、simpleperf 授权或 KSU/SUU Manager 是否存在作为预检查条件。

### 3.1 仓库与制品的关系

`xpad2-cli` 是集成和产品发布仓库，不是所有组件源码的合并仓库。

```text
组件源码仓库
|-- xpad2-ionstack-poc
|-- xpad2-ksu-lateload
|-- xpad2-sukisu-lateload
|-- xpad-installer
|-- KSU / SukiSU Ultra Manager
`-- BoomInstaller
        |
        v 各自构建、测试、发布
不可变组件制品（ELF / SO / KO / APK）
        |
        v assets.lock.json 锁定版本、身份和 SHA-256
xpad2-cli 集成仓库
        |
        |-- 构建自包含 xpad2 ELF
        |-- 生成可选的离线缓存包
        `-- 完成整套真机验收并发布
```

各组件仓库分别拥有其源码、组件级构建和组件级 Release。`xpad2-cli` 只消费已经
发布并经过验证的不可变制品，不复制或分叉这些仓库的完整源码，也不自动跟随任何
仓库的 `latest`。

`xpad2-cli` 拥有：

- `xpad2` 命令、事务、缓存、状态探针和日志实现。
- Root、KSU/SUU、CLI 和 APK provider 的适配层。
- `assets.lock.json`、组件兼容矩阵和 `sources.lock.json`。
- 获取并校验锁定制品的构建脚本。
- 跨组件端到端真机验证和最终产品 Release。
- 聚合发布所需的许可证、NOTICE 和精确对应源码记录。

每一个 XPad2 版本代表一个不可变且整体验证过的组件组合。组件仓库发布新版本后，
不会自动改变任何现有 XPad2 版本。升级组件必须经过：

```text
组件仓库发布
-> 更新 assets.lock.json / sources.lock.json
-> 构建新的 xpad2
-> XPad2 产品族门 + `/19`–`/260` Root 门；/260 真机 install full/suu-full、重跑、重启恢复和失败收尾验证
-> 发布新的 XPad2 版本
```

`assets.lock.json` 记录进入产品的二进制身份；`sources.lock.json` 记录每个二进制
对应的源码仓库、commit/tag、许可证和可获取的精确源码归档。构建和发布过程不从
未锁定的工作区文件或浮动 URL 取制品。公开 CI 使用 `tools/verify_sources.sh` 验证仓库
canonical 名称以及 tag 到 commit 的不可变映射；被重命名仓库的旧 URL 即使仍可重定向，
也不能通过依赖链校验。

### 3.2 开发语言与组件边界

`xpad2` 主程序使用 Rust。已经验证的底层组件保持各自原有语言和独立制品边界，不为
统一语言而重写：

```text
xpad2 命令、事务、缓存、catalog、日志       Rust
IonStack POC                                C / 汇编
xpad-install                                C + 内嵌 DEX
KSU/SUU ksud                                现有 Rust 制品
KSU/SUU Manager / BoomInstaller             已签名 APK
```

`xpad2` 将底层二进制作为经过哈希锁定的数据内嵌或放入缓存，运行时解包并作为独立
子进程调用。第一版不通过 FFI 把 exploit 或 installer 源码链接进 Rust 主程序，以便
保留组件隔离、原始许可证边界和现有真机验证证据。

Rust 控制面负责：

- 命令解析和安装计划。
- 原子文件操作、目录缓存和事务恢复。
- JSON catalog、JSONL event 和安装收据。
- SHA-256、catalog 与 update manifest 的 production RSA 签名验证。
- 子进程、signal、Boot ID 和操作锁管理。
- `xpad2log` 打包和脱敏。

目标构建为 `aarch64-linux-android`、Android API 33 PIE ELF；release profile 使用
LTO、strip 和 `panic=abort`。构建必须提交 `Cargo.lock`，运行时不需要 Rust 工具链或
JVM。普通安装完全离线；只有显式自更新使用内嵌 rustls/webpki 根证书访问公开 HTTPS。
依赖保持锁定，核心使用 `serde`/`serde_json`、`sha2`、RSA 验签、semver、ZIP、ureq
以及必要的 `libc` 能力。

### 3.3 私有上游仓库与构建输入

上游组件仓库当前可以保持私有。私有仓库访问只发生在构建阶段，不进入设备运行时：

```text
私有组件仓库 / 构建机本地制品目录 / 群晖冷备
                         |
                         v
                assets.lock SHA-256 校验
                         |
                         v
                   构建自包含 xpad2
                         |
                         v
              XPad2 Release / 离线缓存包
```

必须区分两类目录：

| 目录 | 所在位置 | 用途 |
| --- | --- | --- |
| `XPAD2_ARTIFACT_DIR` | 构建机 | 保存从私有上游获得的锁定构建输入 |
| `XPAD2_CACHE_DIR` | Android 设备 | 保存安装时复用的已校验制品 |

本地或离线构建优先接受显式制品目录：

```sh
cargo xtask assemble --artifact-dir ~/xpad2-artifacts
```

该目录不是信任边界。所有文件仍必须匹配 `assets.lock.json` 中的身份、大小和
SHA-256；来自本机或群晖不能跳过校验。

CI 需要跨私有仓库获取制品时：

- 使用仅授权指定组件仓库、Contents 只读的短期 GitHub App installation token。
- 只读取明确仓库、tag/release 和 asset filename，禁止使用 `latest`。
- 下载后先验证大小和 SHA-256，再进入构建目录。
- token 只存在于构建任务内，不写入 Git、日志、`xpad2`、catalog 或缓存包。
- 群晖保存相同 SHA-256 的冷备，但冷备也不能覆盖 lock 校验。

不使用 Git submodule 拉入私有组件源码，不把大型 ELF/KO/APK 长期提交到
`xpad2-cli` Git 历史，也不让设备端 `xpad2` 登录 GitHub 或持有任何仓库凭据。

在公开发布前，`xpad2-cli` 和集成 Release 可以保持私有。公开发布时必须逐项确认
再分发权利：GPL 组件随 Release 提供精确对应源码或 source bundle；Apache/MIT 等
组件保留 LICENSE、NOTICE 和修改声明；不可再分发的私有制品不能进入公开版本。
APK 生产签名私钥始终保持私有，XPad2 只消费已经签名的 APK。

最终用户只消费 XPad2 Release，不需要访问任何上游私有仓库。私有仓库是生产输入，
XPad2 Release 是唯一交付边界。

## 4. 命令模型

命令遵循：

```text
xpad2 <verb> <object...> [options]
```

### 4.1 状态和诊断

```sh
xpad2 version
xpad2 status
xpad2 status --json
xpad2 list
xpad2 info COMPONENT
xpad2 doctor
```

### 4.2 自更新

```sh
xpad2 update --check [--json]
xpad2 update [--version VERSION]
xpad2 update --offline DIRECTORY_OR_ZIP
xpad2 update --reinstall
```

默认更新只前进到 GitHub Latest 稳定版。同版本只有显式 `--reinstall` 才替换；降级必须
同时给出精确 `--version` 或离线包及 `--allow-downgrade`，避免 latest 配置错误造成回退。
更新不需要 Root，不改变任何已安装组件；`--cache-dir` 不参与自更新事务。

### 4.3 Root

```sh
xpad2 root
xpad2 root -- COMMAND ARG...
xpad2 freeze ota
xpad2 unfreeze ota
```

- `xpad2 root` 显式获得当前启动周期的临时 Root，并留下可用客户端供操作者使用。
- `xpad2 root -- ...` 取得 Root 后执行一次命令。
- 任意 Root 路径必须先通过 `pm disable-user --user 0` 冻结正在运行的 OTA 主包
  `com.tal.pad.ota`，再从 `dumpsys package` 独立确认 user 0 状态；失败时不得启动 IonStack。
- OTA 冻结跨重启持久，只有显式 `xpad2 unfreeze ota` 才恢复。停止状态的
  `com.tal.init.ota` 是 `xpad-installer` 的 31317 secondary trigger，应用升级包
  `com.tal.pad.app_upgrade` 也不是系统 OTA；两者均不进入冻结集合。
- 显式 Root 的安全状态、有效期和清理方法必须打印给用户。
- 不能以 `/data/local/tmp/su` 或 socket 文件存在作为成功依据，必须实际验证
  `su -c id`。

### 4.4 内置组件

```sh
xpad2 install                         # 无参数默认 full / KSU
xpad2 install ksu
xpad2 install suu
xpad2 install ksu-manager
xpad2 install suu-manager
xpad2 install xpad-installer
xpad2 install boominstaller
xpad2 install full
xpad2 install suu-full
```

支持一次选择多个组件：

```sh
xpad2 install ksu ksu-manager boominstaller
```

`full` 固定选择 KSU，`suu-full` 固定选择 SukiSU Ultra。`ksu` 与 `suu` 同一 boot
互斥；请求混合两者必须在计划阶段失败，运行时切换必须先普通重启。

### 4.5 任意本地制品

```sh
xpad2 install cli FILE [--name NAME]
xpad2 install apk FILE
```

CLI 制品第一版只允许落到 `/data/local/tmp`。默认文件名取输入 basename；`--name`
只允许安全的单段文件名，不能包含 `/`、`..` 或控制字符。

### 4.6 验证、修复和清理

```sh
xpad2 verify [COMPONENT]
xpad2 repair COMPONENT
xpad2 cleanup
xpad2 logs export DIRECTORY
```

`cleanup` 只删除失败事务和临时工作区，不删除制品缓存。删除缓存必须使用显式缓存
命令。

## 5. 内置组件目录

| ID | 类型 | 目标状态 | 生命周期 |
| --- | --- | --- | --- |
| `ota` | policy | 受支持 XPad2 系统 OTA 主包对 user 0 不可运行 | 持久，显式解冻 |
| `ksu` | runtime | KernelSU late-load 接口正常 | 当前启动周期 |
| `suu` | runtime | SukiSU Ultra 40796、flags/features `0x5`、late-load 接口正常 | 当前启动周期 |
| `ksu-manager` | APK | `me.weishu.kernelsu` 匹配锁定版本 | 持久 |
| `suu-manager` | APK | `com.sukisu.ultra` v4.1.3/40796 与生产签名匹配 | 持久 |
| `xpad-installer` | CLI | `/data/local/tmp/xpad-install` 匹配锁定哈希 | 普通重启后保留 |
| `installer-backup` | policy | 正式 anchor attribution 完整且 `znxrun` UID 与本机 OEM installer 一致 | 持久 |
| `boominstaller` | APK | `com.yoyicue.boominstaller` 安装、激活并配置自启动 | 持久 |
| `full` | bundle | 上述全部达到目标状态 | 混合 |
| `suu-full` | bundle | 用 `suu`/`suu-manager` 替换 `full` 的 KSU 对 | 混合 |

两个 full profile 都不包含任何 `xpad2.apk`，因为不存在该制品。

## 6. `install full` / `install suu-full` 事务

```text
1. 获取全局 operation lock
2. 记录 Boot ID、SELinux、现有 Root、KSU/SUU 和组件状态
3. 校验 XPad2 产品族和制品锁；runtime 请求再校验 `/19`–`/260`、`4.19.191` 与 ABI
4. 冻结并复验 XPad2 OTA 主包；失败则停止
5. 安装并验签所选 runtime 对应的官方 Manager；SUU 必须在模块注册前固定 Manager 身份
6. 如果所选 runtime 已健康加载，跳过临时 Root 和 late-load
7. 否则在 OTA 已冻结的前提下通过 IonStack POC 获取临时 Root
8. late-load 锁定版本的 KSU 或 SUU；验证完整 runtime 身份，并以实际 `ksud module list`
   成功作为控制面就绪栅栏；另一 runtime 已驻留时要求普通重启
9. 部署并验证 xpad-install CLI
10. 幂等收敛正式 0044 anchor，并验证 attribution 与本机 OEM installer UID
11. 安装 BoomInstaller APK
12. 激活 BoomInstaller 并配置普通开机自启动
13. 所有 APK 事务结束后再次幂等收敛并验证 0044 anchor
14. 验证 OTA、所选 runtime 与全部制品目标状态
15. 恢复 SELinux Enforcing
16. 关闭安装事务创建的临时 su daemon/socket/client
17. 写入事务收据和日志，释放 operation lock
```

原则：

- 一次事务最多获取一次临时 Root。
- 用户显式执行 `root` 时留下临时 Root；runtime/full profile 内部获取的 Root 默认关闭。
- 任一步失败后仍优先执行 SELinux 和临时 Root 收尾。
- 如果 runtime 已经成功加载、后续 APK 安装失败，记录部分成功；重跑时从状态探针继续。
- 如果另一 runtime 已加载或当前模块身份不健康，停止并要求普通重启，不尝试在线切换。
- runtime 驻留后切换到 `u:r:ksu:s0` 的 `/system/bin/su` 执行后续特权命令；IonStack 临时
  Root 仅保留为恢复通道，直到 Enforcing 下的最终验活完成。
- IonStack 六轮 holder 机会耗尽后停止，明确建议普通重启，不无限重试。
- Boot ID 在危险阶段发生变化时，事务立即判为失败，不把重启后的旧文件当作成功现场。

## 7. 两类制品的安装合同

### 7.1 CLI 制品

安装前：

- 校验文件是 ELF。
- 校验目标架构为 AArch64，ABI 与设备兼容。
- 校验 catalog 中的文件大小和 SHA-256；任意本地文件至少记录 SHA-256。
- 目标路径必须在 `/data/local/tmp` 的允许范围内。

安装时：

- 写入同目录的随机 `.partial` 文件。
- 完整写入、`fsync`、设置权限后原子 `rename`。
- 内置 CLI 使用锁定的目标文件名和权限。

安装后：

- 重新计算目标文件 SHA-256。
- 对 `xpad-install` 运行只读 native `self-test`，并验证 `installer-backup` 状态；状态查询
  不得选择 31317 transport。
- 任何实际 APK 提交后，最终阶段再次执行 `znxrun ensure` 并独立验证备用身份。
- 写入安装收据。

### 7.2 APK 制品

安装前：

- 解析 APK 包名、versionCode、签名证书和支持的 ABI。
- 内置 APK 必须与 catalog 中的包名、版本、签名和 SHA-256 一致。
- 任意 APK 显示实际解析结果，不根据文件名推断包名。

安装时：

- 交给 `xpad-install` 的 `auto` 路径；目标 APK 只允许由受管 0044 身份提交。
- 已安装相同或更高版本且签名匹配时允许跳过。
- 签名不兼容时停止，不自动卸载现有应用或清除用户数据。

安装后：

- 通过 PackageManager 独立读取实际包名、versionCode、签名和 installer attribution。
- BoomInstaller 还必须验证激活后的唯一服务为 Root UID 0 或 ADB-shell UID 2000，并验证
  自启动配置；任何其他 UID 服务或多个并存服务均视为损坏。
- 首次安装和同包同证书升级都走 auto：使用 UID 与本机 OEM installer 一致的持久 0044 身份，并在该身份内从
  OEM provider 转向 direct。若 0044 缺失或损坏，31317 只补建正式 anchor/alias；外层
  复验 alias、anchor attribution 和 PackageManager UID 三者一致后才开始目标安装。修复失败时不得把目标 APK 交给临时 Root 或 31317。
  `/260` 的 OEM provider 可能接收请求后不实际提交，auto 必须识别未提交结果并在同一
  0044 身份内继续，不能误报成功。
- 31317 写设置前持久保存完整原值；每个阶段记录 boot ID、Zygote64/32、system_server、
  SystemUI PID 与设置长度/换行元数据。核心 PID 变化时写入本 boot 熔断并返回 75。
- `--version`、`doctor`、`verify`、`cleanup`、`znxrun status` 在 native dispatch 中提前
  返回；未知命令也必须在 transport 选择前返回 64。所有只读状态/验证路径以及 xpad2
  对 ELF 的 `self-test` 都不能意外落入 31317。
- BoomInstaller 激活从已验证安装目录读取 `base.apk` 和 `lib/arm64/libshizuku.so`；
  不放宽 xpad2 的 0700 私有工作目录；APK broker 固定为 UID 2000，不创建常驻 UID 1000
  服务。

## 8. 本地目录缓存

本地缓存是一级能力。默认根目录：

```text
/data/local/tmp/.xpad2/
|-- cache/
|   |-- blobs/<sha256>         跨 release 共享的内容寻址实体
|   `-- releases/
|       `-- <product>--<catalog>/  签名 catalog 与 blob 引用
|-- work/           当前事务临时文件
|-- state/
|   |-- update-backups/        最近一个旧 ELF
|   `-- 安装收据与状态快照
|-- logs/           原始 xpad2log 数据
`-- operation.lock  全局互斥锁
```

支持覆盖缓存目录：

```sh
xpad2 install full --cache-dir /data/local/tmp/my-xpad2-cache
XPAD2_CACHE_DIR=/data/local/tmp/my-xpad2-cache xpad2 install full
```

显式命令：

```sh
xpad2 cache path
xpad2 cache list
xpad2 cache verify
xpad2 cache import DIRECTORY
xpad2 cache prune
xpad2 cache clear
```

### 8.1 缓存格式

```text
xpad2-cache/
|-- catalog.json
|-- catalog.sig
`-- blobs/
    |-- <64-character-sha256>
    `-- <64-character-sha256>
```

`catalog.json` 只描述数据，不允许携带或执行任意安装脚本。安装动作由 `xpad2` 中
已知的 artifact kind/provider 实现。

概念性条目：

```json
{
  "id": "xpad-installer",
  "version": "0.2.14",
  "kind": "cli",
  "sha256": "641eb9d1d790397e3087a41b922cd8f807188ff382d42938f1beb55a10b2d743",
  "size": 98472,
  "target": "/data/local/tmp/xpad-install"
}
```

### 8.2 解析顺序

对命名组件按以下顺序解析：

1. `--cache-dir` 指定目录。
2. `XPAD2_CACHE_DIR` 指定目录。
3. 默认 `/data/local/tmp/.xpad2/cache/releases/<product>--<catalog>`。
4. `xpad2` 单文件内嵌的基线制品。
5. 全部缺失时明确失败；普通 install 不联网下载。

命中缓存不代表可信。每次使用前仍需校验 catalog、签名、大小和 SHA-256。

默认托管缓存按 product/catalog 版本隔离，因此升级与回滚不会读取另一版本的 JSON。
签名损坏、内容损坏，以及通过 `--cache-dir`/`XPAD2_CACHE_DIR` 显式选择的任何不匹配
缓存都硬失败。旧 v0.1.x 使用的 legacy `cache/` 可以保留给旧 ELF 回滚使用。

### 8.3 缓存安全和生命周期

- 内嵌 catalog 是受信任的基线。
- 外部 catalog 必须通过发布签名验证，并且所有 blob 都必须出现在当前
  `assets.lock.json` 中；签名不能授权缓存绕过产品版本锁引入新组件。
- 组件版本升级必须发布新的 XPad2 版本和锁文件，缓存不是独立更新渠道。
- `/sdcard` 只作为导入来源；不得从可被其他应用写入或 `noexec` 的位置原地执行 ELF。
- 导入使用 `.partial`、`fsync` 和原子 `rename`。
- blob 实体统一存于托管 `cache/blobs/<sha256>`；release cache 优先使用硬链接，Android
  SELinux 禁止时使用指向精确 SHA 实体的受校验符号链接；catalog 仍严格按版本隔离。
- `cleanup` 不清缓存。
- `cache prune` 自动迁移旧布局并只保留当前与一个回滚 release 引用的 blob。
- `cache clear` 清除全部托管 release/blob；显式外部缓存仍只处理指定目录。

电脑准备离线缓存时：

```sh
adb -s SERIAL push ./xpad2-cache /data/local/tmp/
adb -s SERIAL shell /data/local/tmp/xpad2 \
  install full --cache-dir /data/local/tmp/xpad2-cache
```

这里的“本地目录”指 Android 设备上的目录；`xpad2` 无法直接读取电脑文件系统。

## 9. 签名自更新

更新清单使用固定文件名 `xpad2-update.json`，相邻的
`xpad2-update.json.sig` 是 RSA-4096/SHA-256 原始签名。默认发现入口为：

```text
https://api.github.com/repos/yoyicue/xpad2-cli/releases/latest
```

指定 `--version X.Y.Z` 时使用 API 的 `releases/tags/vX.Y.Z`。程序只接受 canonical
repository 的 uploaded asset API URL，再由 API 重定向到 release-assets；这样在
`github.com:443` 不可达但 API/asset 域可达的网络上仍能工作。API metadata 是不可信的
运输索引，必须与签名 manifest 里的 tag、文件名、大小和可用 digest 交叉验证。
manifest 使用严格字段集合，锁定 schema/kind/channel/repository、目标 semver、catalog
版本、签名 `/19`–`/260` profile，以及 ELF、legacy cache ZIP、catalog 的文件名、大小、
SHA-256 和 HTTPS URL。独立 `catalog.sig` 直接验证候选内嵌 catalog。可选的
`xpad2-deltas.json` 与相邻签名使用同一 production RSA identity，严格绑定目标 manifest
中的 ELF 身份，并为每个基线锁定版本、大小、SHA-256 及 canonical patch asset。只有两份
sidecar 同时不存在才视为旧 Release；只出现一份、签名无效或字段越界均硬失败。
HTTPS 证书验证与 Release RSA 签名缺一不可；远端 JSON 不能添加安装脚本或改变 xpad2
内置 provider。网络暂态失败最多三次有界重试，大文件每 15 秒报告下载进度并通过 Range
从 partial 续传；永久 4xx 立即失败，403/429 遵循服务端限流时间。

更新事务顺序固定：

```text
当前 ELF 验证 XPad2 产品族（不要求 Root profile）
-> 下载或读取 manifest + signature
-> production RSA 验签和版本策略门禁
-> 获取可选 delta index + signature，并严格绑定目标 manifest
-> 当前 ELF 精确匹配基线时下载 patch 并有界重建，否则下载完整 ELF
-> 校验 ELF 的签名清单大小与 SHA-256
-> 候选 ELF 自检自身哈希、内嵌 catalog 和真机产品族
-> 候选 ELF 逐项校验并导出自身内嵌 cache
-> 将 blob 迁移到全局 SHA store，并为目标 release 建立受校验引用
-> 将目标 cache 原子切换到目标版本独立目录
-> 备份当前 ELF 并原子替换 current_exe
-> 已安装 ELF 再执行一次候选自检
-> 保留当前与一个回滚 release，回收其他 cache/ELF
-> 成功提交收据；失败恢复旧 ELF 和旧 cache
```

运行中的旧 ELF 与磁盘路径上的新 ELF 是不同 inode，因此旧进程可以安全完成收据与
失败恢复。cache 在 release 之间不共享可变 catalog，崩溃在任意时点最多留下已验证但
尚未启用的目标版本目录；当前或旧 ELF 始终可以使用自身内嵌制品。最近一份旧 ELF
保存在 `state/update-backups/`，同版本修复必须显式 `--reinstall`，任何降级必须再加
`--allow-downgrade`。

patch 解码以当前 ELF 作为只读 zstd dictionary，输出不能超过签名目标大小；重建文件只有
大小和 SHA-256 均精确匹配主 manifest 后才可成为候选。基线不匹配直接走完整 ELF；patch
下载、哈希或解码失败会记录原因并安全回退完整 ELF；无论走哪条路，后续候选双自检、cache
导出、原子替换与回滚事务完全相同。

离线 Release 同时提供 `xpad2-update-vX.Y.Z.zip`，包含签名 manifest、catalog 签名、
delta 索引与签名、patch、目标 ELF 和为旧 updater 保留的匹配 cache ZIP。v0.4.5+ 优先从
ELF 自导出，不再解压重复 cache；完整 ELF 仍保留为基线不匹配及旧 updater 的回退路径。

## 10. 状态与成功判定

| 对象 | 成功判定 |
| --- | --- |
| 临时 Root | 实际执行 `su -c id` 返回精确 root 身份；socket/文件存在不算 |
| KernelSU | 模块存在、`ksud debug info` 的版本/UAPI/LKM/late-load/runtime 字段匹配 |
| SukiSU Ultra | 模块存在、`debug info` 的 40796、flags/features `0x5`、LKM/late-load/runtime 字段匹配 |
| KSU Manager | 包名、versionCode、签名及与锁定 KSU 组合兼容 |
| SUU Manager | `com.sukisu.ultra`、40796 与官方生产签名匹配 |
| xpad-install | 目标路径、ELF ABI、SHA-256 和只读 native `self-test` 全部通过 |
| BoomInstaller | APK 身份正确、唯一服务 UID 为 0/2000、自启动配置完成 |
| 安全收尾 | SELinux Enforcing，事务临时 daemon/socket/client 不存在 |

状态至少区分：

```text
absent
ready
active
installed
outdated
incompatible
broken
needs-reboot
```

同一状态模型用于人类输出、`--json` 输出和事务恢复。

## 11. 日志与诊断

每次修改操作创建独立 transaction ID，并将日志写入：

```text
/data/local/tmp/.xpad2/logs/<transaction-id>/
```

`xpad2 logs export DIRECTORY` 生成：

```text
xpad2log-YYYYMMDD-HHMMSS.zip
```

诊断包至少包含：

- 产品版本、catalog 版本和所有制品哈希。
- 开始/结束 Boot ID 与 SELinux 状态。
- Root 六轮阶段和最终分类。
- KSU/SUU late-load 及 `debug info`。
- CLI/APK 安装和独立验证结果。
- `xpad-install` 运行中的逐行 stdout/stderr（每行持久化后再显示）。
- 31317 每阶段的核心 PID、隐藏设置元数据、本 boot 熔断结果。
- 完整当前 logcat、可取得的上一 boot、DropBox crash 与进程退出信息。
- 当前事务、上一次事务和上一次启动可获得的相关日志。
- 清理结果及仍需普通重启的原因。

默认脱敏设备 SN、ADB key、私钥、配对凭据、token 和应用私有数据。

执行过程使用稳定的 JSONL event schema，同时默认渲染为可读文本。例如：

```json
{"event":"step","name":"root-holder","state":"running","attempt":2,"max":6}
{"event":"component","id":"ksu","state":"active","runtime":"current-boot"}
{"event":"action-required","action":"reboot","reason":"holder-attempts-exhausted"}
```

## 12. 初始锁定制品

首个实现版本以当前已验证制品为基线；正式构建时写入 `assets.lock.json`：

| 组件 | 版本/来源 | SHA-256 |
| --- | --- | --- |
| IonStack POC | `release/xpad2-19-260` / `6103dab` | v19-a/v19-b/v260 分 profile 锁定；3-worker 安全参数 |
| KernelSU module | XPad2 Linux 4.19 late-load v0.2.1 | `e930a6929c6cd156f394e6b15bed2258b19205cc17fa3410db7f68cef7b8fb21` |
| `ksud-xpad2` | KernelSU 32547 / UAPI 2 | `26ea0f41af159a63a9afdff98963247da9d0bad0363f7e9c937f4cfbcd9f69c6` |
| KernelSU Manager | v3.2.5-22-gccfee6dc / 32547 | `bd2b5d6671ed3636d1b3ac40c0f2e7dc0eb23319298fefc59d88b382e2800d7e` |
| SukiSU Ultra module | XPad2 Linux 4.19 v0.1.0 / 40796 | `5835dbed566e9711fab02c3b729e6dce495b996481af53c474f2be4816e7fd81` |
| `ksud-sukisu-xpad2` | SukiSU Ultra v4.1.3 / 40796 | `74379a3c1a556448762db00d8e1316b31a4cf56a1eb1b8accd8447a1e3859bd8` |
| SukiSU Ultra Manager | v4.1.3 / 40796 | `1b1e837c0a5b6aa34554882fad67cef6db6ca1a84d43e07dd904cf54f8d261ae` |
| `xpad-install` | v0.2.14 | `641eb9d1d790397e3087a41b922cd8f807188ff382d42938f1beb55a10b2d743` |
| BoomInstaller | v13.6.0.r24.2f6e7c2 production | `e9940c3b4931731320ac30cb2459ed661d0ef02ca8539260bf9fc6d3834389b0` |

版本号相等不是 runtime/Manager 兼容性的判据；两套组合分别由 catalog 显式锁定。

## 13. 发布制品

一个版本发布 Android CLI、离线 cache 与两套锁定 Manager APK，不发布 `xpad2.apk`
或桌面程序：

```text
xpad2-vX.Y.Z-android-arm64
xpad2-vX.Y.Z-android-arm64.zip
xpad2-cache-vX.Y.Z.zip
xpad2-update.json
xpad2-update.json.sig
catalog.sig
xpad2-deltas.json
xpad2-deltas.json.sig
xpad2-delta-vW.X.Y-to-vX.Y.Z-android-arm64.zst
xpad2-update-vX.Y.Z.zip
kernelsu_manager_<locked-version>.apk
SukiSU_v<locked-version>-release.apk
assets.lock.json
sources.lock.json
SHA256SUMS
licenses/
```

裸 ELF 便于直接 `adb push`；主 ZIP 包含文档、锁文件、许可证和校验清单。缓存 ZIP
是可选的离线部署和旧 updater 兼容形式，其内容必须与同一版本 `xpad2` 内嵌的制品集合
完全一致，不能成为第二条版本线。固定名 update manifest 和 delta index 供 Latest Release
发现；delta 只优化传输，不是独立版本线或信任根。

## 14. v0.6.0 验收标准

1. 单个 `xpad2` ELF 可以被推送到 `/data/local/tmp` 并正常执行。
2. `status` 和 `doctor` 不进行 Root 或持久修改。
3. `freeze ota`/`unfreeze ota` 幂等且只改变锁定的系统 OTA 主包。
4. 所有 Root 入口在 IonStack 前完成 OTA 冻结，冻结失败时不进入利用链。
5. canonical `/19`–`/260` fingerprint profile 可以进入控制面；三种精确 kernel build
   分别快速选择 v19-a/v19-b/v260 runner/preload。未知 build 进入只读 discovery；两个
   独立 anchor 唯一选型并完成 preflight/validate 后才进入写入，未知或冲突证据安全停止。
6. 两个 profile 分别激活锁定 KSU/SUU 和对应 Manager；APK 身份、`xpad-install` 哈希正确。
7. 完成后 SELinux 为 Enforcing，安装事务创建的临时 Root 窗口已关闭。
8. 再次执行同一 profile 能根据真实状态跳过完成项，不重复 Root 或重装。
9. 普通重启后 runtime 变为 inactive，但 OTA 冻结、APK 和 CLI 制品仍在；再次执行可只恢复 runtime。
10. 从显式本地缓存目录离线完成相同安装，缓存损坏时安全失败。
11. 六轮 Root 机会耗尽、Boot ID 改变、runtime 不兼容和 APK 签名冲突都有明确诊断。
12. 任意成功或失败事务均可导出 `xpad2log`。
13. `update --check` 只读取签名 manifest，准确区分 available/current/ahead。
14. 在线更新只下载目标 ELF 与小型 catalog 签名；候选 ELF 自行导出并安装匹配 cache。
15. manifest、ELF、cache ZIP、catalog 或 blob 任一身份不符时，当前 ELF 保持不变。
16. 替换后自检失败时，旧 ELF 与旧 cache 自动恢复，并留下失败事务收据。
17. 更新不获取 Root、不改变 OTA/runtime/APK 状态，完成后仍为 SELinux Enforcing。
18. BoomInstaller 保留 Shizuku 内部类/AIDL/Binder 身份，但只声明 Boom namespace 的
    Android 权限；最终 APK 不抢占官方 Shizuku permission/group。
19. `installer-backup` 只有在正式 anchor attribution、`run-as` UID 与本机 OEM installer UID 三者一致时才为 active。
20. 无关 APK 提交、主动抹除 attribution 和普通重启后，0044 状态均能验证或幂等恢复。
21. `ksu` 与 `suu` 组合请求在利用前失败；另一 runtime 已驻留时返回需要普通重启。
22. SUU exact Release 模块在真机显示 `Direct Syscall Table (4.19)`，清理临时 Root 后仍为 `u:r:ksu:s0` 且 SELinux Enforcing。
23. `status`、`doctor`、`verify`、`cleanup` 和 `znxrun status` 不会创建 31317 incident；锁定 ELF 只执行 native `self-test`。
24. 真实 31317 preflight 的原设置前后精确一致，阶段 JSONL 可解析且核心 PID 全程一致；模拟本 boot 熔断在写设置前返回 75。
25. 每个目标 APK 只经 0044 提交；0044 缺失时 31317 只补建并复验 0044，修复失败则目标 APK 保持未安装。
26. BoomInstaller 服务只接受唯一 UID 0/2000；普通重启后 UID 2000 本地 ADB 服务在有界时间内恢复，且不新增 31317 incident。
27. `xpad2log` 包含 Boom 自启动状态、服务 UID、0044 状态及最近 12 次经脱敏的 BoomInstaller 安装日志。
28. 所有 xpad-install 输出运行中逐行写入事务日志，退出码 75 无条件映射为普通重启；导出包包含 incident JSONL。
29. 删除外部 `/data/local/tmp/xpad-install` 后，BoomInstaller 仍能用 APK 内置锁定引擎完成 0044 安装、清理临时文件，并在普通重启后独立恢复 UID 2000 服务。
30. `version` 不扫描全部内嵌制品；每个制品只在实际解析/导出时验证大小与 SHA-256。
31. 网络中断后下一次请求携带正确 Range 并续传；永久 4xx 不重试，限流等待服从响应头。
32. 历史 cache 迁移为共享 SHA blob，只保留当前与一个回滚 release；旧 ELF 至少保留两份。
33. 发布脚本从上一稳定版生成更小的 zstd patch，验签后重建结果逐字节等于目标 ELF。
34. 当前 ELF 的版本、大小、SHA-256 精确匹配时在线更新记录 `binary_mode=delta` 且不下载
    完整 ELF；任一基线字段不匹配时安全走完整 ELF。
35. patch 缺失、损坏、超界或重建身份错误时不替换当前 ELF；完整 ELF 可用则自动回退，
    完整 ELF 同样不可用则事务明确失败并保留原版本。
36. 官方 `moe.shizuku.privileged.api` 已安装时，BoomInstaller r21 仍能经健康 0044 安装，
    以 UID 2000 启动并由 provider 返回有效 Binder；全程 SELinux Enforcing。
37. 31317 提交 anchor 后只在完整 `ZNXRUN_STATUS healthy` 时进入目标 APK 安装；alias
    延迟落盘会被有界轮询吸收，超时仍安全失败且目标 APK 未提交。
38. 两个并发 mutating update 中只有持有 `OperationLock` 的进程可进入下载/替换/回滚；
    另一个在修改共享状态前明确失败，`update --check` 保持只读。
39. `status`、`doctor`、`installer-backup`、`cleanup` 和日志导出在运行 xpad-install 前均
    验证 AArch64 ELF 与 catalog 锁定 SHA-256；错版或篡改文件只报告诊断，不执行。
40. 默认托管 cache 的签名、JSON、版本或 blob 任一校验失败时回退内嵌锁定制品并告警；
    `--cache-dir`/`XPAD2_CACHE_DIR` 显式 cache 的相同错误继续硬失败。
41. 候选安装前存在同目录原子回滚副本；候选验证失败后恢复 ELF 精确哈希，且
    `last-self-update.json` 指向的永久备份不会被同次回收删除。
42. fingerprint 固定前缀与 `:user/release-keys` 后缀不变；产品族门接受 canonical 数字
    incremental 和 arm64，Root 门只接受 19–260 与 `4.19.191`。18、261 与 V231227
    `/1703659196` 可运行 update/OTA/installer/Manager 控制面但不可进入 IonStack；前导零、
    符号、溢出、尾随字符、错误产品前缀或 ABI 在产品族门拒绝。
    fingerprint Root 范围不能直接决定 kernel offsets；范围内未知 `uname -v` 必须由至少
    两个独立动态 anchor 唯一选型，并先完成无写入 validate。
43. v0.5.2 的 signed catalog 顶层携带三套 IonStack profile 映射及对应 discovery offsets，update manifest 仅携带
    精确 `/260` 兼容锚点；v0.4.14 会忽略未知 catalog 顶层字段，仍能在 /260 上完成升级。
44. BoomInstaller Provider 必须同时报告 ready、配对密钥存在且可解密、paired，并区分
    network-untrusted、wireless-adb-not-started、key-invalid 与 pending-reboot；仅凭进程和
    Settings 值不能判定自启动健康。
45. UID 2000 的无线 ADB 等待探针使用 shell-attributed `settings` 命令读取全局状态，
    不以 `android` calling package 访问 SettingsProvider；/260 真机连续稳定 TLS、配对和
    Provider `paired=true` 验收通过。
46. 同产品族但不满足 Root 门的设备上，`update --check`、OTA、`xpad-installer`、
    `installer-backup`、Manager、BoomInstaller 和任意 CLI/APK 不被 Root profile 拦截；
    `root`、`ksu`、`suu`、`full`、`suu-full` 在任何 IonStack 写入前明确拒绝。
47. BoomInstaller r24 在 KSU 真机中以 UID 0 启动 server/broker，经 OEM Provider 安装
    目标 APK 并核验 installer 为 `com.tal.pad.znxxservice`；Provider 副本、私有 staging
    和内嵌 CLI 均在事务结束后删除。Magisk/KSU/SUU 复用同一 libsu UID 0 合约。
48. xpad-install 与 BoomInstaller 的 APK/DEX 暂存文件逐事务唯一；旧固定名只读残留、
    并发事务或上次中断不会阻断新事务，staging I/O 失败明确返回 artifact/path/errno 且
    Windows 工具不会误导用户重启。
49. `install zygisk`/`install lsposed` 只使用锁定的 NeoZygisk v2.3、Vector v2.0 和
    MagiskPolicy v30.7 ARM64 制品；大小、SHA-256、来源 commit/tag 与许可证均可追溯。
50. 旧 KSU `SET_SEPOLICY` 返回 `EOPNOTSUPP` 时，不把空成功当作已应用；MagiskPolicy
    live load 后 policy 哈希变化且精确读回 system_server self execmem，未应用内置 Magisk
    规则或 Vector 上游宽泛 `allow *`。
51. NeoZygisk 新 daemon 的每个 `memfd:zygisk-module` 在 system_server fork 前重标为
    `u:object_r:ksu_file:s0:c0`；状态探针同时验证 Zygote maps、单实例 daemon 和 memfd 标签。
52. Vector system_server 自动重试为 0；策略或 FD 传递失败不会形成 Zygote/system_server
    重启风暴，90 秒严格验活失败返回明确诊断。
53. Vector Active 必须同时满足 lspd 单实例、Neo 模块注册、配置数据库、live rule、当前
    system_server 的模块 maps 与带当前 PID 的 Bridge 注入日志，不能以 daemon 存活冒充。
54. `/260` 真机在 SELinux Enforcing 下记录 Vector framework 注入 system_server；CLI
    不包含具体应用包名、应用 Hook 载荷、scope 管理或业务日志验收条件。
55. IonStack 创建的临时 su 在显式 Hook 安装中保留到 Vector 验活；live rule 写入后先
    恢复 Enforcing，临时 su 只作为恢复通道，Bridge 必须在 Enforcing 下启动。验活后关闭
    daemon/socket/client；`hooks disable` 移除最小 live rule 后只做 userspace soft-reboot。
