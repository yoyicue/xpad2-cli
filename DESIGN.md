# XPad2 CLI 设计

状态：v0.1.2 已实现；v0.1.1 完成 BoomInstaller 依赖身份和公开分发材料，v0.1.2
增加可验证的 OTA 冻结策略与 Root 前强制门禁（2026-07-15）。

验收覆盖单 ELF、只读状态探针、3-worker IonStack 临时 Root、KernelSU late-load、
CLI/APK 身份验证、临时 Root 安全收口、同 boot 幂等重跑、普通重启后恢复、RSA 签名
离线缓存、损坏缓存安全失败和 `xpad2log` 导出。发布组合以 `assets.lock.json` 与
`sources.lock.json` 为准。

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
adb -s SERIAL shell /data/local/tmp/xpad2 install full
```

`xpad2` 支持安装两类制品：

1. CLI 制品：Android ELF 命令，例如 `xpad-install`。
2. APK 制品：Android 应用，例如 KernelSU Manager 和 BoomInstaller。

KernelSU 是当前启动周期的 runtime 能力，不归入 CLI/APK 两类制品；临时 Root 是
安装事务使用的能力边界，也不是一个持久安装包。

## 2. 非目标

- 不开发 `xpad2.apk`。
- 不开发 XPad2 Manager GUI。
- 不开发 `xpad2ctl`。
- 不替代 Android 的通用软件仓库或 PackageManager。
- 不修改 AVB、boot image 或 system 分区。
- 不在线卸载或替换已经加载的 KernelSU 模块。
- 第一版不自动联网下载制品。

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
   +-- IonStack Temporary Root Provider
   +-- KernelSU Late-load Provider
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

安装普通 APK 不把 Root、simpleperf 授权或 KernelSU Manager 是否存在作为预检查条件。

### 3.1 仓库与制品的关系

`xpad2-cli` 是集成和产品发布仓库，不是所有组件源码的合并仓库。

```text
组件源码仓库
|-- xpad2-ionstack-poc
|-- xpad2-ksu-lateload
|-- xpad-installer
|-- KernelSU Manager
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
- Root、KernelSU、CLI 和 APK provider 的适配层。
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
-> /260 真机 install full、重跑、重启恢复和失败收尾验证
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
ksud                                        现有 Rust 制品
KernelSU Manager / BoomInstaller            已签名 APK
```

`xpad2` 将底层二进制作为经过哈希锁定的数据内嵌或放入缓存，运行时解包并作为独立
子进程调用。第一版不通过 FFI 把 exploit 或 installer 源码链接进 Rust 主程序，以便
保留组件隔离、原始许可证边界和现有真机验证证据。

Rust 控制面负责：

- 命令解析和安装计划。
- 原子文件操作、目录缓存和事务恢复。
- JSON catalog、JSONL event 和安装收据。
- SHA-256 与 catalog 签名验证。
- 子进程、signal、Boot ID 和操作锁管理。
- `xpad2log` 打包和脱敏。

目标构建为 `aarch64-linux-android`、Android API 33 PIE ELF；release profile 使用
LTO、strip 和 `panic=abort`。构建必须提交 `Cargo.lock`，运行时不需要 Rust 工具链、
JVM 或网络。依赖保持克制并锁定版本，优先使用 `serde`/`serde_json`、`sha2`、RSA
验签、ZIP 以及必要的 `libc`/`nix` 能力。

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

### 4.2 Root

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

### 4.3 内置组件

```sh
xpad2 install ksu
xpad2 install ksu-manager
xpad2 install xpad-installer
xpad2 install boominstaller
xpad2 install full
```

支持一次选择多个组件：

```sh
xpad2 install ksu ksu-manager boominstaller
```

### 4.4 任意本地制品

```sh
xpad2 install cli FILE [--name NAME]
xpad2 install apk FILE
```

CLI 制品第一版只允许落到 `/data/local/tmp`。默认文件名取输入 basename；`--name`
只允许安全的单段文件名，不能包含 `/`、`..` 或控制字符。

### 4.5 验证、修复和清理

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
| `ota` | policy | `/260` 系统 OTA 主包对 user 0 不可运行 | 持久，显式解冻 |
| `ksu` | runtime | KernelSU late-load 接口正常 | 当前启动周期 |
| `ksu-manager` | APK | `me.weishu.kernelsu` 匹配锁定版本 | 持久 |
| `xpad-installer` | CLI | `/data/local/tmp/xpad-install` 匹配锁定哈希 | 普通重启后保留 |
| `boominstaller` | APK | `com.yoyicue.boominstaller` 安装、激活并配置自启动 | 持久 |
| `full` | bundle | 上述四项全部达到目标状态 | 混合 |

`full` 不包含任何 `xpad2.apk`，因为不存在该制品。

## 6. `install full` 事务

```text
1. 获取全局 operation lock
2. 记录 Boot ID、SELinux、现有 Root/KSU/组件状态
3. 校验精确 /260 固件、内核和制品锁
4. 冻结并复验 `/260` OTA 主包；失败则停止
5. 如果 KSU 已健康加载，跳过临时 Root 和 late-load
6. 否则在 OTA 已冻结的前提下通过 IonStack POC 获取临时 Root
7. late-load 锁定版本的 KernelSU
8. 部署并验证 xpad-install CLI
9. 安装或升级锁定版本的 KernelSU Manager APK
10. 安装 BoomInstaller APK
11. 激活 BoomInstaller 并配置普通开机自启动
12. 验证 OTA、KSU 与全部制品目标状态
13. 恢复 SELinux Enforcing
14. 关闭安装事务创建的临时 su daemon/socket/client
15. 写入事务收据和日志，释放 operation lock
```

原则：

- 一次事务最多获取一次临时 Root。
- 用户显式执行 `root` 时留下临时 Root；`install ksu/full` 内部获取的 Root 默认关闭。
- 任一步失败后仍优先执行 SELinux 和临时 Root 收尾。
- 如果 KSU 已经成功加载、后续 APK 安装失败，记录部分成功；重跑时从状态探针继续。
- 如果 KSU 已加载但版本不匹配或不健康，停止并要求普通重启，不尝试在线卸载或替换。
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
- 对 `xpad-install` 运行固定的 `doctor`/版本探针。
- 写入安装收据。

### 7.2 APK 制品

安装前：

- 解析 APK 包名、versionCode、签名证书和支持的 ABI。
- 内置 APK 必须与 catalog 中的包名、版本、签名和 SHA-256 一致。
- 任意 APK 显示实际解析结果，不根据文件名推断包名。

安装时：

- 交给 `xpad-install` 的 `auto` 路径选择有效身份通道。
- 已安装相同或更高版本且签名匹配时允许跳过。
- 签名不兼容时停止，不自动卸载现有应用或清除用户数据。

安装后：

- 通过 PackageManager 独立读取实际包名、versionCode、签名和 installer attribution。
- BoomInstaller 还必须验证激活后的 system 服务和自启动配置。
- 首次安装走 OEM auto provider；同包同证书升级走 UID 1000 Direct PackageInstaller。
  `/260` 的 OEM provider 对首次安装可靠，但可能接收更新请求后不实际提交；升级不能
  在该路径等待到超时。
- BoomInstaller 激活从已验证安装目录读取 `base.apk` 和 `lib/arm64/libshizuku.so`；
  不放宽 xpad2 的 0700 私有工作目录，也不要求 UID 1000 穿透 shell 私有目录。

## 8. 本地目录缓存

本地缓存是一级能力。默认根目录：

```text
/data/local/tmp/.xpad2/
|-- cache/          已校验制品缓存，普通重启后保留
|-- work/           当前事务临时文件
|-- state/          安装收据与状态快照
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
  "version": "0.1.1",
  "kind": "cli",
  "sha256": "a0b638402abf0e567d8927ac1a865b1eefaff710bc4f32273bd5c49ce55fcf75",
  "size": 54680,
  "target": "/data/local/tmp/xpad-install"
}
```

### 8.2 解析顺序

对命名组件按以下顺序解析：

1. `--cache-dir` 指定目录。
2. `XPAD2_CACHE_DIR` 指定目录。
3. 默认 `/data/local/tmp/.xpad2/cache`。
4. `xpad2` 单文件内嵌的基线制品。
5. 全部缺失时明确失败；第一版不联网下载。

命中缓存不代表可信。每次使用前仍需校验 catalog、签名、大小和 SHA-256。

默认托管缓存位于固定状态目录，跨 `xpad2` 版本升级时可能保留旧 catalog。若旧 catalog
签名有效但 release 身份不同，安装解析明确告警并回退到当前 ELF 的内嵌制品；签名损坏、
内容损坏，以及通过 `--cache-dir`/`XPAD2_CACHE_DIR` 显式选择的任何不匹配缓存仍然硬失败。

### 8.3 缓存安全和生命周期

- 内嵌 catalog 是受信任的基线。
- 第一版的外部 catalog 必须通过发布签名验证，并且所有 blob 都必须出现在当前
  `assets.lock.json` 中；签名不能授权缓存绕过产品版本锁引入新组件。
- 组件版本升级必须发布新的 XPad2 版本和锁文件，缓存不是独立更新渠道。
- `/sdcard` 只作为导入来源；不得从可被其他应用写入或 `noexec` 的位置原地执行 ELF。
- 导入使用 `.partial`、`fsync` 和原子 `rename`。
- blob 以 SHA-256 命名，同一内容只保存一份。
- `cleanup` 不清缓存。
- `cache prune` 保留当前锁定版本及最近一次成功事务使用的 blob。
- `cache clear` 必须显式执行，并且不能删除正在运行事务引用的文件。

电脑准备离线缓存时：

```sh
adb -s SERIAL push ./xpad2-cache /data/local/tmp/
adb -s SERIAL shell /data/local/tmp/xpad2 \
  install full --cache-dir /data/local/tmp/xpad2-cache
```

这里的“本地目录”指 Android 设备上的目录；`xpad2` 无法直接读取电脑文件系统。

## 9. 状态与成功判定

| 对象 | 成功判定 |
| --- | --- |
| 临时 Root | 实际执行 `su -c id` 返回精确 root 身份；socket/文件存在不算 |
| KernelSU | 模块存在、`ksud debug info` 的版本/UAPI/LKM/late-load/runtime 字段匹配 |
| KSU Manager | 包名、versionCode、签名及与锁定 KSU 组合兼容 |
| xpad-install | 目标路径、ELF ABI、SHA-256 和 `doctor` 全部通过 |
| BoomInstaller | APK 身份正确、system 服务工作、自启动配置完成 |
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

## 10. 日志与诊断

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
- KernelSU late-load 及 `debug info`。
- CLI/APK 安装和独立验证结果。
- 当前事务、上一次事务和上一次启动可获得的相关日志。
- 清理结果及仍需普通重启的原因。

默认脱敏设备 SN、ADB key、私钥、配对凭据、token 和应用私有数据。

执行过程使用稳定的 JSONL event schema，同时默认渲染为可读文本。例如：

```json
{"event":"step","name":"root-holder","state":"running","attempt":2,"max":6}
{"event":"component","id":"ksu","state":"active","runtime":"current-boot"}
{"event":"action-required","action":"reboot","reason":"holder-attempts-exhausted"}
```

## 11. 初始锁定制品

首个实现版本以当前已验证制品为基线；正式构建时写入 `assets.lock.json`：

| 组件 | 版本/来源 | SHA-256 |
| --- | --- | --- |
| IonStack POC | `xpad2-ionstack-poc` `acb75f8` | 分组件锁定；3-worker 安全参数 |
| KernelSU module | XPad2 Linux 4.19 late-load | `a99d230975c70c7efe72142770f936cd5e7585cfdd6ba9c8d45807bdf87b3f13` |
| `ksud-xpad2` | KernelSU 32547 / UAPI 2 | `8e6fed9f063b9b998f5b0cec8b64f31ad1eea885c528b9e9883ff3f4cd108e06` |
| KernelSU Manager | v3.2.4 / 32457 | `f0951351291494e0c309267b375cf5bfbdb5eca6df0ec18f6fb7df8b3dea990b` |
| `xpad-install` | v0.1.1 | `a0b638402abf0e567d8927ac1a865b1eefaff710bc4f32273bd5c49ce55fcf75` |
| BoomInstaller | v13.6.0.r9.2f1ac6f production | `308cd48362d57b34344f7b52b3219ce99aa585d112479dc1d9564127f06fa1d6` |

版本号相等不是 KSU/Manager 兼容性的判据；兼容组合由 catalog 显式锁定。

## 12. 发布制品

一个版本只发布 Android CLI，不发布 APK 或桌面程序：

```text
xpad2-vX.Y.Z-android-arm64
xpad2-vX.Y.Z-android-arm64.zip
xpad2-cache-vX.Y.Z.zip
assets.lock.json
sources.lock.json
SHA256SUMS
licenses/
```

裸 ELF 便于直接 `adb push`；主 ZIP 包含文档、锁文件、许可证和校验清单。缓存 ZIP
是可选的离线部署形式，其内容必须与同一版本 `xpad2` 内嵌的制品集合完全一致，不能
成为第二条版本线。

## 13. 第一版验收标准

1. 单个 `xpad2` ELF 可以被推送到 `/data/local/tmp` 并正常执行。
2. `status` 和 `doctor` 不进行 Root 或持久修改。
3. `freeze ota`/`unfreeze ota` 幂等且只改变锁定的系统 OTA 主包。
4. 所有 Root 入口在 IonStack 前完成 OTA 冻结，冻结失败时不进入利用链。
5. 精确 `/260` 普通启动现场可以执行 `install full`。
6. 完成后 KernelSU 正常、两个 APK 身份正确、`xpad-install` 哈希正确。
7. 完成后 SELinux 为 Enforcing，安装事务创建的临时 Root 窗口已关闭。
8. 再次执行 `install full` 能根据真实状态跳过完成项，不重复 Root 或重装。
9. 普通重启后 KSU 变为 inactive，但 OTA 冻结、APK 和 CLI 制品仍在；再次执行可只恢复 KSU。
10. 从显式本地缓存目录离线完成相同安装，缓存损坏时安全失败。
11. 六轮 Root 机会耗尽、Boot ID 改变、KSU 不兼容和 APK 签名冲突都有明确诊断。
12. 任意成功或失败事务均可导出 `xpad2log`。
