# xpad2

`xpad2` 是运行在 XPad2 Android 设备上的单文件、可离线工作、可按需获得临时 Root，
并能通过签名 Release 自更新的安装器。
它只支持已经验证的 `/260` 固件，不提供桌面 GUI、桌面 CLI 或 `xpad2.apk`。

第一次使用请直接阅读：[xpad2 小白使用指南](BEGINNER_GUIDE.md)。

## 快速开始

从同一版本 Release 下载 `xpad2-vX.Y.Z-android-arm64`：

```sh
adb -s SERIAL push xpad2-vX.Y.Z-android-arm64 /data/local/tmp/xpad2
adb -s SERIAL shell chmod 700 /data/local/tmp/xpad2
adb -s SERIAL shell /data/local/tmp/xpad2 status
adb -s SERIAL shell /data/local/tmp/xpad2 install
```

从 v0.2.0 开始，首次 `adb push` 后可以直接在 Pad 上检查和安装后续稳定版本：

```sh
adb -s SERIAL shell /data/local/tmp/xpad2 update --check
adb -s SERIAL shell /data/local/tmp/xpad2 update
```

不带组件的 `install` 默认等价于 `install full`。`full` 为兼容既有用户继续选择
KernelSU；它会收敛以下目标状态：

- `/260` 固件的系统 OTA 主包已对 user 0 冻结；
- KernelSU 32547 / UAPI 2 以 late-load 方式在当前 boot 激活；
- KernelSU Manager v3.2.5-22-gccfee6dc（versionCode 32547）；
- `/data/local/tmp/xpad-install` v0.2.5 锁定构建；
- `installer-backup`：正式签名的无代码/无权限 anchor 持久保存 0044 attribution，
  `run-as znxrun` 独立验证为本机 OEM installer 的真实 UID；
- BoomInstaller v13.6.0.r15.889f53c：内部 Shizuku 类/AIDL/Binder 协议保持上游结构，
  Android 全局权限改用 Boom 自有 namespace，可与官方 Shizuku 包共存；
  APK 自带并校验 `xpad-install` v0.2.5，修复后会等待 0044 alias 完整收敛；隔离的 UID 2000 broker 不依赖
  `/data/local/tmp/xpad-install` 或 `xpad2`。普通开机以有界 Job 恢复本地 ADB，不会触发
  0044/31317。

SukiSU Ultra 是显式可选后端：`xpad2 install suu-full` 会用已经真机验证的 SukiSU
Ultra 40796、官方 `com.sukisu.ultra` Manager v4.1.3 替换上述 KSU runtime/Manager
组合，其余 installer、0044 backup 和 BoomInstaller 保持相同。`ksu` 与 `suu` 共用
`kernelsu` 模块名，同一 boot 只能选择一个；切换必须先普通重启。

再次执行同一命令是幂等的：已经通过包名、版本、证书、哈希和运行时探针验证的项目
会跳过。普通重启后 APK 和 CLI 保留，只需恢复所选 runtime。

## 时间与重启预期

IonStack 临时 Root 通常需要数分钟，使用历史真机数据收敛出的 3-worker capture，最多
尝试 6 轮 holder 机会，并有 20 分钟总安全截止。6 轮均失败后，本 boot 后续成功率很低，
`xpad2` 会退出并明确要求普通重启，不会无限重试。KSU/SUU 的 `late-load` 子进程会在
后台完成模块注册；xpad2 会保留临时 Root 窗口并等待最多 30 秒，通过完整身份验证后才
恢复 SELinux 和清理临时 socket/client。

如果 Android 返回 `process is bad`，或者已加载的 KSU/SUU 无法通过锁定身份验证，
`xpad2` 同样要求普通重启。退出码 `75` 专门表示“需要普通重启”。
`xpad-installer` 只有在 0044 缺失或失效时才用 31317 补回 0044；31317 不接收目标 APK。
修复事务会逐阶段核对 boot ID、Zygote、system_server 与 SystemUI PID；任一变化立即
触发本 boot 熔断并返回 75，普通重启前不再尝试。

显式 `xpad2 root` 会保留临时 Root，并打印 SELinux 状态。完成操作后必须执行
`xpad2 cleanup` 或普通重启。`install ksu/full/suu/suu-full` 自己创建或接管的临时 Root 默认安全关闭，
并独立验证 SELinux Enforcing、socket 和 client 均已清理。

所有 Root 入口都会先冻结 `/260` 正在运行的系统 OTA 主包 `com.tal.pad.ota`，确认
PackageManager user 0 状态不可运行后才允许启动 IonStack。冻结失败时 Root 安全失败，
不会继续利用链。该状态跨普通重启保留；需要恢复系统更新时必须显式执行
`xpad2 unfreeze ota`。停止状态的 `com.tal.init.ota` 是 `xpad-installer` 的 zygote 对齐
依赖，应用升级组件 `com.tal.pad.app_upgrade` 则不是系统 OTA；两者都不会被冻结。

## 命令

```text
xpad2 version
xpad2 status [--json]
xpad2 doctor
xpad2 list
xpad2 info COMPONENT
xpad2 update --check [--json]
xpad2 update [--version VERSION]
xpad2 update --offline DIRECTORY_OR_ZIP
xpad2 root [-- COMMAND ARG...]
xpad2 freeze ota
xpad2 unfreeze ota
xpad2 install                              # 默认 full / KernelSU
xpad2 install ksu|suu|ksu-manager|suu-manager|xpad-installer|installer-backup|boominstaller ...
xpad2 install full|suu-full
xpad2 install cli FILE [--name NAME]
xpad2 install apk FILE
xpad2 verify [COMPONENT]
xpad2 repair COMPONENT
xpad2 cleanup
xpad2 logs export DIRECTORY
xpad2 cache path|list|verify|import DIRECTORY|prune|clear
```

安装普通 APK 不会把临时 Root、simpleperf 授权或 KSU/SUU Manager 是否存在作为
预检查条件。APK 会先解析并验证真实 manifest、ABI、v2/v3 签名和内容摘要；签名冲突
时不会自动卸载应用或清除用户数据。首次安装和同包升级都使用 auto：目标 APK 始终在
持久 0044 身份中提交，先尝试 OEM Provider，未提交时再尝试同一身份的 direct。若 0044
缺失或失效，31317 只负责补回并复验 0044，修复成功后才开始目标安装。BoomInstaller
激活使用已经过独立身份验证的已安装 `base.apk` 与原生 starter，控制面只保留标准
Root/ADB-shell 身份；安装 broker 使用 APK 自带的锁定引擎，xpad2 只负责可选分发和激活。

`installer-backup` 是备用安装路径，不是 Android 用户或常驻进程。xpad2 把它作为一等
状态展示：正式 anchor 的 PackageManager attribution 和 `run-as` UID 必须同时正确才算
`active`。安装 `xpad-installer` 时会幂等执行 `znxrun ensure`；健康时不创建事务，丢失或
仍依赖旧 carrier 时自动修复。任何由 xpad2 实际提交的 APK 安装/升级完成后还会再次
幂等执行 `ensure` 和独立状态验证，覆盖 PackageManager 重写 `packages.list` 的边界。
实现不直接编辑 `packages.list`，临时 OEM 白名单在成功、失败及可处理中断后均由监督
进程恢复。

名称边界保持固定：`BoomInstaller` 是
[`yoyicue/BoomInstaller`](https://github.com/yoyicue/BoomInstaller) 产生的 Android
APK；`xpad-installer` 是独立仓库产生的设备 CLI `/data/local/tmp/xpad-install`。
旧私有仓库名 `xpad2_installer` 已停用，不能再作为任何组件标识。

## 签名自更新

默认 `xpad2 update` 通过 `api.github.com` 的 Latest Release 元数据定位固定名的
`xpad2-update.json`、签名和 asset ID，再由 API 重定向到 release-assets 下载域；不要求
设备能够直连 `github.com:443`。HTTPS 只负责传输，GitHub API JSON 本身不作为信任根；
更新清单、目标 ELF、catalog 签名和 `/260` profile 均由内置 production RSA 公钥及
SHA-256 验证。v0.4.6 起还会读取独立签名的 `xpad2-deltas.json`：只有当前 ELF 的版本、
大小和 SHA-256 与某个发布基线全部精确一致，才下载对应 zstd patch；重建结果仍必须精确
匹配主更新清单中的目标大小和 SHA-256。索引不存在、没有匹配基线或 patch 下载/重建失败
时自动回退完整 ELF；索引或签名成对出现但无效时硬失败。由于旧 updater 不认识 delta，
从 v0.4.5 升级 v0.4.6 仍会下载一次完整 ELF，后续相邻版本才获得增量收益。

新候选 ELF 验证自身后直接导出其内嵌 cache，正常在线更新不再重复下载约 30 MiB 的
cache ZIP；该 ZIP 只为旧 updater 和独立离线导入保留。目标 ELF 在替换前后均以候选进程
自检。下载 partial 支持 HTTP Range 续传；只重试网络/5xx 等暂态错误，GitHub 403/429
会遵循 `Retry-After`/rate-limit reset，而不是短间隔空转。

```sh
xpad2 update --check             # 只检查，不下载大文件、不修改设备
xpad2 update                     # 更新到最新稳定版
xpad2 update --version 0.4.9     # 选择精确发布版本
xpad2 update --reinstall         # 同版本修复性重装
xpad2 update --offline FILE.zip  # 无网络时使用完整离线更新包
```

更新无需 Root，也不改变 KSU、APK、OTA 冻结状态或用户数据。安装使用同文件系统的
`.partial + fsync + rename` 原子替换；旧 ELF 只保留一份用于失败恢复。低版本不会被
自动安装；显式降级还必须同时给出 `--version`/`--offline` 和
`--allow-downgrade`。首次从 v0.1.x 升到 v0.2.0 或更高版本仍需执行一次手工
`adb push`，因为旧 ELF 本身没有 updater。

## 离线目录缓存

默认运行目录为 `/data/local/tmp/.xpad2`。每个产品/catalog 仍使用独立且签名的
`cache/releases/<product>--<catalog>/` 元数据，但制品实体统一存入按 SHA-256 命名的
`cache/blobs/`，release 目录仅保留指向内容仓库的受校验引用，不复制 blob。自动回收只
保留当前与一个回滚 release。
也可使用：

```sh
xpad2 install full --cache-dir /data/local/tmp/xpad2-cache
XPAD2_CACHE_DIR=/data/local/tmp/xpad2-cache xpad2 install full
```

外部缓存必须同时满足：RSA 发布签名有效、catalog 属于当前 `xpad2` 版本、每个条目
仍在当前 `assets.lock.json` 中、blob 大小和 SHA-256 正确。缓存不能引入产品未锁定的
新版本；损坏缓存会安全失败，不会执行其中的 ELF。自更新由候选 ELF 导出并校验匹配
cache，不会信任旧进程凭空生成制品。通过 `--cache-dir` 或 `XPAD2_CACHE_DIR` 显式选择
的缓存仍保持严格失败；为避免把任意目录卷入跨版本事务，自更新时禁止该覆盖参数。

## 诊断

```sh
adb shell /data/local/tmp/xpad2 logs export /sdcard/Download
```

输出文件名为 `xpad2log-YYYYMMDD-HHMMSS.zip`，包含当前及历史事务、完整当前/可获得的上一
boot logcat、DropBox/进程退出信息、KSU/SUU、PackageManager、Boom 自启动状态、0044 状态、
BoomInstaller 最近 12 次结构化安装日志、清理结果和 lock 身份。
所有 `xpad-install` stdout/stderr 在运行中逐行 `fsync` 到事务日志；31317 的阶段、设置元数据
和核心 PID JSONL 也会一并导出。导出时会过滤设备序列号、ADB key、配对凭据、token、密码
和私钥相关行。

## 构建

主控制面使用 Rust；IonStack、两套锁定 ksud、xpad-install 和 APK 仍作为独立、哈希锁定制品。
需要 Rust、`cargo-ndk`、Android NDK r29、`jq`、`zip` 和 OpenSSL：

```sh
cargo test --all
cargo android
tools/verify_sources.sh
export XPAD2_RELEASE_SIGNING_BACKUP=/path/to/protected/signing-backup
tools/package_release.sh
tools/verify_release.sh
```

构建机可以把私有上游的锁定文件放在 `XPAD2_ARTIFACT_DIR`。文件名必须匹配
`assets.lock.json`，并且大小和 SHA-256 始终重新校验。未指定时，开发机从同级组件
仓库的固定输出位置读取。普通安装完全离线；只有显式 `xpad2 update` 才通过内置
rustls/webpki HTTPS 客户端访问公开 GitHub Release。设备不包含 GitHub token、私有
仓库凭据或发布私钥。

离线 cache 的 `catalog.sig` 与自更新 `xpad2-update.json.sig` 使用现有 XPad2/BOOM
RSA-4096 production identity；两种 JSON 都有严格的 kind/schema/字段边界。
`tools/sign_catalog.sh` 只在发布机内存中恢复 PKCS12 密码和临时私钥，随后销毁临时目录。
私钥、加密密码和恢复 RSA key 保持在受限本地目录与群晖冷备，绝不进入仓库或诊断包。
发布 ZIP 同时包含各组件许可证、BoomInstaller 修改声明，以及从 `Cargo.lock` 对应 crate
源码自动收集的 Rust 第三方许可证清单。`tools/verify_sources.sh` 会联网确认每个
`sources.lock.json` 仓库仍是 canonical 名称，且 tag 精确解析到锁定 commit；旧仓库名的
重定向不会被当作有效来源。

精确架构、事务、状态和验收定义见 [DESIGN.md](DESIGN.md)。

## 支持边界

此版本只接受以下指纹：

```text
alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/260:user/release-keys
```

临时 Root 链可能导致设备重启或 kernel panic。仅应在你拥有或明确获授权、且有恢复路径
的设备上使用。`xpad2` 不修改 AVB、boot image 或 system 分区，也不在线卸载、替换或
切换 KSU/SUU。
