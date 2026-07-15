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
adb -s SERIAL shell /data/local/tmp/xpad2 install full
```

从 v0.2.0 开始，首次 `adb push` 后可以直接在 Pad 上检查和安装后续稳定版本：

```sh
adb -s SERIAL shell /data/local/tmp/xpad2 update --check
adb -s SERIAL shell /data/local/tmp/xpad2 update
```

`install full` 会收敛以下目标状态：

- `/260` 固件的系统 OTA 主包已对 user 0 冻结；
- KernelSU 32547 / UAPI 2 以 late-load 方式在当前 boot 激活；
- KernelSU Manager v3.2.5-22-gccfee6dc（versionCode 32547）；
- `/data/local/tmp/xpad-install` v0.1.1 锁定构建；
- BoomInstaller v13.6.0.r10.d356705：Root 主服务通过隔离的 UID 1000 broker 安装 APK，
  并在普通开机时优先恢复 Root、失败时回退到已配对的本地 ADB。

再次执行同一命令是幂等的：已经通过包名、版本、证书、哈希和运行时探针验证的项目
会跳过。普通重启后 APK 和 CLI 保留，只恢复 KSU。

## 时间与重启预期

IonStack 临时 Root 通常需要数分钟，使用历史真机数据收敛出的 3-worker capture，最多
尝试 6 轮 holder 机会，并有 20 分钟总安全截止。6 轮均失败后，本 boot 后续成功率很低，
`xpad2` 会退出并明确要求普通重启，不会无限重试。KernelSU 的 `late-load` 子进程会在
后台完成模块注册；xpad2 会保留临时 Root 窗口并等待最多 30 秒，通过完整身份验证后才
恢复 SELinux 和清理临时 socket/client。

如果 Android 返回 `process is bad`，或者已加载的 KSU 无法通过锁定身份验证，
`xpad2` 同样要求普通重启。退出码 `75` 专门表示“需要普通重启”。

显式 `xpad2 root` 会保留临时 Root，并打印 SELinux 状态。完成操作后必须执行
`xpad2 cleanup` 或普通重启。`install ksu/full` 自己创建或接管的临时 Root 默认安全关闭，
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
xpad2 install ksu|ksu-manager|xpad-installer|boominstaller|full ...
xpad2 install cli FILE [--name NAME]
xpad2 install apk FILE
xpad2 verify [COMPONENT]
xpad2 repair COMPONENT
xpad2 cleanup
xpad2 logs export DIRECTORY
xpad2 cache path|list|verify|import DIRECTORY|prune|clear
```

安装普通 APK 不会把临时 Root、simpleperf 授权或 KernelSU Manager 是否存在作为
预检查条件。APK 会先解析并验证真实 manifest、ABI、v2/v3 签名和内容摘要；签名冲突
时不会自动卸载应用或清除用户数据。首次安装使用 OEM auto 通道；检测到同包已安装且
证书兼容时，升级使用 UID 1000 Direct PackageInstaller 通道，避免 OEM Provider 接收
更新请求后不落盘而一直等待。BoomInstaller 激活使用已经过独立身份验证的已安装
`base.apk` 与原生 starter，不把 shell 私有工作目录中的临时文件交给 UID 1000 执行。

名称边界保持固定：`BoomInstaller` 是
[`yoyicue/BoomInstaller`](https://github.com/yoyicue/BoomInstaller) 产生的 Android
APK；`xpad-installer` 是独立仓库产生的设备 CLI `/data/local/tmp/xpad-install`。
旧私有仓库名 `xpad2_installer` 已停用，不能再作为任何组件标识。

## 签名自更新

默认 `xpad2 update` 从 `yoyicue/xpad2-cli` 的 GitHub Latest Release 获取固定名的
`xpad2-update.json` 与签名。HTTPS 只负责传输；更新清单、目标 ELF、匹配的 cache ZIP、
catalog 和 `/260` profile 均由内置 production RSA 公钥验证。目标 ELF 在替换前必须
以候选进程完成一次自检，替换后再完成一次相同自检。

```sh
xpad2 update --check             # 只检查，不下载大文件、不修改设备
xpad2 update                     # 更新到最新稳定版
xpad2 update --version 0.2.1     # 选择精确发布版本
xpad2 update --reinstall         # 同版本修复性重装
xpad2 update --offline FILE.zip  # 无网络时使用完整离线更新包
```

更新无需 Root，也不改变 KSU、APK、OTA 冻结状态或用户数据。安装使用同文件系统的
`.partial + fsync + rename` 原子替换；旧 ELF 最多保留三份用于失败恢复。低版本不会被
自动安装；显式降级还必须同时给出 `--version`/`--offline` 和
`--allow-downgrade`。首次从 v0.1.x 升到 v0.2.0 仍需执行一次手工 `adb push`，因为旧
ELF 本身没有 updater。

## 离线目录缓存

默认运行目录为 `/data/local/tmp/.xpad2`，每个产品/catalog 组合使用独立的
`cache/releases/<product>--<catalog>/`，因此新旧 ELF 可以安全并存和回滚。也可使用：

```sh
xpad2 install full --cache-dir /data/local/tmp/xpad2-cache
XPAD2_CACHE_DIR=/data/local/tmp/xpad2-cache xpad2 install full
```

外部缓存必须同时满足：RSA 发布签名有效、catalog 属于当前 `xpad2` 版本、每个条目
仍在当前 `assets.lock.json` 中、blob 大小和 SHA-256 正确。缓存不能引入产品未锁定的
新版本；损坏缓存会安全失败，不会执行其中的 ELF。自更新把匹配 cache 写入目标版本
自己的目录，不会覆盖当前版本目录。通过 `--cache-dir` 或 `XPAD2_CACHE_DIR` 显式选择
的缓存仍保持严格失败；为避免把任意目录卷入跨版本事务，自更新时禁止该覆盖参数。

## 诊断

```sh
adb shell /data/local/tmp/xpad2 logs export /sdcard/Download
```

输出文件名为 `xpad2log-YYYYMMDD-HHMMSS.zip`，包含当前及历史事务、当前/上一 boot
可获得的 logcat、KSU、PackageManager、清理结果和 lock 身份。导出时会过滤设备序列号、
ADB key、配对凭据、token、密码和私钥相关行。

## 构建

主控制面使用 Rust；IonStack、ksud、xpad-install 和 APK 仍作为独立、哈希锁定制品。
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
的设备上使用。`xpad2` 不修改 AVB、boot image 或 system 分区，也不在线卸载/替换 KSU。
