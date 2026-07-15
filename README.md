# xpad2

`xpad2` 是运行在 XPad2 Android 设备上的单文件、离线、可按需获得临时 Root 的安装器。
它只支持已经验证的 `/260` 固件，不提供桌面 GUI、桌面 CLI 或 `xpad2.apk`。

## 快速开始

从同一版本 Release 下载 `xpad2-vX.Y.Z-android-arm64`：

```sh
adb -s SERIAL push xpad2-vX.Y.Z-android-arm64 /data/local/tmp/xpad2
adb -s SERIAL shell chmod 700 /data/local/tmp/xpad2
adb -s SERIAL shell /data/local/tmp/xpad2 status
adb -s SERIAL shell /data/local/tmp/xpad2 install full
```

`install full` 会收敛以下目标状态：

- `/260` 固件的系统 OTA 主包已对 user 0 冻结；
- KernelSU 32547 / UAPI 2 以 late-load 方式在当前 boot 激活；
- KernelSU Manager v3.2.4（versionCode 32457）；
- `/data/local/tmp/xpad-install` v0.1.1 锁定构建；
- BoomInstaller v13.6.0.r9.2f1ac6f、system 服务与普通开机自启动。

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

## 离线目录缓存

默认运行目录为 `/data/local/tmp/.xpad2`，制品缓存位于其 `cache/` 子目录。也可使用：

```sh
xpad2 install full --cache-dir /data/local/tmp/xpad2-cache
XPAD2_CACHE_DIR=/data/local/tmp/xpad2-cache xpad2 install full
```

外部缓存必须同时满足：RSA 发布签名有效、catalog 属于当前 `xpad2` 版本、每个条目
仍在当前 `assets.lock.json` 中、blob 大小和 SHA-256 正确。缓存不能引入产品未锁定的
新版本；损坏缓存会安全失败，不会执行其中的 ELF。升级 `xpad2` 后，旧版默认托管缓存
会被明确忽略并回退到当前 ELF 的内嵌制品；通过 `--cache-dir` 或 `XPAD2_CACHE_DIR`
显式选择的缓存仍保持严格失败，不会静默回退。

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
仓库的固定输出位置读取。设备运行时不联网，也不包含任何 GitHub token 或私有仓库凭据。

离线 cache 的 `catalog.sig` 使用现有 XPad2/BOOM RSA-4096 production identity；
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
