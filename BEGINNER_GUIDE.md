# xpad2 小白使用指南

这份指南适合第一次使用命令行的用户。按顺序复制命令即可，不需要自己获取 Root，
也不需要安装 `xpad2.apk`——这个 APK 不存在，`xpad2` 是放在 Pad 上运行的单文件命令。

## 1. 使用前确认

你需要：

- 一台电脑（Windows、macOS 或 Linux）；
- 一根能传数据的 USB 线；
- 电脑已经安装 Android Platform Tools，终端里能运行 `adb`；
- Pad 已开启 USB 调试，并且 fingerprint incremental 是 `/19`–`/260`；
- Pad 中的重要数据已有备份，设备是你本人所有或已经获得明确授权。

`xpad2` 只支持下面这个签名固件范围：

```text
alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/<19..260>:user/release-keys
```

其中 `<19..260>` 表示 canonical 十进制闭区间，不是字面文本。设备和构建前缀、
`:user/release-keys` 后缀、内核 `4.19.191` 系列及 arm64 ABI 仍必须匹配。
V231227 的 `/1703659196` 当前不在生产支持范围内。

以下三种精确 `uname -v` 会直接走快速路径：

```text
#1 SMP PREEMPT Tue Aug 13 02:06:24 CST 2024   (xpad2-v19-a)
#1 SMP PREEMPT Mon Dec 16 23:29:13 CST 2024   (xpad2-v19-b)
#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026   (xpad2-v260)
```

范围内的其他 `uname -v` 不会在入口被拒绝。Root 时程序先运行只读 discovery；只有
至少两个 offset anchor 唯一指向上述某一 profile，并完成 preflight 与无写入 validate，
才继续最终 Root。证据不足或候选冲突会安全停止并保留诊断日志。

临时 Root 过程存在自动重启或 kernel panic 风险。不要在电量过低时操作，也不要在执行
过程中拔线、强制关机或同时启动第二个 `xpad2`。

## 2. 连接 Pad

用 USB 连接电脑和 Pad，打开终端或 PowerShell，执行：

```sh
adb devices
```

正常输出类似：

```text
List of devices attached
XXXXXXXXXXXX    device
```

如果显示 `unauthorized`，解锁 Pad，在 USB 调试授权弹窗中选择允许，再执行一次
`adb devices`。如果没有设备，先检查 USB 线、USB 模式和 Platform Tools。

如果同时连接了多台 Android 设备，后续命令中的 `adb` 都要改成：

```text
adb -s 你的设备序列号
```

## 3. 下载并校验 xpad2

当前正式版本是
[`v0.5.1`](https://github.com/yoyicue/xpad2-cli/releases/tag/v0.5.1)。只需要下载：

```text
xpad2-v0.5.1-android-arm64
```

macOS 或 Linux 可以直接执行：

```sh
curl -fLO https://github.com/yoyicue/xpad2-cli/releases/download/v0.5.1/xpad2-v0.5.1-android-arm64
shasum -a 256 xpad2-v0.5.1-android-arm64
```

Windows PowerShell 可以执行：

```powershell
Invoke-WebRequest -Uri "https://github.com/yoyicue/xpad2-cli/releases/download/v0.5.1/xpad2-v0.5.1-android-arm64" -OutFile "xpad2-v0.5.1-android-arm64"
Get-FileHash .\xpad2-v0.5.1-android-arm64 -Algorithm SHA256
```

正确的 SHA-256 是：

```text
2a03faf398b9de2011d5fc1d5d69bb66192fee7e03998fe3f518d2246a1a5ac3
```

哈希不一致时不要继续，重新下载文件。

## 4. 把 xpad2 安装到 Pad

在下载文件所在目录执行：

```sh
adb push xpad2-v0.5.1-android-arm64 /data/local/tmp/xpad2
adb shell chmod 700 /data/local/tmp/xpad2
adb shell /data/local/tmp/xpad2 version
```

最后一条命令应显示：

```text
xpad2 0.5.1 (catalog 2026-07-18.4)
```

这就表示 `xpad2` 已经安装到了：

```text
/data/local/tmp/xpad2
```

## 5. 首次检查

执行：

```sh
adb shell /data/local/tmp/xpad2 status
```

确认输出中包含：

```text
指纹/19–/260支持=yes
SELinux=Enforcing
```

如果提示固件不支持，不要尝试绕过检查，也不要继续 Root。

## 6. 一键完成安装

小白用户只需要使用下面这一条命令；不写组件时默认就是 `full`：

```sh
adb shell /data/local/tmp/xpad2 install
```

它会自动完成：

1. 冻结系统 OTA 主程序，避免操作期间自动升级；
2. 在需要时获得临时 Root；
3. 激活当前启动周期的 KernelSU；
4. 安装 KernelSU Manager；
5. 安装 `xpad-installer`；
6. 建立并验证与本机 OEM installer UID 一致的 `installer-backup` 备用安装路径；
7. 安装并激活 BoomInstaller；
8. 恢复 SELinux Enforcing，并清理临时 Root 文件和进程。

临时 Root 通常需要几分钟，最多尝试 6 轮，并有 20 分钟安全截止。终端仍在持续输出时
请耐心等待，不要重复执行命令。

首次配置 BoomInstaller 无线调试时，Pad 可能弹出“始终允许此网络”之类的网络信任
确认。请保持屏幕解锁并点允许；工具会等待无线 ADB 开关与 TLS 端口连续稳定后再配对，
最多等待 90 秒。没有确认时会明确报告 `waiting-network-trust` 并失败，不会假装安装成功。
配对完成后若显示 `pending-reboot`，按提示普通重启一次。

小白用户不要直接运行：

```text
xpad2 root
```

默认 `full` 会自动管理临时 Root，并在结束时进行安全清理。

## 7. 判断是否成功

安装完成后再次执行：

```sh
adb shell /data/local/tmp/xpad2 status
```

正常状态应包含：

```text
SELinux=Enforcing
temporary-root  absent
ota             active
ksu             active
suu             ready
ksu-manager     installed
xpad-installer  installed
installer-backup active
boominstaller   active
```

再次执行 `install` 是安全的。已经验证成功的项目会直接跳过，不会重复安装。

### 可选：使用 SukiSU Ultra

默认 `full` 保持 KernelSU，避免既有用户升级后被静默切换。只有明确希望使用 SukiSU
Ultra 时，先普通重启，再执行：

```sh
adb shell /data/local/tmp/xpad2 install suu-full
```

该 profile 使用 SukiSU Ultra 40796 与官方 Manager v4.1.3；其余安装器组件相同。
`ksu` 和 `suu` 同一 boot 不能并存，不能在已经加载其中一个后在线切换。

## 8. 如果提示需要普通重启

下面几种情况都应该普通重启后再试：

- 6 轮 Root 机会全部失败；
- 出现 `process is bad`；
- 程序退出码是 `75`；
- 提示 KSU/SUU 状态不兼容或当前 boot 不再适合继续尝试。

可以在 Pad 上正常关机再开机，或者执行：

```sh
adb reboot
adb wait-for-device
adb shell /data/local/tmp/xpad2 install
```

不要在同一个失败的启动周期里反复强行执行 Root。

## 9. 普通重启后怎么办

普通重启后：

- `xpad2`、对应 Manager、BoomInstaller、`xpad-installer`、`installer-backup` 和 OTA
  冻结状态仍然保留；
- KSU/SUU late-load 只属于当前启动周期，可能显示为 inactive 或 absent。

需要恢复默认 KSU profile 时重新执行：

```sh
adb shell /data/local/tmp/xpad2 install
```

此前选择 SUU 的设备则继续执行 `xpad2 install suu-full`，不要改用默认 `install`，除非
已经普通重启且确实要切回 KSU。

已经安装好的 APK 和 CLI 会被跳过，只恢复缺失的运行时状态。

如果只有 `installer-backup` 不是 `active`，不需要重新 Root，可以单独执行：

```sh
adb shell /data/local/tmp/xpad2 repair installer-backup
```

该命令会校验或恢复正式 anchor，再独立验证 `run-as znxrun` 的 UID 与本机
`com.tal.pad.znxxservice` 的真实 UID 一致；不同设备可能是 10070、10072 等不同值。

## 10. 恢复系统 OTA

`install`、`install full` 和 `install suu-full` 都会冻结系统 OTA 主程序。只有确实准备
进行官方系统升级时，才执行：

```sh
adb shell /data/local/tmp/xpad2 unfreeze ota
```

重新冻结：

```sh
adb shell /data/local/tmp/xpad2 freeze ota
```

系统升级可能使 Root 链失效。升级前应先确认新 fingerprint incremental、内核和 ABI
是否仍在签名 profile 内。

## 11. 出问题时导出日志

一键生成诊断包：

```sh
adb shell /data/local/tmp/xpad2 logs export /sdcard/Download
```

命令会打印类似路径：

```text
/sdcard/Download/xpad2log-20260715-120000.zip
```

把打印出的真实路径复制到下面命令中：

```sh
adb pull /sdcard/Download/xpad2log-20260715-120000.zip .
```

远程求助时提供这个 ZIP。它包含当前完整 logcat、可取得的上一 boot、DropBox/进程退出
信息、逐行持久化的安装输出、Boom 自启动/服务 UID/最近安装日志、0044 状态，以及
`xpad-installer` 的 31317 修复阶段/PID 元数据。诊断导出
会过滤设备序列号、ADB key、配对凭据、token、密码和私钥相关内容。

## 12. 更新 xpad2

v0.2.0 以后优先让 Pad 自己检查和安装稳定更新：

```sh
adb shell /data/local/tmp/xpad2 update --check
adb shell /data/local/tmp/xpad2 update
```

检查不会修改版本或组件状态。v0.4.6 起，相邻版本且当前文件未经修改时会优先下载签名
增量，通常只有几百 KiB；当前 ELF 不是精确发布基线或增量失败时会自动改下完整 ELF。
从 v0.4.5 升到首个支持增量的 v0.4.6 仍需完整下载一次。大文件每 15 秒会打印一次字节数
和百分比，网络中断会从已验证的 partial 续传。程序会验证签名清单、增量索引、目标 ELF、
catalog 和固件身份，再由新 ELF 导出自己的离线制品并原子替换自身；不需要 Root、不重启，
也不会卸载 APK 或清除应用数据。

Pad 无法联网时，在电脑下载同一 Release 的 `xpad2-update-vX.Y.Z.zip`，推送后离线更新：

```sh
adb push xpad2-update-vX.Y.Z.zip /data/local/tmp/
adb shell /data/local/tmp/xpad2 update --offline /data/local/tmp/xpad2-update-vX.Y.Z.zip
adb shell rm /data/local/tmp/xpad2-update-vX.Y.Z.zip
```

如果当前仍是 v0.1.x，或设备不是精确 `/260` 且当前 xpad2 早于 v0.5.0，需要先按
第 3–4 节手工覆盖到当前 v0.5.1 一次；旧 updater 的精确 `/260` 门禁无法自行跨入
新的 fingerprint 范围。

## 常见问题

### `adb: command not found`

电脑没有安装 Platform Tools，或者 `adb` 所在目录没有加入 `PATH`。

### `more than one device/emulator`

同时连接了多台设备。先运行 `adb devices`，然后使用：

```sh
adb -s 设备序列号 shell /data/local/tmp/xpad2 status
```

### 有 `xpad2.apk` 吗？

没有。`xpad2` 是 Android ARM64 CLI；KSU/SUU Manager 和 BoomInstaller 才是 APK。

### Pad 需要联网吗？

`install full`、`install suu-full` 和所有 Root/安装能力都不需要联网，因为 ELF 已内嵌锁定制品。只有选择
在线 `xpad2 update` 时 Pad 需要访问公开 GitHub Release；也可以使用上面的离线更新包。
