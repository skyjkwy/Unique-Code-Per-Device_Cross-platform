# Unique-Code-Per-Device（Cross-platform）

一机一码授权系统：C 核心 + Qt 6 图形界面，支持 Windows / Linux / macOS，提供机器码绑定、离线激活码、有效期控制与防篡改校验。

项目代码基于skywyjk的开源项目，项目代码请见 [GitHub](https://github.com/skywyjk/Unique-Code-Per-Device)

## 功能概览

- 机器码：基于本机硬件指纹生成，可复制、可规范化、可混淆显示。
- 离线激活：作者用私钥对「机器码 + 用户信息 + 有效时长」签名生成激活码，客户机用内置公钥离线验签，全程不需要授权服务器。
- 有效期控制：激活码可设置年/月/日/时/分/秒，运行中实时计算剩余时间。
- 时间防护：NTP 授时（UDP 123）加性能计数器锚定，抑制改系统时间。
- 防篡改：Windows 下构建时计算 DLL `.text` 段 SHA-256 并加载校验，同时带反调试检查；Linux/macOS 下关闭这两项平台专有加固，保留加密授权文件、多份备份、HMAC 时间锚与 NTP 校验。
- 授权数据：主文件位于程序目录 `license-SkyBox.dat`，并按平台冗余备份：
  - Windows：注册表 + `%LOCALAPPDATA%\SkySoftware\license-SkyBox.dat` + NTFS ADS。
  - Linux：`$XDG_DATA_HOME/SkySoftware/license-SkyBox.dat` + 程序目录隐藏缓存。
  - macOS：`~/Library/Application Support/SkySoftware/license-SkyBox.dat` + 程序目录隐藏缓存。
- 除 NTP 授时外无任何网络通信。

## 目录结构

```
Unique-Code-Per-Device/
├─ CMakeLists.txt            跨平台构建入口
├─ build.sh                  Linux / macOS 一键构建
├─ build.bat                 Windows 一键构建（自动探测 VS + CMake + Ninja）
├─ install_qt.py             Qt 6 安装脚本（基于 aqtinstall）
├─ include/                  公共头文件
│  ├─ platform.h             平台抽象层
│  ├─ license.h              授权核心
│  ├─ license_dll.h          对外 DLL / 动态库接口
│  ├─ hardware.h            硬件指纹
│  ├─ ntp_client.h          NTP 授时
│  ├─ time_anchor.h         HMAC 时间锚
│  ├─ anti_debug.h          反调试接口
│  ├─ ecdsa.h               ECDSA P-256
│  └─ sha256.h              可移植 SHA-256 / HMAC
├─ src/
│  ├─ license.c / license_dll.c / key.c / sha256.c
│  ├─ platform_win32.c / platform_posix.c
│  ├─ hardware.c / hardware_posix.c
│  ├─ ntp_client.c / ntp_posix.c
│  ├─ time_anchor.c / time_anchor_posix.c
│  ├─ anti_debug.c / anti_debug_posix.c
│  ├─ ecdsa.c / ecdsa_sign.c / ecdsa_openssl.c
│  ├─ license_backup_win32.c / license_backup_posix.c
│  ├─ pe_digest.c / hashgen.c（Windows 自校验哈希）
│  ├─ embed_key.c（把密钥转成头文件）
│  └─ qt/                    Qt 6 图形界面
│     ├─ common/             共用封装与样式
│     ├─ license_system/     激活工具
│     ├─ generator/          发码工具
│     ├─ keygen/             密钥对生成器
│     └─ dat_viewer/         授权文件查看器
├─ tests/core_roundtrip.c    核心激活往返测试（可选）
├─ key/
│  ├─ sky.bin                ECDSA 私钥（保密，仅用于 generator）
│  ├─ sky_share.bin          ECDSA 公钥（编入客户端）
│  └─ 公钥私钥区分.txt
├─ logo.ico
├─ LICENSE                   MIT 许可证
└─ README.md
```

## 依赖

| 平台 | 编译器 | 依赖 |
| --- | --- | --- |
| Windows x64 | MSVC 2019/2022/2026 | CMake 3.16+、Ninja（VS 自带即可）、Qt 6 Widgets（可选） |
| Linux x64 | GCC / Clang | CMake、OpenSSL 开发包（`libssl-dev`）、Qt 6 Widgets（可选） |
| macOS Intel / Apple Silicon | Apple Clang | CMake、Homebrew OpenSSL、Qt 6（可选） |

核心库与命令行构建不依赖 Qt。未找到 Qt 6 时 CMake 会给出警告并跳过四个 GUI 工具。

## 构建

### Windows

```bat
build.bat
```

指定 Qt 6 路径（根据实际安装位置调整）：

```bat
build.bat -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
```

尚未安装 Qt 6 时，可先运行安装脚本（需要 Python 3.8+）：

```bat
python install_qt.py
```

脚本默认安装 Qt 6.8.0 到 `C:\Qt`，可用 `--version`、`--arch`、`--out`、`--modules` 调整。国内网络可改用镜像：

```bat
python install_qt.py --qt-base https://mirrors.aliyun.com/qt
```

### Linux

```bash
sudo apt install build-essential cmake libssl-dev qt6-base-dev
chmod +x build.sh
./build.sh
```

### macOS

```bash
brew install cmake openssl@3 qt
./build.sh -DCMAKE_PREFIX_PATH="$(brew --prefix qt);$(brew --prefix openssl@3)"
```

> Windows 下运行 Qt 版工具前，可用 Qt 自带的 `windeployqt.exe` 复制运行库：
> `windeployqt build\license_system.exe build\generator.exe build\keygen.exe build\dat_viewer.exe`

### 常用选项

```bash
# 只构建核心库与动态库，不构建 GUI
./build.sh -DBUILD_GUI=OFF

# 同时构建核心往返测试
./build.sh -DBUILD_GUI=OFF -DBUILD_TESTS=ON
./build/core_roundtrip

# 关闭 Windows DLL 自校验（一般不需要）
./build.sh -DENABLE_WINDOWS_SELF_HASH=OFF
```

产物位于 `build/`（Windows 多配置生成器位于 `build/Release/`）：

| 文件 | 说明 |
| --- | --- |
| `license.lib` / `liblicense.so` / `liblicense.dylib` | 授权核心库 |
| `license.dll`（Windows） | 带 `.text` 自校验的授权 DLL |
| `license_system` | 图形化激活工具 |
| `generator` | 激活码生成器，内置私钥，仅供作者使用 |
| `keygen` | ECDSA 密钥对生成器 |
| `dat_viewer` | `license-SkyBox.dat` 授权文件查看器 |

## 使用流程

1. 生成密钥对（首次或需要换密钥时）：
   运行 `keygen`，得到 `sky.bin`（私钥）与 `sky_share.bin`（公钥），放入 `key/` 后重新构建。
2. 集成到目标程序：
   加载授权动态库，调用 `License_Init` 初始化，用 `License_GetMachineCode` 取机器码，用 `License_ShowActivationDialog` 或自定义界面完成激活，用 `License_IsActivated` / `License_Verify` 判断授权状态。
3. 客户激活：
   客户运行 `license_system`，复制机器码发给作者。
4. 作者发码：
   在 `generator` 中填入机器码、用户名/邮箱和有效时长，生成激活码；客户粘贴后点击「验证并激活」。

## 主要接口

`include/license_dll.h` 导出：

- `License_Init` / `License_Shutdown`
- `License_IsActivated` / `License_Verify`
- `License_GetMachineCode` / `License_GetObfuscatedMachineCode` / `License_NormalizeMachineCode`
- `License_GetInfo`
- `License_ShowActivationDialog` / `License_Activate` / `License_Clear`
- `License_GenerateCode`（发码端生成激活码）
- `License_SetNtpBase`（外部已有时钟基准时可注入）

`include/license.h` 额外提供 `License_ReadFileInfo` 与 `License_DecryptFile`，供 DAT 查看器等工具复用解密逻辑。

## 跨平台说明

- 机器码由各平台硬件指纹生成，天然不同：Windows 使用卷序列号/CPU/MAC；Linux 使用 `/etc/machine-id`/CPU/MAC；macOS 使用 IOPlatformUUID/CPU/MAC。
- ECDSA 密钥文件使用 Windows CNG 的 P-256 BLOB 格式，三平台共用同一份 `key/sky.bin` 与 `key/sky_share.bin`，激活码可跨平台签发与验证。
- Windows 使用 BCrypt 实现 ECDSA；Linux/macOS 使用 OpenSSL 实现，签名格式统一为 64 字节 `r||s`。
- Windows 自校验与反调试在非 Windows 平台自动关闭；授权文件加密、备份恢复、时间锚与 NTP 校验保持启用。
- 授权文件路径与目录均按 UTF-8 处理：Windows 内部转换为宽字符访问，Linux/macOS 直接使用 UTF-8。

## 注意事项

- `key/sky.bin` 与 `generator` 属于发码侧，切勿随客户程序分发。
- 修改 Windows DLL 相关源码后必须重新完整构建，让 `hashgen` 重新写入哈希，否则自校验会失败。
- 更换密钥后需要重新构建客户端与发码工具，旧激活码将失效。
- 全项目源码不含注释，`embed_key` 与 `hashgen` 生成的头部文件同样不带注释。

## 许可证

MIT，见 [LICENSE](LICENSE)。

第三方组件与 LGPLv3 合规声明见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)，许可证全文位于 `LICENSES/`。
