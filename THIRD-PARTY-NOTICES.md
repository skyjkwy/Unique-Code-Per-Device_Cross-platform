# 第三方组件与许可证声明

本文件说明本项目（下称“本项目”）对第三方组件——特别是 Qt 6——的使用方式与许可证义务。发布本项目的二进制程序（`license_system`、`generator`、`keygen`、`dat_viewer`）时，应随附本文件与 `LICENSES/` 目录下的许可证全文。

> 本文件是合规声明模板，不构成法律意见。发布前请按第 8 节检查清单核对并替换全部占位符。

---

## 1. 本项目自身代码

本项目自身源代码采用 MIT 许可证，全文见 [LICENSE](LICENSE)。

```
MIT License

Copyright (c) 2026 skywyjk
```

MIT 许可证仅覆盖本项目原创代码，不改变任何第三方组件原有的许可证。

## 2. 使用的 Qt 组件

| 组件 | 用途 | 许可证 |
| --- | --- | --- |
| Qt Core | 基础运行时、容器、文件与字符串处理 | LGPLv3（或商业许可） |
| Qt Gui | 窗口系统集成、字体、图像、事件 | LGPLv3（或商业许可） |
| Qt Widgets | 全部图形界面 | LGPLv3（或商业许可） |

- 使用的 Qt 版本：`6.8.0`
- 构建方式：`Windows: MSVC 2022；Linux: GCC；macOS: Apple Clang`，**动态链接** Qt 共享库
- 是否修改 Qt 源码：**否**（使用官方预编译二进制或未修改的官方源码构建）

本项目**未使用**任何仅以 GPL 提供的 Qt 模块（如 Qt Charts、Qt Data Visualization、Qt Virtual Keyboard 等），也未使用 Qt WebEngine、Qt Quick 3D 等带有额外限制的模块。

Qt 版权声明：

```
Qt Toolkit
Copyright (C) The Qt Company Ltd. and other contributors.
Licensed under the GNU Lesser General Public License, version 3.
```

## 3. 许可证全文

随附的许可证全文（来自 https://www.gnu.org/licenses/ ）：

- [LICENSES/LGPL-3.0](LICENSES/LGPL-3.0) —— GNU Lesser General Public License v3.0
- [LICENSES/GPL-3.0](LICENSES/GPL-3.0) —— GNU General Public License v3.0（LGPLv3 通过引用并入 GPLv3 条款，因此必须一并提供）

## 4. 动态链接与用户可替换性

本项目以动态链接方式使用 Qt（Windows 为 `Qt6Core.dll` / `Qt6Gui.dll` / `Qt6Widgets.dll`，Linux 为 `libQt6Core.so.6` 等，macOS 为 `QtCore.framework` / `QtGui.framework` / `QtWidgets.framework`）。这满足 LGPLv3 第 4 条对“使用合适共享库机制”的要求：

1. **用户可替换 Qt 库**：用户可以用自行编译或从 Qt 官方获取的同版本（或二进制兼容版本）Qt 共享库替换随程序分发的 Qt 库，程序无需重新链接即可运行。
2. **不静态链接 Qt**：本项目不对 Qt 做静态链接，也不使用 `-static`、`/MT` 等方式把 Qt 固化进可执行文件。
3. **不阻止替换**：不对 Qt 共享库做签名锁定、加载路径硬编码或完整性校验，不阻止用户替换这些库。
4. **不修改 Qt**：如后续修改 Qt 源码，必须在分发包中附带修改后的 Qt 源码及修改说明。

### 4.1 各平台库文件位置

| 平台 | Qt 共享库位置 | 替换方式 |
| --- | --- | --- |
| Windows | 可执行文件同目录或 `platforms/`、`styles/` 等子目录 | 直接用同名 DLL 覆盖 |
| Linux | 可执行文件同目录、`lib/` 或系统库路径 | 替换同名 `.so`，或用 `LD_LIBRARY_PATH` 指向替换库 |
| macOS | `.app/Contents/Frameworks/` 内的 framework | 替换 framework 内的动态库，或使用 `DYLD_LIBRARY_PATH` |

发布时的部署命令示例：

```bat
:: Windows
windeployqt --release build\license_system.exe build\generator.exe build\keygen.exe build\dat_viewer.exe
```

```bash
# macOS
macdeployqt build/license_system.app -always-overwrite
```

```bash
# Linux：随包分发 Qt 共享库时，保留 .so 文件的独立可替换性
ldd build/license_system | grep Qt
```

> Linux 打包注意：不建议把 Qt 库静态编译进可执行文件；使用 AppImage / Flatpak 时，应保证包内 Qt 库可被用户替换，或同时在包外提供对应 Qt 源码。

## 5. 获取 Qt 源代码

LGPLv3 要求使用者能够获取对应版本的 Qt 源代码。可通过以下官方渠道获取：

- 官方发布源码包：<https://download.qt.io/official_releases/qt/>
- Qt 代码仓库：<https://code.qt.io/cgit/qt/>
- 具体版本：<https://download.qt.io/official_releases/qt/6.8/6.8.0/submodules/>

若以“书面要约”方式履行义务，可在文档或安装包中附上如下声明（LGPLv3 通过 GPLv3 第 6(b) 条允许此方式，要约有效期至少三年）：

```
Written Offer for Source Code

For the Qt libraries distributed with this product, the distributor
skyjkwy hereby offers, valid for at least three years from the date
of distribution, to give any third party, for a charge no more than the
cost of physically performing source distribution, a complete
machine-readable copy of the corresponding source code for the Qt
version(s) distributed with this product.

Contact: 312146554+skyjkwy@users.noreply.github.com
```

建议同时直接托管一份对应 Qt 源码压缩包，避免仅依赖书面要约。

## 6. 安装信息（Installation Information）

LGPLv3 第 4 条第 4 项与 GPLv3 第 6 条要求：若程序属于“User Product”（消费类设备等），且使用了修改过的 LGPL 库，则必须提供“安装信息”，使用户能够安装修改后的库版本。

本项目情况：

- Qt 库**未被修改**，因此通常不触发该条的安装信息义务；
- 若本程序被预装到锁定的硬件设备（如一体机、嵌入式设备、带安全启动且禁止替换系统库的设备），请在此处补充安装信息说明：`无`；
- 若目标平台禁止替换动态库（例如部分应用商店、游戏主机、iOS），LGPLv3 义务无法满足，此时应改用 Qt 商业许可证。

## 7. Qt 内置第三方组件

Qt 官方二进制包内还包含若干第三方组件（如 PCRE2、zlib、FreeType、libpng、HarfBuzz、SQLite 等），其许可证以 Qt 安装目录下的 `LICENSES/` 目录为准：

- Qt 6 安装目录（6.8.0）：
  - Windows：`C:\Qt\6.8.0\msvc2022_64\LICENSES\`
  - Linux：`/opt/Qt/6.8.0/gcc_64/LICENSES/`
  - macOS：`~/Qt/6.8.0/macos/LICENSES/`
- 发布时应将该目录中实际随程序分发的组件许可证一并提供。

本项目的其余依赖：

| 依赖 | 平台 | 许可证 |
| --- | --- | --- |
| OpenSSL | Linux / macOS（ECDSA 实现） | Apache License 2.0 |
| Windows CNG / BCrypt | Windows（ECDSA、随机数） | 操作系统组件，随系统提供 |

## 8. 发布前检查清单

- [ ] 分发包含本文件 `THIRD-PARTY-NOTICES.md`
- [ ] 分发包含 `LICENSES/LGPL-3.0` 与 `LICENSES/GPL-3.0`
- [ ] 分发包含 Qt 安装目录 `LICENSES/` 中实际使用组件的许可证
- [x] 确认版本号（Qt 6.8.0）、发布者（skyjkwy）与联系方式与实际分发一致
- [ ] 确认 Qt 为动态链接，未使用 `/MT`、`-static` 等方式静态链接
- [ ] 确认未修改 Qt 源码；若修改，附上修改后的源码与说明
- [ ] 确认未链接 GPL-only 模块（Qt Charts、Qt Data Visualization、Qt Virtual Keyboard 等）
- [ ] 确认未对 Qt 共享库设置阻止替换的签名/校验/路径锁定
- [ ] 在“关于”对话框或帮助菜单中展示 Qt 版权与 LGPLv3 声明
- [ ] 提供可访问的 Qt 源代码获取方式（下载链接或书面要约）

---

# English Notice

This product uses the Qt Toolkit under the terms of the GNU Lesser General Public License, version 3 (LGPLv3).

```
This product uses Qt 6.8.0, Copyright (C) The Qt Company Ltd. and other
contributors. Qt is licensed under the GNU Lesser General Public License,
version 3. The Qt libraries are dynamically linked and are not modified.

A copy of the LGPLv3 is provided in LICENSES/LGPL-3.0, and the
incorporated GPLv3 terms in LICENSES/GPL-3.0.

You may replace the Qt shared libraries distributed with this product with
binary-compatible versions of your own build. On Windows, replace the
Qt6*.dll files in the application directory. On Linux, replace the
corresponding libQt6*.so.6 files. On macOS, replace the frameworks under
the application bundle's Contents/Frameworks/ directory
(for example, license_system.app/Contents/Frameworks/).

Qt source code is available from:
  https://download.qt.io/official_releases/qt/
  https://code.qt.io/cgit/qt/

The original source code of this project is licensed under the MIT License;
see LICENSE.
```

---

## 免责声明

本文件仅为便于履行开源许可证信息提供义务而编写，不构成法律意见。若用于商业发行、硬件预装或受限制的应用商店渠道，建议由法律顾问复核。
