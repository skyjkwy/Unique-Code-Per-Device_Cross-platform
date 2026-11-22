#!/usr/bin/env python3
import argparse
import os
import platform
import subprocess
import sys

DEFAULT_QT_VERSION = "6.8.0"
DEFAULT_PYPI_INDEX = "https://pypi.tuna.tsinghua.edu.cn/simple"
# 默认使用阿里云镜像（国内访问稳定，不被重定向到海外 ftp.jaist.ac.jp）
# 国内备选：https://mirrors.tuna.tsinghua.edu.cn/qt  https://mirror.nju.edu.cn/qt
DEFAULT_QT_BASE = "https://mirrors.aliyun.com/qt"


def host_name():
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "mac"
    return "linux"


def default_arch():
    system = platform.system()
    if system == "Windows":
        return "win64_msvc2022_64"
    if system == "Darwin":
        return "clang_64"
    return "linux_gcc_64"


def default_out():
    if platform.system() == "Windows":
        return r"C:\Qt"
    return os.path.expanduser("~/Qt")


def install_dir(out, version, arch):
    if arch.startswith("win64"):
        folder = arch[len("win64_"):]
    elif arch.startswith("linux_"):
        folder = arch[len("linux_"):]
    elif arch == "clang_64":
        folder = "macos"
    else:
        folder = arch
    return os.path.join(out, version, folder)


def run(cmd):
    print(">> " + " ".join(cmd), flush=True)
    subprocess.check_call(cmd)


def aqt_available():
    try:
        import aqt  # noqa: F401
        return True
    except ImportError:
        return False


def main():
    parser = argparse.ArgumentParser(description="安装 Qt 6（基于 aqtinstall）")
    parser.add_argument("--version", default=DEFAULT_QT_VERSION, help="Qt 版本，默认 %s" % DEFAULT_QT_VERSION)
    parser.add_argument("--arch", default=default_arch(), help="Qt 架构，默认 %s" % default_arch())
    parser.add_argument("--out", default=default_out(), help="安装根目录，默认 %s" % default_out())
    parser.add_argument("--modules", default="", help="附加模块，逗号分隔，例如 qtcharts")
    parser.add_argument("--pypi-index", default=DEFAULT_PYPI_INDEX, help="pip 镜像")
    parser.add_argument("--qt-base", default=DEFAULT_QT_BASE,
                        help="Qt 下载镜像，默认 %s" % DEFAULT_QT_BASE)
    parser.add_argument("--official", action="store_true",
                        help="强制使用 Qt 官方源（可能被重定向到海外镜像）")
    parser.add_argument("--minimal", action="store_true", default=True,
                        help="仅下载 qtbase + qttools（满足 Widgets GUI 构建），默认开启")
    parser.add_argument("--all", dest="minimal", action="store_false",
                        help="下载 Qt 所有默认组件（体积大）")
    parser.add_argument("--timeout", type=int, default=120,
                        help="单请求超时秒数，默认 120")
    args = parser.parse_args()

    if sys.version_info < (3, 8):
        print("需要 Python 3.8 或更高版本")
        return 1

    if not aqt_available():
        run([sys.executable, "-m", "pip", "install", "--upgrade", "aqtinstall", "-i", args.pypi_index])

    cmd = [
        sys.executable, "-m", "aqt", "install-qt",
        host_name(), "desktop", args.version, args.arch,
        "-O", args.out,
        "--timeout", str(args.timeout),
    ]
    if args.qt_base and not args.official:
        cmd += ["-b", args.qt_base]
    if args.minimal:
        # qtbase = Core + Gui + Widgets，qttools = windeployqt / moc / uic
        cmd += ["--archives", "qtbase", "qttools"]
    if args.modules:
        cmd += ["-m"] + [m.strip() for m in args.modules.split(",") if m.strip()]

    run(cmd)

    prefix = install_dir(args.out, args.version, args.arch)
    config = os.path.join(prefix, "lib", "cmake", "Qt6", "Qt6Config.cmake")
    if not os.path.isfile(config):
        print("安装完成，但未找到 %s" % config)
        return 1

    print("")
    print("Qt 已安装到: %s" % prefix)
    print("构建 GUI 时传入:")
    if platform.system() == "Windows":
        print('  build.bat -DCMAKE_PREFIX_PATH="%s"' % prefix)
    else:
        print('  ./build.sh -DCMAKE_PREFIX_PATH="%s"' % prefix)
    return 0


if __name__ == "__main__":
    sys.exit(main())
