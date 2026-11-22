#!/usr/bin/env python3
import argparse
import os
import platform
import subprocess
import sys

DEFAULT_QT_VERSION = "6.8.0"
DEFAULT_PYPI_INDEX = "https://pypi.tuna.tsinghua.edu.cn/simple"
DEFAULT_QT_BASE = ""


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
    parser.add_argument("--qt-base", default=DEFAULT_QT_BASE, help="Qt 下载镜像，默认使用官方源")
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
    ]
    if args.qt_base:
        cmd += ["-b", args.qt_base]
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
