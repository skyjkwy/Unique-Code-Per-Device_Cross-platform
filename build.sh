#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="${ROOT}/build"

cmake -S "${ROOT}" -B "${BUILD}" -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build "${BUILD}" --parallel "$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
