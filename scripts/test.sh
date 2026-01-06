#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"

run_static() {
  echo "[static] python unittest"
  cd "$ROOT_DIR/static"
  uv run python -m unittest discover -s tests -q
}

run_dynamic_local() {
  echo "[dynamic-local] go test"
  cd "$ROOT_DIR/dynamic"
  go test ./...
}

run_dynamic_linux() {
  echo "[dynamic-linux] go test via orb"
  orb bash -lc "cd $ROOT_DIR/dynamic && go test ./..."
}

case "$MODE" in
  static)
    run_static
    ;;
  dynamic)
    run_dynamic_local
    ;;
  dynamic-linux)
    run_dynamic_linux
    ;;
  all)
    run_static
    run_dynamic_local
    run_dynamic_linux
    ;;
  *)
    echo "Usage: scripts/test.sh [static|dynamic|dynamic-linux|all]" >&2
    exit 2
    ;;
esac

echo "[ok] tests completed: $MODE"
