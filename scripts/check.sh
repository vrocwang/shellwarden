#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"

echo "== rustfmt"
cargo fmt --all -- --check

echo "== schemas"
for file in schemas/*.json; do
  python3 -m json.tool "$file" >/dev/null
done

echo "== clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests"
cargo test --workspace

echo "== frontend build"
npm run build

echo
echo "acceptance: OK"
