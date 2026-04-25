#!/bin/bash
# SessionStart hook for Claude Code on the web.
# Ensures the pinned Rust toolchain is installed and the cargo dep cache is
# warm before the agent loop starts. Skipped in local sessions, where the
# contributor manages their own toolchain.

set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --no-modify-path
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

# rust-toolchain.toml pins channel + components; `rustup show` installs them.
rustup show active-toolchain >/dev/null 2>&1 || rustup show >/dev/null

# Warm the dependency cache so the first cargo build/test/clippy is fast.
# Best-effort: a flaky registry shouldn't fail the session start, since cargo
# will lazily fetch on demand.
cargo fetch --locked || echo "warning: cargo fetch failed; deps will be fetched on first build" >&2

echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
