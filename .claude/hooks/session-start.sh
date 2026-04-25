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

# Install cargo-deny so the agent can reproduce the CI deny job locally.
# Prebuilt musl binary; best-effort, mirroring the cargo-fetch pattern above.
if ! command -v cargo-deny >/dev/null 2>&1; then
  CARGO_DENY_VERSION="0.19.4"
  CARGO_DENY_DIR="cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl"
  CARGO_DENY_URL="https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/${CARGO_DENY_DIR}.tar.gz"
  CARGO_DENY_TMP="$(mktemp -d)"
  if curl --proto '=https' --tlsv1.2 -sSfL "$CARGO_DENY_URL" \
       | tar -xzf - -C "$CARGO_DENY_TMP" \
     && [ -x "${CARGO_DENY_TMP}/${CARGO_DENY_DIR}/cargo-deny" ]; then
    install -m 0755 "${CARGO_DENY_TMP}/${CARGO_DENY_DIR}/cargo-deny" "$HOME/.cargo/bin/cargo-deny"
  else
    echo "warning: failed to install cargo-deny ${CARGO_DENY_VERSION}; \`cargo deny check\` will be unavailable" >&2
  fi
  rm -rf "$CARGO_DENY_TMP"
fi

echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
