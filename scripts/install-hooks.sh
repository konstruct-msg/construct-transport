#!/usr/bin/env bash
# Point git at the tracked hooks in .githooks/. Run once per clone.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "Installed: core.hooksPath = .githooks"
