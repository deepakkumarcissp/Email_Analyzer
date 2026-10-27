#!/usr/bin/env bash
# DKCISSP Email Analyzer — single-command installer (Linux / macOS)
#
# Run this one line in a terminal and it does everything: downloads the
# project, sets up a private virtual environment, installs dependencies,
# starts the local web UI, and opens it in your browser.
#
#   curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Email_Analyzer/main/install.sh | bash
#
# Nothing you paste into the tool ever leaves your machine.
set -euo pipefail

REPO_URL="https://github.com/deepakkumarcissp/Email_Analyzer"
INSTALL_DIR="${DKCISSP_INSTALL_DIR:-$HOME/dkcissp-email-analyzer}"

echo "DKCISSP Email Analyzer — installer"
echo "Installing to: $INSTALL_DIR"
echo ""

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Existing install found — updating..."
  git -C "$INSTALL_DIR" pull --ff-only
elif command -v git >/dev/null 2>&1; then
  echo "Downloading (git clone)..."
  git clone --depth 1 "$REPO_URL.git" "$INSTALL_DIR"
else
  echo "git not found — downloading a zip archive instead..."
  if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    echo "Error: need either 'git', or both 'curl' and 'unzip', to install." >&2
    exit 1
  fi
  TMP_DIR=$(mktemp -d)
  curl -fsSL "$REPO_URL/archive/refs/heads/main.zip" -o "$TMP_DIR/repo.zip"
  unzip -q "$TMP_DIR/repo.zip" -d "$TMP_DIR"
  rm -rf "$INSTALL_DIR"
  mv "$TMP_DIR"/Email_Analyzer-main "$INSTALL_DIR"
  rm -rf "$TMP_DIR"
fi

cd "$INSTALL_DIR"
chmod +x run.sh run.command 2>/dev/null || true

echo ""
echo "Starting the app..."
echo ""
exec ./run.sh
