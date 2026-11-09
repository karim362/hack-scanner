# Hack Scanner v25.2

> Portable path scanner for security research — **dirsearch + godirb + ffuf** with redirect leak detection.

![Hack Scanner](screenshot.svg)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20macOS-blue)]()
[![Shell](https://img.shields.io/badge/shell-bash-green)]()

## ✨ Features

- 🎯 **3 scanners** — dirsearch, godirb, ffuf (auto-installed)
- 🕵️ **Wildcard detection** — auto-filters fake responses
- 🔥 **Redirect Leak detection** — detects sensitive data in 301/302 bodies
- 🎨 **Cinematic UI** — color-coded severity
- 📱 **Portable** — Termux (ARM64), Linux, macOS (AMD64)
- ⚡ **Zero config** — first run installs everything
- 🚀 **One-command launch** — `kaha` from anywhere

## 🚀 Install

```bash
git clone https://github.com/karim362/hack-scanner.git hack
cd hack
./install.sh
source ~/.bashrc

## 🔧 Recent Fixes (v25.2)

- **Wildcard detection**: skips paths with same `(status + size)` × 3+
- **Catch-all redirects**: aggregates `3xx` responses (5+ small) into 1 line
- **Smart classification**:
  - `3xx` responses → always LOW (redirects, not real files)
  - `size < 20B` → LOW (empty API responses)
  - `size ≥ 1MB` → warning "truncated?"
- **Target validation**: filters invalid inputs like `.` or empty lines
- **ffuf install fix**: correct args order for Termux/Linux/macOS
