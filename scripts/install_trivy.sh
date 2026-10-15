#!/usr/bin/env bash
# ติดตั้ง Trivy แบบล็อกเวอร์ชัน และตรวจ SHA-256 กับค่าที่เขียนไว้ในไฟล์นี้ก่อนใช้
# ถ้าไฟล์ที่โหลดมาถูกแก้ (supply chain attack) checksum จะไม่ตรง และหยุดทันที
set -euo pipefail

VERSION="0.74.0"
SHA256="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
FILE="trivy_${VERSION}_Linux-64bit.tar.gz"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sSfL -o "$TMP/$FILE" "https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/${FILE}"
echo "${SHA256}  $TMP/$FILE" | sha256sum -c -
tar -xzf "$TMP/$FILE" -C "$TMP" trivy
install -m 755 "$TMP/trivy" "$INSTALL_DIR/trivy"
trivy --version