#!/usr/bin/env bash
# Regenerate the committed FAT32 fixtures. The gzip images are authoritative.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${PYTHON:-python3}" "$here/make_fat32_fixtures.py" "$@"
