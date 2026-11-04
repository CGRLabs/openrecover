#!/usr/bin/env bash
# Regenerate the committed NTFS fixtures. The gzip images are authoritative.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${PYTHON:-python3}" "$here/make_ntfs_fixtures.py" "$@"
