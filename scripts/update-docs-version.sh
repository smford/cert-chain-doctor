#!/usr/bin/env bash
set -euo pipefail

# Injects the latest release version into documentation files
VERSION="${1:-}"

if [ -z "$VERSION" ]; then
  # Fallback: check git tag or default
  VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.1.0")
fi

CLEAN_VERSION="${VERSION#v}"
echo "Updating documentation to version: ${VERSION} (${CLEAN_VERSION})"

DOCS_DIR="${2:-docs}"

# Update version badges, download links, and install snippets in markdown docs
find "$DOCS_DIR" -maxdepth 2 -name "*.md" -type f | while read -r doc_file; do
  # Replace github release download version references
  sed -i.bak -E "s|releases/download/v[0-9]+\.[0-9]+\.[0-9]+|releases/download/v${CLEAN_VERSION}|g" "$doc_file" 2>/dev/null || true
  # Replace version badge references
  sed -i.bak -E "s|badge/version-v[0-9]+\.[0-9]+\.[0-9]+|badge/version-v${CLEAN_VERSION}|g" "$doc_file" 2>/dev/null || true
  rm -f "${doc_file}.bak"
done

echo "Documentation version update complete."
