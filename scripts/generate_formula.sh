#!/usr/bin/env bash
set -euo pipefail

# Generates a Homebrew Formula for cert-chain-doctor from GoReleaser checksums
VERSION="${1:-}"
DIST_DIR="${2:-dist}"
OUTPUT_FILE="${3:-Formula/cert-chain-doctor.rb}"

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version> [dist_dir] [output_file]" >&2
  exit 1
fi

# Strip leading v if present
CLEAN_VERSION="${VERSION#v}"
CHECKSUMS_FILE="${DIST_DIR}/checksums.txt"

if [ ! -f "$CHECKSUMS_FILE" ]; then
  echo "Error: Checksums file not found at $CHECKSUMS_FILE" >&2
  exit 1
fi

get_sha256() {
  local pattern="$1"
  local sha
  sha=$(grep -E "${pattern}" "$CHECKSUMS_FILE" | awk '{print $1}' | head -n 1 || true)
  if [ -z "$sha" ]; then
    echo "0000000000000000000000000000000000000000000000000000000000000000"
  else
    echo "$sha"
  fi
}

SHA_DARWIN_AMD64=$(get_sha256 "cert-chain-doctor_.*_darwin_amd64\.tar\.gz")
SHA_DARWIN_ARM64=$(get_sha256 "cert-chain-doctor_.*_darwin_arm64\.tar\.gz")
SHA_LINUX_AMD64=$(get_sha256 "cert-chain-doctor_.*_linux_amd64\.tar\.gz")
SHA_LINUX_ARM64=$(get_sha256 "cert-chain-doctor_.*_linux_arm64\.tar\.gz")

mkdir -p "$(dirname "$OUTPUT_FILE")"

cat > "$OUTPUT_FILE" <<EOF
# typed: false
# frozen_string_literal: true

# This formula was auto-generated for cert-chain-doctor (https://github.com/smford/cert-chain-doctor).
class CertChainDoctor < Formula
  desc "Visual TLS handshake & intermediate certificate chain debugger and AIA auto-repairer"
  homepage "https://github.com/smford/cert-chain-doctor"
  version "${CLEAN_VERSION}"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/smford/cert-chain-doctor/releases/download/v#{version}/cert-chain-doctor_#{version}_darwin_arm64.tar.gz"
      sha256 "${SHA_DARWIN_ARM64}"
    end
    on_intel do
      url "https://github.com/smford/cert-chain-doctor/releases/download/v#{version}/cert-chain-doctor_#{version}_darwin_amd64.tar.gz"
      sha256 "${SHA_DARWIN_AMD64}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/smford/cert-chain-doctor/releases/download/v#{version}/cert-chain-doctor_#{version}_linux_arm64.tar.gz"
      sha256 "${SHA_LINUX_ARM64}"
    end
    on_intel do
      url "https://github.com/smford/cert-chain-doctor/releases/download/v#{version}/cert-chain-doctor_#{version}_linux_amd64.tar.gz"
      sha256 "${SHA_LINUX_AMD64}"
    end
  end

  def install
    bin.install "cert-chain-doctor"
  end

  test do
    system "#{bin}/cert-chain-doctor", "--version"
  end
end
EOF

echo "Successfully generated $OUTPUT_FILE for version ${CLEAN_VERSION}"
