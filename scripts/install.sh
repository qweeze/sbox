#!/bin/sh

set -eu

REPO="${REPO:-qweeze/sbox}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

fail() {
	echo "sbox install: $*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

github_api() {
	url="$1"
	if [ -n "${GITHUB_TOKEN:-}" ]; then
		curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" "$url"
	else
		curl -fsSL "$url"
	fi
}

latest_version() {
	github_api "https://api.github.com/repos/${REPO}/releases/latest" |
		sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
		head -n 1
}

uname_s=$(uname -s)
uname_m=$(uname -m)

case "$uname_s" in
Darwin)
	os="Darwin"
	;;
*)
	fail "unsupported OS: ${uname_s} (macOS only)"
	;;
esac

case "$uname_m" in
x86_64)
	arch="amd64"
	;;
arm64|aarch64)
	arch="arm64"
	;;
*)
	fail "unsupported architecture: ${uname_m}"
	;;
esac

need_cmd curl
need_cmd tar
need_cmd shasum

if [ "$VERSION" = "latest" ]; then
	VERSION="$(latest_version)"
	[ -n "$VERSION" ] || fail "could not determine latest release version"
fi

archive="sbox_${VERSION}_${os}_${arch}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"
archive_url="${base_url}/${archive}"
checksums_url="${base_url}/checksums.txt"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM

echo "Installing sbox ${VERSION} for ${os}/${arch}..."

curl -fsSL "$archive_url" -o "${tmpdir}/${archive}"
curl -fsSL "$checksums_url" -o "${tmpdir}/checksums.txt"

expected_checksum=$(grep "  ${archive}\$" "${tmpdir}/checksums.txt" | awk '{print $1}')
[ -n "${expected_checksum:-}" ] || fail "missing checksum for ${archive}"

actual_checksum=$(shasum -a 256 "${tmpdir}/${archive}" | awk '{print $1}')
[ "$expected_checksum" = "$actual_checksum" ] || fail "checksum mismatch for ${archive}"

tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
[ -f "${tmpdir}/sbox" ] || fail "archive did not contain sbox binary"

if [ -w "$INSTALL_DIR" ]; then
	mkdir -p "$INSTALL_DIR"
	install -m 0755 "${tmpdir}/sbox" "${INSTALL_DIR}/sbox"
else
	need_cmd sudo
	sudo mkdir -p "$INSTALL_DIR"
	sudo install -m 0755 "${tmpdir}/sbox" "${INSTALL_DIR}/sbox"
fi

echo "Installed to ${INSTALL_DIR}/sbox"

