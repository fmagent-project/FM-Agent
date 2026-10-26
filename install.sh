#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_root="${XDG_DATA_HOME:-${HOME:?HOME is not set}/.local/share}/fm-agent-dsh"
bin_dir="${HOME}/.local/bin"
version="0.3.0-dsh.1"

usage() {
    echo "Usage: ./install.sh [--prefix DIR] [--bin-dir DIR]"
    echo "Installs only bundled files; this script never accesses the network."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; install_root="$2"; shift 2 ;;
        --bin-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; bin_dir="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || {
    echo "This bundle supports Linux x86_64 only." >&2; exit 1; }
"$source_root/scripts/verify_offline.sh" --quick

install_root="$(readlink -m "$install_root")"
bin_dir="$(readlink -m "$bin_dir")"
destination="$install_root/versions/$version"
staging="$install_root/versions/.installing-$version-$$"
mkdir -p "$staging" "$bin_dir"
cp -a "$source_root/." "$staging/"

if [[ -e "$destination" || -L "$destination" ]]; then
    backup="$destination.backup.$(date +%Y%m%d%H%M%S).$$"
    mv "$destination" "$backup"
    echo "Existing version preserved at $backup"
fi
mv "$staging" "$destination"
ln -sfn "$destination" "$install_root/current"

launcher="$bin_dir/fm-agent"
if [[ -e "$launcher" && ! -L "$launcher" ]]; then
    echo "Refusing to replace non-symlink: $launcher" >&2
    exit 1
fi
ln -sfn "$install_root/current/bin/fm-agent" "$launcher"

echo "Installed FM-Agent to $destination"
echo "Launcher: $launcher"
echo "Next: $launcher configure"
