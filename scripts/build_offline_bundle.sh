#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$source_root/../dist}"
bundle_name="FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1"
mkdir -p "$output_dir"
stage_root="$(mktemp -d "$output_dir/.fm-agent-stage.XXXXXX")"
bundle_root="$stage_root/$bundle_name"

cleanup() {
    case "$stage_root" in
        "$output_dir"/.fm-agent-stage.*) rm -rf -- "$stage_root" ;;
    esac
}
trap cleanup EXIT

for required in \
    vendor/python/bin/python3 \
    vendor/deepseek-harness/dsh \
    vendor/deepseek-harness/dsh-rg \
    vendor/codegraph/bin/codegraph; do
    [[ -e "$source_root/$required" ]] || { echo "Missing $required" >&2; exit 1; }
done

mkdir -p "$bundle_root"
for directory in bin config docs licenses md plugins scripts src vendor; do
    cp -a "$source_root/$directory" "$bundle_root/"
done
for file in .env.example BUILD-INFO.md INSTALL_zh.md LICENSE README.md README_zh.md \
    VALIDATION-REPORT_zh.md \
    config.py dashboard.py report.py fm-agent.toml install.sh main.py pyproject.toml uv.lock; do
    cp -a "$source_root/$file" "$bundle_root/"
done

find "$bundle_root" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$bundle_root" -type f -name '*.pyc' -delete
chmod +x "$bundle_root/bin/fm-agent" "$bundle_root/install.sh" \
    "$bundle_root/scripts/verify_offline.sh" "$bundle_root/scripts/mock_openai_server.py" \
    "$bundle_root/scripts/test_model_connectivity.py" \
    "$bundle_root/scripts/run_harness_with_tool_proxy.py"

(cd "$bundle_root" && find . -type f ! -name MANIFEST.sha256 -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256)

archive="$output_dir/$bundle_name.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime='UTC 2026-09-15' -C "$stage_root" -cf - "$bundle_name" \
    | gzip -n -9 > "$archive"
(cd "$output_dir" && sha256sum "$bundle_name.tar.gz" > "$bundle_name.tar.gz.sha256")
echo "$archive"
