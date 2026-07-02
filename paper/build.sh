#!/usr/bin/env bash
# Build paper/main.tex -> main.pdf.
#
# Engine preference (no root required):
#   1. tectonic     -- self-contained static binary; auto-fetches TeX packages
#                      on demand. This is the primary path on hosts without a
#                      TeX install and without docker-group membership. If not on
#                      PATH, this script downloads a pinned static build into
#                      ./.tectonic/ (needs network the first time only).
#   2. pdflatex/latexmk -- used if a local TeX Live install is present.
#   3. docker texlive   -- used if the docker socket is usable.
# tectonic resolves cross-references internally; the pdflatex path runs 2 passes.
#
# Usage:  ./build.sh              # build main.pdf
#         ./build.sh clean        # remove build artifacts (keeps ./.tectonic)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOB="main"
TEX="${JOB}.tex"
DOCKER_IMG="texlive/texlive:latest"
TECTONIC_VER="0.15.0"
TECTONIC_URL="https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40${TECTONIC_VER}/tectonic-${TECTONIC_VER}-x86_64-unknown-linux-musl.tar.gz"

cd "$HERE"

if [[ "${1:-}" == "clean" ]]; then
  rm -f "${JOB}".{aux,log,out,pdf,bbl,blg,toc,fls,fdb_latexmk} "${JOB}.xdv"
  echo "cleaned build artifacts (kept ./.tectonic)"
  exit 0
fi

[[ -f "$TEX" ]] || { echo "error: $TEX not found in $HERE" >&2; exit 1; }

# --- locate or fetch tectonic --------------------------------------------------
find_tectonic() {
  if command -v tectonic >/dev/null 2>&1; then echo "tectonic"; return 0; fi
  if [[ -x "${HERE}/.tectonic/tectonic" ]]; then echo "${HERE}/.tectonic/tectonic"; return 0; fi
  return 1
}

fetch_tectonic() {
  echo "[build] fetching tectonic ${TECTONIC_VER} (one-time) ..." >&2
  mkdir -p "${HERE}/.tectonic"
  local tgz="${HERE}/.tectonic/tectonic.tar.gz"
  # curl honors ambient http(s)_proxy; GitHub release assets are reachable that way.
  if ! curl -sSL -o "$tgz" "$TECTONIC_URL"; then
    echo "[build] tectonic download failed" >&2; return 1
  fi
  tar xzf "$tgz" -C "${HERE}/.tectonic" && [[ -x "${HERE}/.tectonic/tectonic" ]]
}

run_pdflatex_passes() {
  local cmd="$1"
  $cmd || true    # pass 1
  $cmd            # pass 2 resolves \ref/\label
}
PDFLATEX_ARGS="-interaction=nonstopmode -halt-on-error ${TEX}"

# --- pick an engine ------------------------------------------------------------
if TECT="$(find_tectonic)"; then
  echo "[build] using ${TECT}"
  "$TECT" "${TEX}"
elif command -v pdflatex >/dev/null 2>&1; then
  echo "[build] using local pdflatex"
  run_pdflatex_passes "pdflatex ${PDFLATEX_ARGS}"
elif command -v latexmk >/dev/null 2>&1; then
  echo "[build] using local latexmk"
  latexmk -pdf -interaction=nonstopmode "${TEX}"
elif docker ps >/dev/null 2>&1; then
  echo "[build] using Docker image ${DOCKER_IMG}"
  docker image inspect "${DOCKER_IMG}" >/dev/null 2>&1 || docker pull "${DOCKER_IMG}"
  run_pdflatex_passes "docker run --rm -v ${HERE}:/work -w /work -u $(id -u):$(id -g) ${DOCKER_IMG} pdflatex ${PDFLATEX_ARGS}"
elif fetch_tectonic; then
  echo "[build] using freshly fetched ${HERE}/.tectonic/tectonic"
  "${HERE}/.tectonic/tectonic" "${TEX}"
else
  echo "error: no usable LaTeX engine (tectonic/pdflatex/latexmk/docker) and tectonic download failed" >&2
  exit 1
fi

if [[ -f "${JOB}.pdf" ]]; then
  echo "[build] OK -> ${HERE}/${JOB}.pdf"
else
  echo "[build] FAILED: ${JOB}.pdf not produced (see ${JOB}.log)" >&2
  exit 1
fi
