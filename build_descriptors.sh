#!/usr/bin/env bash
set -euo pipefail

# Root defaults to project root if running from anywhere inside repo
ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/fuzz}"
SHIM_DIR="$OUT_DIR/_shim"

mkdir -p "$OUT_DIR" "$SHIM_DIR/api" "$SHIM_DIR/rtapi"

if ! command -v protoc >/dev/null 2>&1; then
  echo "[!] Missing protoc. Cài đặt bằng: brew install protobuf" >&2
  exit 1
fi

# Prepare shim paths to satisfy imports in apigrpc.proto
ln -sf "$ROOT_DIR/api.proto" "$SHIM_DIR/api/api.proto"
ln -sf "$ROOT_DIR/realtime.proto" "$SHIM_DIR/rtapi/realtime.proto"

# Try to include apigrpc.proto when available; it imports api/api.proto and rtapi/realtime.proto
PROTO_ARGS=(
  -I"$SHIM_DIR"
  -I"$OUT_DIR/_third_party/googleapis"
  --include_imports
  --include_source_info
  --descriptor_set_out="$OUT_DIR/descriptor_set.pb"
)

INPUTS=("api/api.proto" "rtapi/realtime.proto")
if [[ -f "$ROOT_DIR/apigrpc.proto" ]]; then
  ln -sf "$ROOT_DIR/apigrpc.proto" "$SHIM_DIR/apigrpc.proto"
  # Just include apigrpc.proto if the dependency openapiv2 exists in vendor
  if [[ -f "$OUT_DIR/_third_party/googleapis/protoc-gen-openapiv2/options/annotations.proto" ]]; then
    INPUTS+=("apigrpc.proto")
  else
    echo "[i] Skipping apigrpc.proto (missing protoc-gen-openapiv2 in vendor)." >&2
  fi
fi

echo "[i] Building descriptor set from: ${INPUTS[*]}"
protoc "${PROTO_ARGS[@]}" "${INPUTS[@]}"

echo "[ok] Wrote: $OUT_DIR/descriptor_set.pb"


