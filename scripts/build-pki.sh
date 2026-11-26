#!/usr/bin/env bash
set -euo pipefail

PKI_DIR="${1:-pki}"
TS_DIR="${PKI_DIR}/timestamps"
TAG_NAME="${RELEASE_TAG:-}"

mkdir -p "${TS_DIR}"

# 4 个免费 RFC 3161 TSA 服务（名称|URL|是否需要cert参数|额外curl参数）
TSAS=(
  "digicert|http://timestamp.digicert.com|yes|"
  "sectigo|http://timestamp.sectigo.com|yes|"
  "freetsa|https://freetsa.org/tsr|yes|"
  "globalsign|http://timestamp.globalsign.com/tsa/r6advanced1|yes|"
)

warn() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::warning::$1" >&2
  else
    echo "WARNING: $1" >&2
  fi
}

request_tsa() {
  local target_file="$1"
  local base_name="$2"
  local tsa_name="$3"
  local tsa_url="$4"

  local tsq_file="${TS_DIR}/${base_name}.${tsa_name}.tsq"
  local tsr_file="${TS_DIR}/${base_name}.${tsa_name}.tsr"
  local tmp_tsr="${tsr_file}.tmp"

  # 生成 RFC 3161 SHA-256 时间戳请求
  if ! openssl ts -query -data "${target_file}" -sha256 -cert -out "${tsq_file}" 2>/dev/null; then
    warn "Failed to create TSQ for ${base_name} (${tsa_name})"
    rm -f "${tsq_file}"
    return 1
  fi

  # 发送请求到 TSA（超时 20s，最多重试 2 次）
  local http_code
  http_code=$(curl -sS -m 20 --retry 2 --retry-delay 2 \
    -H "Content-Type: application/timestamp-query" \
    --data-binary "@${tsq_file}" \
    -o "${tmp_tsr}" \
    -w "%{http_code}" \
    "${tsa_url}" 2>/dev/null || echo "000")

  if [[ "${http_code}" != "200" ]] || [[ ! -s "${tmp_tsr}" ]]; then
    warn "TSA ${tsa_name} returned HTTP ${http_code} for ${base_name} (${tsa_url})"
    rm -f "${tmp_tsr}"
    return 1
  fi

  # 验证响应是否为合法的 RFC 3161 TimeStampResp
  if ! openssl ts -reply -in "${tmp_tsr}" -text >/dev/null 2>&1; then
    warn "TSA ${tsa_name} returned invalid TSR payload for ${base_name}"
    rm -f "${tmp_tsr}"
    return 1
  fi

  mv "${tmp_tsr}" "${tsr_file}"
  return 0
}

# 收集待处理的证书与 CRL 文件
shopt -s nullglob
PKI_FILES=()
for f in "${PKI_DIR}"/*.cer "${PKI_DIR}"/*.crt "${PKI_DIR}"/*.pem "${PKI_DIR}"/*.crl; do
  [[ -f "$f" ]] && PKI_FILES+=("$f")
done
shopt -u nullglob

if [[ ${#PKI_FILES[@]} -eq 0 ]]; then
  warn "No certificate or CRL files found in ${PKI_DIR}"
fi

# 清理旧的无效临时文件
rm -f "${TS_DIR}"/*.tmp

# 生成 SHA256SUMS.txt（仅包含根目录下的证书和 CRL）
SUMS_FILE="${PKI_DIR}/SHA256SUMS.txt"
: > "${SUMS_FILE}"
if [[ ${#PKI_FILES[@]} -gt 0 ]]; then
  (
    cd "${PKI_DIR}"
    for f in *.cer *.crt *.pem *.crl; do
      [[ -f "$f" ]] || continue
      sha256sum "$f" >> "SHA256SUMS.txt"
    done
  )
fi

# 对每个证书/CRL 以及 SHA256SUMS.txt 申请多个免费可信时间戳
ALL_TARGETS=("${PKI_FILES[@]}")
if [[ -s "${SUMS_FILE}" ]]; then
  ALL_TARGETS+=("${SUMS_FILE}")
fi

for target in "${ALL_TARGETS[@]}"; do
  base_name="$(basename "${target}")"
  for entry in "${TSAS[@]}"; do
    IFS='|' read -r tsa_name tsa_url _ <<< "${entry}"
    request_tsa "${target}" "${base_name}" "${tsa_name}" "${tsa_url}" || true
  done
done

# 生成 pki/manifest.json（使用 python3 保证 JSON 格式严格正确）
python3 - "${PKI_DIR}" "${TS_DIR}" "${TAG_NAME}" <<'PYEOF'
import json
import os
import sys
from datetime import datetime, timezone, timedelta

pki_dir = sys.argv[1]
ts_dir = sys.argv[2]
tag_name = sys.argv[3] if len(sys.argv) > 3 else ""

tz_bj = timezone(timedelta(hours=8))
now_bj = datetime.now(tz_bj).strftime("%Y-%m-%d %H:%M:%S +08:00")

tsa_labels = {
    "digicert": "DigiCert",
    "sectigo": "Sectigo",
    "freetsa": "FreeTSA",
    "globalsign": "GlobalSign",
}

def collect_timestamps(filename):
    items = []
    for key, label in tsa_labels.items():
        tsr_name = f"{filename}.{key}.tsr"
        tsq_name = f"{filename}.{key}.tsq"
        tsr_path = os.path.join(ts_dir, tsr_name)
        tsq_path = os.path.join(ts_dir, tsq_name)
        if os.path.isfile(tsr_path):
            entry = {
                "tsa": key,
                "label": label,
                "tsrUrl": f"./pki/timestamps/{tsr_name}",
                "tsrSize": os.path.getsize(tsr_path),
            }
            if os.path.isfile(tsq_path):
                entry["tsqUrl"] = f"./pki/timestamps/{tsq_name}"
                entry["tsqSize"] = os.path.getsize(tsq_path)
            items.append(entry)
    return items

files = []
for name in sorted(os.listdir(pki_dir)):
    full = os.path.join(pki_dir, name)
    if not os.path.isfile(full):
        continue
    ext = os.path.splitext(name)[1].lower()
    if ext not in (".cer", ".crt", ".pem", ".crl"):
        continue
    ftype = "crl" if ext == ".crl" else "cert"
    files.append({
        "name": name,
        "type": ftype,
        "url": f"./pki/{name}",
        "size": os.path.getsize(full),
        "timestamps": collect_timestamps(name),
    })

sums_path = os.path.join(pki_dir, "SHA256SUMS.txt")
checksums = None
if os.path.isfile(sums_path):
    checksums = {
        "name": "SHA256SUMS.txt",
        "url": "./pki/SHA256SUMS.txt",
        "size": os.path.getsize(sums_path),
        "timestamps": collect_timestamps("SHA256SUMS.txt"),
    }

manifest = {
    "updatedAt": now_bj,
    "releaseTag": tag_name or None,
    "files": files,
    "checksums": checksums,
}

with open(os.path.join(pki_dir, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)
    f.write("\n")
PYEOF

echo "Generated ${PKI_DIR}/manifest.json and timestamps in ${TS_DIR}"
