#!/usr/bin/env bash
set -euo pipefail

PKI_DIR="${1:-pki}"
TS_DIR="${PKI_DIR}/timestamps"
TAG_NAME="${RELEASE_TAG:-}"

mkdir -p "${TS_DIR}"

# 4 个免费 RFC 3161 TSA 服务（名称|URL）
TSAS=(
  "digicert|http://timestamp.digicert.com"
  "sectigo|http://timestamp.sectigo.com"
  "freetsa|https://freetsa.org/tsr"
  "globalsign|http://timestamp.globalsign.com/tsa/r6advanced1"
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

has_existing_tsr() {
  local base_name="$1"
  shopt -s nullglob
  local matches=("${TS_DIR}/${base_name}".*.tsr)
  shopt -u nullglob
  [[ ${#matches[@]} -gt 0 ]]
}

# 读取上一次的 SHA256SUMS.txt 以便比对文件是否发生变化
declare -A OLD_HASHES
SUMS_FILE="${PKI_DIR}/SHA256SUMS.txt"
OLD_SUMS_HASH=""
if [[ -f "${SUMS_FILE}" ]]; then
  OLD_SUMS_HASH="$(sha256sum "${SUMS_FILE}" | awk '{print $1}')"
  while read -r hash fname; do
    [[ -n "${hash}" && -n "${fname}" ]] && OLD_HASHES["${fname}"]="${hash}"
  done < "${SUMS_FILE}"
fi

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

# 清理旧的无效临时文件及已删除文件遗留的时间戳
rm -f "${TS_DIR}"/*.tmp
declare -A CURRENT_NAMES
for f in "${PKI_FILES[@]}"; do
  CURRENT_NAMES["$(basename "$f")"]=1
done
CURRENT_NAMES["SHA256SUMS.txt"]=1

shopt -s nullglob
for ts_file in "${TS_DIR}"/*.tsr "${TS_DIR}"/*.tsq; do
  ts_base="$(basename "${ts_file}")"
  # 去掉 .<tsa>.tsr / .<tsa>.tsq 两段后缀还原原文件名
  orig_name="${ts_base%.*.*}"
  if [[ -z "${CURRENT_NAMES[${orig_name}]+x}" ]]; then
    echo "Removing orphaned timestamp file: ${ts_base}"
    rm -f "${ts_file}"
  fi
done
shopt -u nullglob

# 生成新的 SHA256SUMS.txt（按文件名排序保证确定性）
TMP_SUMS="${SUMS_FILE}.tmp"
: > "${TMP_SUMS}"
if [[ ${#PKI_FILES[@]} -gt 0 ]]; then
  (
    cd "${PKI_DIR}"
    for f in $(LC_ALL=C printf '%s\n' *.cer *.crt *.pem *.crl 2>/dev/null | sort); do
      [[ -f "$f" ]] || continue
      sha256sum "$f" >> "SHA256SUMS.txt.tmp"
    done
  )
fi
mv "${TMP_SUMS}" "${SUMS_FILE}"
NEW_SUMS_HASH="$(sha256sum "${SUMS_FILE}" | awk '{print $1}')"

# 仅对新增、修改或尚无时间戳的文件申请新时间戳；未更改的文件直接复用旧时间戳
for target in "${PKI_FILES[@]}"; do
  base_name="$(basename "${target}")"
  new_hash="$(sha256sum "${target}" | awk '{print $1}')"
  old_hash="${OLD_HASHES[${base_name}]:-}"

  if [[ "${new_hash}" == "${old_hash}" ]] && has_existing_tsr "${base_name}"; then
    echo "Unchanged (${base_name}), reusing existing timestamps."
    continue
  fi

  echo "Changed or new (${base_name}), requesting RFC 3161 timestamps..."
  rm -f "${TS_DIR}/${base_name}".*.tsr "${TS_DIR}/${base_name}".*.tsq
  for entry in "${TSAS[@]}"; do
    IFS='|' read -r tsa_name tsa_url <<< "${entry}"
    request_tsa "${target}" "${base_name}" "${tsa_name}" "${tsa_url}" || true
  done
done

# 处理 SHA256SUMS.txt 的时间戳
if [[ -s "${SUMS_FILE}" ]]; then
  if [[ "${NEW_SUMS_HASH}" == "${OLD_SUMS_HASH}" ]] && has_existing_tsr "SHA256SUMS.txt"; then
    echo "Unchanged (SHA256SUMS.txt), reusing existing timestamps."
  else
    echo "Changed or new (SHA256SUMS.txt), requesting RFC 3161 timestamps..."
    rm -f "${TS_DIR}/SHA256SUMS.txt".*.tsr "${TS_DIR}/SHA256SUMS.txt".*.tsq
    for entry in "${TSAS[@]}"; do
      IFS='|' read -r tsa_name tsa_url <<< "${entry}"
      request_tsa "${SUMS_FILE}" "SHA256SUMS.txt" "${tsa_name}" "${tsa_url}" || true
    done
  fi
fi

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
