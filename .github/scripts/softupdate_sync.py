#!/usr/bin/env python3
"""SoftUpdate 同步脚本：把 GitHub Release 的 win-x64 包上传到自建更新服务并发布。

环境变量：
  SOFTUPDATE_SERVER   更新服务地址（默认 http://soft.shack2.cn）
  SOFTUPDATE_API_KEY  管理 API Key（必填）
  GITHUB_REF_NAME     tag 名（v2.0.0），自动剥离 v 前缀作为版本号
  PKG_DIR             包目录（默认 pkg，取其中第一个 .zip）

同版本已存在时先删除旧记录再上传，保证重跑幂等。
"""
import glob
import json
import os
import sys
import urllib.request
import uuid

SERVER = os.environ.get("SOFTUPDATE_SERVER", "http://soft.shack2.cn").rstrip("/")
API_KEY = os.environ.get("SOFTUPDATE_API_KEY", "")
APP_ID = "spassword-checker"
CHANNEL = "stable"
OS = "windows"
ARCH = "x64"

if not API_KEY:
    sys.exit("SOFTUPDATE_API_KEY 未配置")

version = os.environ.get("GITHUB_REF_NAME", "").lstrip("v")
if not version:
    sys.exit("GITHUB_REF_NAME 为空，无法确定版本号")

pkg_dir = os.environ.get("PKG_DIR", "pkg")
zips = sorted(glob.glob(os.path.join(pkg_dir, "*.zip")))
if not zips:
    sys.exit(f"{pkg_dir} 下没有 zip 包")
zip_path = zips[0]


def request(method, path, body=None, headers=None):
    req = urllib.request.Request(SERVER + path, method=method)
    req.add_header("X-Api-Key", API_KEY)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, body) as r:
        raw = r.read()
        return r.status, json.loads(raw) if raw else {}


# 1. 同版本（版本+渠道+OS+架构）已存在则先删除，保证幂等重跑
_, releases = request("GET", f"/api/admin/releases?appId={APP_ID}")
for r in releases:
    if (r.get("version") == version and r.get("channel") == CHANNEL
            and (r.get("os") or "") == OS and (r.get("arch") or "") == ARCH):
        print(f"删除已存在的 {version}（id={r['id']}，状态 {r.get('status')}）")
        request("DELETE", f"/api/admin/releases/{r['id']}")

# 2. multipart/form-data 上传（urllib 手写，中文 notes 也没问题）
boundary = uuid.uuid4().hex
fields = {
    "appId": APP_ID,
    "version": version,
    "channel": CHANNEL,
    "os": OS,
    "arch": ARCH,
    "notes": f"SNETCracker v{version}（GitHub Actions 自动构建发布）",
}
parts = []
for k, v in fields.items():
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
with open(zip_path, "rb") as f:
    data = f.read()
parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{os.path.basename(zip_path)}"\r\n'
             f'Content-Type: application/zip\r\n\r\n'.encode() + data + b"\r\n")
parts.append(f"--{boundary}--\r\n".encode())
body = b"".join(parts)

status, resp = request("POST", "/api/admin/releases", body,
                       {"Content-Type": f"multipart/form-data; boundary={boundary}"})
print(f"上传结果 {status}: {resp}")
release_id = resp["id"]

# 3. 发布
status, resp = request("POST", f"/api/admin/releases/{release_id}/publish")
print(f"发布结果 {status}: {resp}")
print(f"DONE version={version} id={release_id}")
