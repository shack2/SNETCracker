#!/usr/bin/env python3
"""SoftUpdate 同步脚本：把 GitHub Release 的各平台包上传到自建更新服务并发布。

环境变量：
  SOFTUPDATE_SERVER   更新服务地址（默认 http://soft.shack2.cn）
  SOFTUPDATE_API_KEY  管理 API Key（必填）
  GITHUB_REF_NAME     tag 名（v2.0.0），自动剥离 v 前缀作为版本号
  PKG_DIR             包根目录（默认 pkg，递归扫描其中的平台 zip）

按文件名后缀识别平台：_win-x64 / _linux-x64 / _osx-x64 / _osx-arm64。
更新服务仅接受 zip；同版本同平台已存在时先删除旧记录再上传，保证重跑幂等。
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

# 文件名后缀 → (os, arch)
PLATFORMS = {
    "_win-x64.zip": ("windows", "x64"),
    "_linux-x64.zip": ("linux", "x64"),
    "_osx-x64.zip": ("osx", "x64"),
    "_osx-arm64.zip": ("osx", "arm64"),
}

if not API_KEY:
    sys.exit("SOFTUPDATE_API_KEY 未配置")

version = os.environ.get("GITHUB_REF_NAME", "").lstrip("v")
if not version:
    sys.exit("GITHUB_REF_NAME 为空，无法确定版本号")

pkg_dir = os.environ.get("PKG_DIR", "pkg")
packages = []  # (os, arch, zip_path)
for path in sorted(glob.glob(os.path.join(pkg_dir, "**", "*.zip"), recursive=True)):
    for suffix, (os_name, arch) in PLATFORMS.items():
        if path.endswith(suffix):
            packages.append((os_name, arch, path))
            break
if not packages:
    sys.exit(f"{pkg_dir} 下没有可识别的平台 zip 包（后缀需为 {', '.join(PLATFORMS)}）")


def request(method, path, body=None, headers=None):
    req = urllib.request.Request(SERVER + path, method=method)
    req.add_header("X-Api-Key", API_KEY)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, body) as r:
        raw = r.read()
        return r.status, json.loads(raw) if raw else {}


_, releases = request("GET", f"/api/admin/releases?appId={APP_ID}")

for os_name, arch, zip_path in packages:
    # 1. 同版本+渠道+OS+架构已存在则先删除，保证幂等重跑
    for r in releases:
        if (r.get("version") == version and r.get("channel") == CHANNEL
                and (r.get("os") or "") == os_name and (r.get("arch") or "") == arch):
            print(f"删除已存在的 {version} {os_name}/{arch}（id={r['id']}，状态 {r.get('status')}）")
            request("DELETE", f"/api/admin/releases/{r['id']}")

    # 2. multipart/form-data 上传（urllib 手写，中文 notes 也没问题）
    boundary = uuid.uuid4().hex
    fields = {
        "appId": APP_ID,
        "version": version,
        "channel": CHANNEL,
        "os": os_name,
        "arch": arch,
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
    print(f"上传 {os_name}/{arch} 结果 {status}: {resp}")
    release_id = resp["id"]

    # 3. 发布
    status, resp = request("POST", f"/api/admin/releases/{release_id}/publish")
    print(f"发布 {os_name}/{arch} 结果 {status}: {resp}")
    print(f"DONE version={version} {os_name}/{arch} id={release_id}")
