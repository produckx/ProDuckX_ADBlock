"""FastAPI trên Vercel: build blocklist.bin định kỳ và public qua Vercel Blob."""
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from vercel.blob import sync as blob

import build_blocklist


def load_env():
    # uvicorn local không tự đọc .env -> nạp tay, khỏi thêm dependency
    f = Path(__file__).with_name(".env")
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            key, _, value = line.strip().partition("=")
            if key and not key.startswith("#") and value:
                os.environ.setdefault(key, value.strip().strip("\"'"))


load_env()

CRON_SECRET = os.environ.get("CRON_SECRET", "")
BLOB_NAME = "blocklist.bin"
TMP_OUT = os.path.join(tempfile.gettempdir(), "blocklist.bin")  # Vercel chỉ cho ghi /tmp

app = FastAPI(title="ProDuckX Blocklist")


@app.get("/api/refresh")
def refresh(authorization: str = Header(None)):
    # Vercel Cron tự gửi Authorization: Bearer <CRON_SECRET>
    if CRON_SECRET and authorization != f"Bearer {CRON_SECRET}":
        raise HTTPException(401, "unauthorized")
    stats = build_blocklist.build(TMP_OUT)
    with open(TMP_OUT, "rb") as f:
        uploaded = blob.put_blob(
            BLOB_NAME,
            f.read(),
            access="public",
            content_type="application/octet-stream",
            add_random_suffix=False,
            allow_overwrite=True,
            cache_control_max_age=300,
        )
    return {"ok": True, "url": uploaded.url, **stats}


@app.get("/api/download/blocklist.bin")
def download():
    try:
        meta = blob.head_blob(BLOB_NAME)
    except blob.BlobNotFoundError:
        raise HTTPException(404, "blocklist.bin chưa được tạo")
    return RedirectResponse(meta.download_url, status_code=307)


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><html lang="vi"><meta charset="utf-8">
<title>ProDuckX Blocklist</title>
<style>body{font-family:system-ui;max-width:640px;margin:60px auto;padding:0 16px}
a.btn{display:inline-block;background:#111;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none}</style>
<h1>ProDuckX Blocklist</h1>
<p>Danh sách chặn quảng cáo dạng hash 5 byte (40-bit), làm mới 23:00 Chủ nhật hằng tuần.</p>
<p><a class="btn" href="/api/download/blocklist.bin">Tải blocklist.bin</a></p>
<p><small>Build định kỳ: <code>/api/refresh</code></small></p>
</html>"""
