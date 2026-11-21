"""FastAPI trên Vercel: build blocklist.bin định kỳ và public qua Vercel Blob."""
import os
import tempfile

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from vercel.blob import sync as blob

import build_blocklist

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


@app.get("/download")
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
<p><a class="btn" href="/download">Tải blocklist.bin</a></p>
<p><small>Build định kỳ: <code>/api/refresh</code></small></p>
</html>"""
