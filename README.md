# ProDuckX-ADBlock

Hệ thống tự động tổng hợp danh sách tên miền quảng cáo/mã độc, chuyển đổi thành tệp nhị phân (`blocklist.bin`) sử dụng mã băm FNV-1a 40-bit (5 byte) phục vụ cho thiết bị phần cứng / firmware DNS blocker. Dự án tích hợp FastAPI để tự động tạo và tải lên Vercel Blob theo lịch định kỳ qua Vercel Cron.

---

## 🚀 Tính năng chính

- **Tổng hợp nhiều nguồn chặn lớn**:
  - StevenBlack Hosts
  - Hagezi Light (Wildcard)
  - GoodbyeAds Filter
  - AdGuard SDNS Filter
  - AdAway Default Hosts
- **Chuyển đổi dữ liệu tối ưu**:
  - Tự động chuẩn hóa tên miền và xử lý các luật cho phép (`@@||domain^`).
  - Lọc bỏ cú pháp Adblock không tương thích với DNS blocker (cosmetic rules `##`, `$modifiers`, regex).
  - Băm tên miền bằng thuật toán FNV-1a thu gọn 40-bit (5-byte little-endian), loại bỏ trùng lặp và sắp xếp theo thứ tự để hỗ trợ tìm kiếm nhị phân (`binary search`).
- **Tự động hóa với Vercel**:
  - Endpoint `/api/refresh` chạy theo lịch Vercel Cron để fetch, build và cập nhật `blocklist.bin` lên Vercel Blob Storage.
  - Endpoint `/api/download/blocklist.bin` chuyển hướng trực tiếp (HTTP 307) đến URL tải file công khai từ Vercel Blob.

---

## 📂 Cấu trúc thư mục

```text
ProDuckX-ADBlock/
├── api/
├── data/
│   └── blocklist.bin          # Tệp nhị phân sau khi build cục bộ
├── build_blocklist.py         # Script tải nguồn, lọc domain và xuất file binary
├── main.py                    # Ứng dụng FastAPI phục vụ API và Cron Job
├── requirements.txt           # Thư viện phụ thuộc (fastapi, vercel-blob)
├── vercel.json                # Cấu hình Vercel framework và cron job
├── .env                       # Biến môi trường cục bộ (không commit)
└── README.md
```

---

## 🛠️ Cài đặt & Chạy cục bộ (Local)

### 1. Chuẩn bị môi trường
Yêu cầu Python 3.10 trở lên:
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Cấu hình file `.env`
Tạo file `.env` tại thư mục gốc dự án:
```ini
# Mã bí mật bảo vệ endpoint /api/refresh
CRON_SECRET="your_custom_cron_secret"

# Token xác thực quyền ghi Vercel Blob
BLOB_READ_WRITE_TOKEN="vercel_blob_rw_xxxxxxxxxx"
```

### 3. Build thủ công danh sách chặn
Chạy trực tiếp script để tạo file `data/blocklist.bin`:
```bash
python build_blocklist.py
```

### 4. Chạy server phát triển (FastAPI)
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
- Trang chủ: [http://localhost:8000/](http://localhost:8000/)
- Tải file nhị phân: [http://localhost:8000/api/download/blocklist.bin](http://localhost:8000/api/download/blocklist.bin)
- Kích hoạt cập nhật thủ công:
  ```bash
  curl -H "Authorization: Bearer <CRON_SECRET>" http://localhost:8000/api/refresh
  ```

---

## 🌐 Triển khai lên Vercel (Deployment)

1. **Đẩy mã nguồn lên GitHub/GitLab**.
2. **Import repository vào Vercel**:
   - Vercel sẽ tự nhận diện framework là `FastAPI`.
3. **Cấu hình Vercel Blob**:
   - Vào mục **Storage** > **Create Database** > Chọn **Blob**.
   - Đặt quyền truy cập là **Public**.
   - Kết nối Store với dự án (Vercel sẽ tự động cấp biến `BLOB_READ_WRITE_TOKEN` hoặc `BLOB_STORE_ID`).
4. **Cấu hình Environment Variables**:
   - Thêm biến `CRON_SECRET` trong mục **Settings** > **Environment Variables**.
5. **Cấu hình lịch chạy định kỳ (`vercel.json`)**:
   Lịch mặc định chạy vào 23:00 Chủ nhật hàng tuần (15:00 UTC):
   ```json
   {
     "$schema": "https://openapi.vercel.sh/vercel.json",
     "framework": "fastapi",
     "crons": [
       {
         "path": "/api/refresh",
         "schedule": "0 15 * * 0"
       }
     ]
   }
   ```
   > **Lưu ý**: Đối với tài khoản Vercel miễn phí (Hobby), cron job chỉ hỗ trợ tần suất tối đa **1 lần/ngày**.

---

## 📄 Thông số kỹ thuật của File `blocklist.bin`

- **Độ dài mỗi phần tử**: 5 bytes (40-bit FNV-1a hash, little-endian).
- **Cấu trúc dữ liệu**: Mảng phẳng các giá trị băm đã được sắp xếp tăng dần (`sorted unique uint40`).
- **Cách tra cứu (Lookup)**: Firmware thiết bị có thể áp dụng thuật toán Binary Search trực tiếp trên Flash memory với độ phức tạp $O(\log_2 N)$ (chỉ mất ~19 lần đọc bộ nhớ cho hơn 500.000 tên miền).