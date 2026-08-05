FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# Cài dependency trước, copy code sau -> tận dụng cache layer khi sửa code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Chạy bằng user thường, không dùng root (yêu cầu phi chức năng: bảo mật hệ thống).
RUN useradd --create-home --uid 10001 minisoc && chown -R minisoc:minisoc /srv
USER minisoc

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
