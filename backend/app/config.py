"""Cấu hình tập trung, đọc hoàn toàn từ biến môi trường.

Vì sao pydantic-settings: mọi giá trị được ép kiểu và kiểm tra ngay lúc khởi
động, nên lỗi cấu hình (ví dụ JWT_EXPIRE_MINUTES="abc") làm app chết ngay thay
vì chết giữa giờ demo.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # .env còn chứa biến cho docker/frontend, bỏ qua chúng
    )

    # --- Hạ tầng ---
    database_url: str = "postgresql+psycopg://minisoc:minisoc@127.0.0.1:5432/minisoc"
    redis_url: str = "redis://127.0.0.1:6379/0"

    # --- Bảo mật ---
    jwt_secret: str = "khong-an-toan-doi-ngay"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    admin_email: str = "admin@minisoc.local"
    admin_password: str = "ChangeMe#2026"
    agent_enroll_token: str = "doi-token-nay"

    # --- API ---
    cors_origins: str = "http://localhost:5173"
    log_level: str = "INFO"

    # --- Bật/tắt module (mọi module phải bật/tắt độc lập được) ---
    enable_rule_engine: bool = True
    enable_ml_network: bool = False
    enable_ransomware_behavior: bool = False
    enable_llm_assistant: bool = False

    # --- Mô hình ML của lớp 2 ---
    # Để trống thì dùng ml/artifacts cạnh mã nguồn (khi chạy ngoài Docker).
    # Trong Docker, thư mục này được mount vào và trỏ bằng biến môi trường.
    ml_model_dir: str = ""
    ml_model_name: str = "random_forest"
    ml_alert_threshold: float = 0.80

    # --- Lớp trợ lý AI ---
    llm_provider: str = "anthropic"
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-5"
    llm_anonymize: bool = True

    # --- Thông báo ---
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    alert_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "minisoc@example.com"
    notify_min_severity: str = "high"

    # --- Redis Streams ---
    stream_events: str = "minisoc:events"
    stream_alerts: str = "minisoc:alerts"
    consumer_group: str = "detection"
    stream_maxlen: int = 200_000  # giới hạn stream để Redis không phình vô hạn

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Đọc cấu hình một lần rồi cache — tránh parse .env ở mỗi request."""
    return Settings()


settings = get_settings()
