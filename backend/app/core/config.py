from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "SOC Platform"
    debug: bool = False
    database_url: str = "postgresql://postgres:root@localhost:5432/soc_platform"
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 30

    # SMTP / Email Configuration
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True

    class Config:
        env_file = ".env"

    def __init__(self, **values):
        super().__init__(**values)
        if self.database_url and self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace("postgres://", "postgresql://", 1)


settings = Settings()
