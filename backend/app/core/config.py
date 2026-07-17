from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SOC Platform"
    debug: bool = False

    database_url: str
    secret_key: str
    access_token_expire_minutes: int = 30

    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True

    model_config = SettingsConfigDict(env_file=".env")

    def __init__(self, **values):
        super().__init__(**values)
        if self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace(
                "postgres://",
                "postgresql://",
                1,
            )


settings = Settings()