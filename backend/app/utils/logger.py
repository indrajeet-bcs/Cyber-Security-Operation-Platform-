import logging
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parents[3] / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "app.log"),
    ],
)

logger = logging.getLogger("soc_platform")
