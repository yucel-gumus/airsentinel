"""Configuration settings for AirSentinel Core."""
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "airsentinel" / "web" / "static"

class Settings(BaseModel):
    # App Information
    app_name: str = "AirSentinel Core"
    app_version: str = "2.0.0"
    debug: bool = False

    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8080

    # Paths
    data_dir: Path = DATA_DIR
    signatures_path: Path = DATA_DIR / "fieldwatch-signatures-v2.json"
    db_path: Path = DATA_DIR / "airsentinel.db"
    
    # Radio Scanner Settings
    wifi_scan_interval_sec: float = 8.0
    enable_ble_scanner: bool = True
    enable_wifi_scanner: bool = True

    # Threat & Correlation Engine
    flood_window_seconds: int = 5
    flood_threshold_count: int = 8
    stalking_min_observations: int = 3
    stalking_time_span_minutes: int = 10
    stalking_rssi_threshold: int = -75  # Close proximity

    # Local AI (Ollama) Settings
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:latest"

settings = Settings()
