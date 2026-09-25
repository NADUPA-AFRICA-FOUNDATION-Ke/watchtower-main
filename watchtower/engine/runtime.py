"""Configuration boundary shared by web and local MCP/worker entry points."""
from __future__ import annotations
import os
from pathlib import Path
import yaml
import json
from .service import InvestigationService


def create_service() -> InvestigationService:
    root = Path(__file__).resolve().parents[2]
    directory = Path(os.environ.get('WATCHTOWER_DATA_DIR') or
                     ('/tmp/watchtower' if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') else root))
    directory.mkdir(parents=True, exist_ok=True)
    config = yaml.safe_load((root / 'config.yaml').read_text())
    scam = json.loads((root / 'config.json').read_text())
    return InvestigationService(directory / config['storage'].get('investigations_database', 'investigations.db'),
                                directory / 'provider-cache.db', config.get('investigation', {}), scam.get('brand', {}))
