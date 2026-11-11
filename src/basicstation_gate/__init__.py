"""A LoRa Basics Station front door and CUPS server for ChirpStack and other LNSs."""

import os
from pathlib import Path

__version__ = '0.1.0'
USER_AGENT = f'basicstation-gate/{__version__}'


def env(name, default=None):
    """A setting from NAME, or from the file NAME_FILE names (for secrets
    mounted as files)."""
    path = os.getenv(f'{name}_FILE')
    if path:
        return Path(path).read_text().strip()
    return os.getenv(name, default)
