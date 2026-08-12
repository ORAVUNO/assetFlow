"""Loading the Asset Intelligence registry from YAML."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml

from .models import Registry

# Locations searched, in order, when no explicit path is given.
_DEFAULT_CANDIDATES = (
    "config/asset_intelligence_registry.yaml",
    "asset_intelligence_registry.yaml",
)


def default_registry_path() -> Optional[Path]:
    """Return the first registry file found near the cwd or this package."""
    search_roots = [Path.cwd(), Path(__file__).resolve().parent.parent]
    for root in search_roots:
        for candidate in _DEFAULT_CANDIDATES:
            path = root / candidate
            if path.is_file():
                return path
    return None


def load_registry(path: Optional[os.PathLike | str] = None) -> Registry:
    """Load and validate the registry.

    Raises FileNotFoundError if no registry file can be located, and
    pydantic.ValidationError / ValueError if the file fails validation.
    """
    if path is None:
        resolved = default_registry_path()
        if resolved is None:
            raise FileNotFoundError(
                "could not locate a registry file; looked for "
                + ", ".join(_DEFAULT_CANDIDATES)
                + " — pass an explicit path"
            )
    else:
        resolved = Path(path)
        if not resolved.is_file():
            raise FileNotFoundError(f"registry file not found: {resolved}")

    with resolved.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"registry {resolved} did not parse to a mapping")

    return Registry.model_validate(raw)
