"""Persist a successful UI connection to a local ``.env`` file (opt-in).

By default credentials entered in the UI live in memory only. When the user
ticks "Remember on this machine", the adapter's connection fields are written to
``.env`` in the working directory — the same file the startup auto-connect
already reads (``python-dotenv``), and which is gitignored. This is plaintext on
the local machine (the same posture as editing ``.env`` by hand); it is not
encryption. Only the keys an adapter manages are touched, so unrelated ``.env``
entries and comments are preserved.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from dotenv import dotenv_values, set_key, unset_key


def env_path() -> Path:
    return Path(os.getenv("ASSETFLOW_ENV_FILE") or ".env").resolve()


def save(managed_keys: List[str], assignments: Dict[str, str]) -> None:
    """Persist ``assignments`` to ``.env``, clearing the adapter's other managed
    keys first (so switching auth styles doesn't leave stale values)."""
    path = env_path()
    path.touch(exist_ok=True)
    p = str(path)
    for key in managed_keys:
        if key not in assignments:
            unset_key(p, key)
    for key, value in assignments.items():
        set_key(p, key, value or "")
        os.environ[key] = value or ""  # take effect for this process too


def forget(managed_keys: List[str]) -> None:
    """Remove an adapter's managed keys from ``.env`` and the process env."""
    path = env_path()
    if path.exists():
        p = str(path)
        for key in managed_keys:
            unset_key(p, key)
    for key in managed_keys:
        os.environ.pop(key, None)


def has_saved(managed_keys: List[str]) -> bool:
    """True when ``.env`` holds a non-empty value for any managed key."""
    path = env_path()
    if not path.exists():
        return False
    values = dotenv_values(str(path))
    return any(values.get(k) for k in managed_keys)
