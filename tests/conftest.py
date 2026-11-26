"""Keep test temporary assets inside the workspace, including on a fresh clone."""

from pathlib import Path


def pytest_configure(config):
    if config.option.basetemp:
        # pytest creates the base directory itself, but not a missing parent.
        Path(config.option.basetemp).parent.mkdir(parents=True, exist_ok=True)
