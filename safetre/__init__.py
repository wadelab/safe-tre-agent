"""safetre — a safe-outputs gateway for an AI analyst inside a Trusted Research Environment.

Prototype demonstrating disclosure control for *agentic* analysis of sensitive
behavioural data. Synthetic data only.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # single source of truth: the installed distribution's metadata
    __version__ = version("safe-tre-agent")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0.dev0"
