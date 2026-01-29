"""Black Box: Personal OSINT pattern detection system.

Gathers data from public sources, detects patterns, and outputs
JSON digests for downstream analysis.
"""

__version__ = "0.1.0"
__author__ = "Jason Scott Adams"

from blackbox.exceptions import BlackBoxError

__all__ = ["__version__", "BlackBoxError"]
