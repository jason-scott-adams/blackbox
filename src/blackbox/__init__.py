"""Black Box: Personal OSINT pattern detection system.

Standalone collector for JUNO-ZERO. Gathers data from public sources,
detects patterns, and outputs JSON digests to Juno's inbox.
"""

__version__ = "0.1.0"
__author__ = "Jason"

from blackbox.exceptions import BlackBoxError

__all__ = ["__version__", "BlackBoxError"]
