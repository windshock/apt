"""
Volatility3 external plugin: windows.yarascan

Why this exists:
  - Volatility2 users often expect: "windows.yarascan --yara-file=..."
  - In Volatility3, the closest built-in equivalent is "windows.vadyarascan" (scan process VADs)
  - This file provides a *thin alias* so you can run:

      vol --plugin-dirs /work/vol_plugins windows.yarascan --yara-file=... -f <mem>

Notes:
  - Requires python YARA bindings (yara-python) inside the container.
  - Still requires a real Windows memory image that Volatility3 can stack (not HA region-split blobs).
"""

from volatility3.plugins.windows.vadyarascan import VadYaraScan


class YaraScan(VadYaraScan):
    """Alias for Volatility3's windows.vadyarascan (process VAD scanning)."""


