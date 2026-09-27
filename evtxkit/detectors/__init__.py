"""Detector registry package. Importing this package registers every
built-in detector via the @register decorator side effect."""

from __future__ import annotations

from .base import REGISTRY, Detector, register, run_detectors  # noqa: F401
from . import logon as _logon               # noqa: F401,E402
from . import usermgmt as _usermgmt          # noqa: F401,E402
from . import persistence as _persistence    # noqa: F401,E402
from . import execution as _execution        # noqa: F401,E402
from . import discovery as _discovery        # noqa: F401,E402
from . import collection as _collection      # noqa: F401,E402
from . import c2_transfer as _c2_transfer    # noqa: F401,E402
from . import defense_evasion as _defense    # noqa: F401,E402

__all__ = ["REGISTRY", "Detector", "register", "run_detectors"]
