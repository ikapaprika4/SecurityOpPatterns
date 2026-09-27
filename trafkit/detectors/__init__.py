"""Importing this package registers every detector via the @register
decorator -- callers just need `from trafkit.detectors import base` (or the
top-level `trafkit` package, which imports this) and then read
`base.REGISTRY`."""

from . import arp, cleartext, hostid, http, scanning, tls, tunneling  # noqa: F401
from .base import REGISTRY, AnalysisContext, Detector, run_detectors  # noqa: F401
