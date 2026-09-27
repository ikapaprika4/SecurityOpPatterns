"""Detector package. Importing it populates the REGISTRY."""

from .base import Detector, REGISTRY, register  # noqa: F401
from . import scanning, bruteforce, beaconing, exfiltration, lateral, mitm  # noqa: F401

__all__ = ["Detector", "REGISTRY", "register",
           "scanning", "bruteforce", "beaconing", "exfiltration", "lateral", "mitm"]
