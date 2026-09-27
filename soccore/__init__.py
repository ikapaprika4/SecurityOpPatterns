"""
soccore -- the small shared layer under the four toolkits.

Only code that was duplicated across kits (and, in two cases, subtly wrong in
one of the copies) lives here:

    soccore.netaddr   internal/external address classification
    soccore.pcap      dependency-free pcap/pcapng reader + packet dissector
    soccore.windows   O(n) sliding-window helpers for "N things within T seconds"

Everything else stays in its own kit; each kit remains usable on its own.
"""

__version__ = "1.0.0"
