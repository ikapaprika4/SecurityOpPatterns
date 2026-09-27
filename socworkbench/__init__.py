"""
SOC Workbench -- one drag-and-drop front door to the four toolkits.

Drop emails (.eml/.msg/.mbox), Windows event logs (.evtx/.xml/.json/.jsonl,
ConsoleHost_history.txt), network logs (firewall/IDS/VPN/WAF/Zeek/EVE/CSV)
or packet captures (.pcap/.pcapng/.gz), in any mix, or a folder or .zip of
them. Each file is recognised by its content, routed to the right kit, and
the results come back as uniform "cases": a verdict, findings, indicators,
and the kit-specific detail -- in a local desktop window or browser tab.

    python -m socworkbench                  open the workbench
    python -m socworkbench FILE [FILE ...]  open it with these files analysed
"""

__version__ = "1.0.0"
