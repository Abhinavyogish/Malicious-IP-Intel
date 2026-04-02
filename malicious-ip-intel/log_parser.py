import re

# RFC1918 private ranges
_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "169.254.",
)

_IPV4_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES)


def extract_ips(log_text: str) -> list:
    """Extract unique public IPv4 addresses from log text."""
    seen = set()
    result = []
    for match in _IPV4_PATTERN.finditer(log_text):
        ip = match.group(1)
        if not _is_private(ip) and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def parse_log_file(filepath: str) -> list:
    """Read a log file and return unique public IPs."""
    with open(filepath, "r", encoding="utf-8") as f:
        return extract_ips(f.read())
