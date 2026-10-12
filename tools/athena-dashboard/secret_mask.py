"""Mask secrets in report-facing command text. The log keeps originals."""
import re

MASK = "********"
MIN_LITERAL_LEN = 4

_KEY = r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key)"
_START = r"(?<![\w-])"          # flag must start a token (not inside a hostname/word)
_NOT_PORTS = r"(?![\d,-]+(?:\s|$))"  # nmap-style port list (-p 80,443 / -p1-1000)
# Port-list exemption applies ONLY when the command names a port scanner;
# otherwise a numeric -p value could be a password (fail safe: mask it).
_SCANNER = re.compile(r"(?i)\b(?:nmap|masscan|rustscan|unicornscan)\b")

_P_ATTACHED = re.compile(rf"{_START}(-p)(\S{{3,}})")
_P_SPACED = re.compile(rf"{_START}(-p\s+)(\S+)")
_P_ATTACHED_SCAN = re.compile(rf"{_START}(-p)({_NOT_PORTS}\S{{3,}})")
_P_SPACED_SCAN = re.compile(rf"{_START}(-p\s+){_NOT_PORTS}(\S+)")
_SCAN_SWAP = {_P_ATTACHED: _P_ATTACHED_SCAN, _P_SPACED: _P_SPACED_SCAN}

# (pattern, replacement) -- every rule carries its own explicit replacement
# template rather than relying on group counts.
_RULES = [
    # key=value / key: value
    (re.compile(rf"(?i)\b({_KEY})(\s*[=:]\s*)(\S+)"), rf"\g<1>\g<2>{MASK}"),
    # --password X / --password=X
    (re.compile(r"(?i)(--password[=\s]+)(\S+)"), rf"\g<1>{MASK}"),
    # -p<value> attached / -p value (variant chosen in mask_text)
    (_P_ATTACHED, rf"\g<1>{MASK}"),
    (_P_SPACED, rf"\g<1>{MASK}"),
    # scheme://user:pass@
    (re.compile(r"([A-Za-z0-9_.-]+://[^:/\s]+:)([^@\s]+)(@)"), rf"\g<1>{MASK}\g<3>"),
    # -u user:pass[@host]
    (re.compile(rf"{_START}(-[uU]\s*[^:\s]+:)([^@\s]+)(@?)"), rf"\g<1>{MASK}\g<3>"),
    # -Uuser%pass (smbclient)
    (re.compile(rf"{_START}(-U[^%\s]+%)(\S+)"), rf"\g<1>{MASK}"),
    # LM:NT hash pair
    (re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b"), MASK),
]


def mask_text(text, literals=()):
    if not isinstance(text, str) or not text:
        return text
    out = text
    for lit in literals or ():
        if isinstance(lit, str) and len(lit) >= MIN_LITERAL_LEN:
            out = out.replace(lit, MASK)
    scanner = bool(_SCANNER.search(text))
    for pat, repl in _RULES:
        if scanner:
            pat = _SCAN_SWAP.get(pat, pat)
        out = pat.sub(repl, out)
    return out


def mask_input(input: dict, literals=()):
    if not isinstance(input, dict):
        return input
    return {k: (mask_text(v, literals) if isinstance(v, str) else v) for k, v in input.items()}
