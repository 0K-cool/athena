"""Mask secrets in report-facing command text. The log keeps originals."""
import re

MASK = "********"
MIN_LITERAL_LEN = 4

_KEY = r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key)"
_START = r"(?<![\w-])"          # flag must start a token (not inside a hostname/word)
_NOT_PORTS = r"(?![\d,-]+(?:\s|$))"  # leave nmap-style port lists (-p 80,443 / -p1-1000)

# (pattern, replacement) -- every rule carries its own explicit replacement
# template rather than relying on group counts.
_RULES = [
    # key=value / key: value
    (re.compile(rf"(?i)\b({_KEY})(\s*[=:]\s*)(\S+)"), rf"\g<1>\g<2>{MASK}"),
    # --password X / --password=X
    (re.compile(r"(?i)(--password[=\s]+)(\S+)"), rf"\g<1>{MASK}"),
    # -p<value> attached
    (re.compile(rf"{_START}(-p)({_NOT_PORTS}\S{{3,}})"), rf"\g<1>{MASK}"),
    # -p value
    (re.compile(rf"{_START}(-p\s+){_NOT_PORTS}(\S+)"), rf"\g<1>{MASK}"),
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
    for pat, repl in _RULES:
        out = pat.sub(repl, out)
    return out


def mask_input(input: dict, literals=()):
    if not isinstance(input, dict):
        return input
    return {k: (mask_text(v, literals) if isinstance(v, str) else v) for k, v in input.items()}
