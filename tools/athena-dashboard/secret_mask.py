"""Mask secrets in report-facing command text. The log keeps originals."""
import re

MASK = "********"
MIN_LITERAL_LEN = 4

_KEY = r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key)"
_START = r"(?<![\w-])"          # flag must start a token (not inside a hostname/word)
_NOT_PORTS = r"(?![\d,-]+(?:\s|$))"  # port-list value (-p 80,443 / -p1-1000)

# Port-list exemption applies ONLY to a -p whose own command segment INVOKES a
# port scanner (first token, after VAR=value assignments, basename match);
# otherwise a numeric -p value could be a password (fail safe: mask it).
_SCANNER_CMDS = {"nmap", "masscan", "rustscan", "unicornscan"}
_WRAPPERS = {"sudo", "doas", "time", "env", "nohup", "nice", "exec", "command", "stdbuf"}
# ACCEPTED LIMIT (best-effort, not parsed): a numeric -p password nested in a
# command substitution or subshell, e.g. `nmap $(mysql -p123456 -e 1)`, is not
# split into its own segment and may be exempted by the outer scanner. (Note a
# trailing `)` defeats the port-list lookahead, so `nmap $(mysql -p123456)` is
# in fact masked; the leak needs a space after the value, as in the example.)
# We accept this because (1) it requires a deliberately constructed command, and
# (2) Layer-1 literal masking of credential-store values is the real backstop:
# it catches the actual secret regardless of nesting. Do NOT add subshell parsing.
_SEGMENT_SPLIT = re.compile(r"(&&|&|\|\||\||;|\n)")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_P_ATTACHED = re.compile(rf"{_START}(-p)(\S{{3,}})")
_P_SPACED = re.compile(rf"{_START}(-p\s+)(\S+)")
_P_ATTACHED_SCAN = re.compile(rf"{_START}(-p)({_NOT_PORTS}\S{{3,}})")
_P_SPACED_SCAN = re.compile(rf"{_START}(-p\s+){_NOT_PORTS}(\S+)")

# (pattern, replacement) -- every rule carries its own explicit replacement
# template rather than relying on group counts. The -p rules are applied
# separately, per command segment (see _mask_p_flags).
_RULES = [
    # key=value / key: value
    (re.compile(rf"(?i)\b({_KEY})(\s*[=:]\s*)(\S+)"), rf"\g<1>\g<2>{MASK}"),
    # --password X / --password=X
    (re.compile(r"(?i)(--password[=\s]+)(\S+)"), rf"\g<1>{MASK}"),
    # scheme://user:pass@
    (re.compile(r"([A-Za-z0-9_.-]+://[^:/\s]+:)([^@\s]+)(@)"), rf"\g<1>{MASK}\g<3>"),
    # -u user:pass[@host]
    (re.compile(rf"{_START}(-[uU]\s*[^:\s]+:)([^@\s]+)(@?)"), rf"\g<1>{MASK}\g<3>"),
    # -Uuser%pass (smbclient)
    (re.compile(rf"{_START}(-U[^%\s]+%)(\S+)"), rf"\g<1>{MASK}"),
    # LM:NT hash pair
    (re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b"), MASK),
]


def _invokes_scanner(segment):
    """True if the segment's real command is a port scanner.

    Skips leading VAR=value assignments and bare command-wrapper words (sudo,
    env, time, ...). The first remaining token decides: if it starts with '-'
    it is a flag, and we CANNOT know whether it is a wrapper flag that consumes
    the next word as its argument (sudo -u <user>, nice -n <n>, env -u <var>)
    or a flag the real command would reject -- so we do NOT resolve a command
    and fail safe (return False -> the -p value is masked). Only a wrapper
    directly followed by the real command word (no intervening flags) resolves
    to a scanner. This over-masks rare forms like `sudo -E nmap -p 80`
    (acceptable fail-safe) but can never be fooled by a scanner name that is
    actually a flag's argument, e.g. `sudo -u nmap mysql -p<pass>` (the leak
    this guards against: -u's argument is a username, mysql is the command).
    """
    for tok in segment.split():
        if _ENV_ASSIGN.match(tok):
            continue
        if tok in _WRAPPERS:
            continue
        if tok.startswith("-"):
            return False
        return tok.strip("'\"").rsplit("/", 1)[-1].lower() in _SCANNER_CMDS
    return False


def _mask_p_flags(text):
    """-p masking, decided per command segment (split on ; && & || | newline)."""
    parts = _SEGMENT_SPLIT.split(text)  # separators sit at odd indexes
    for i in range(0, len(parts), 2):
        seg = parts[i]
        if _invokes_scanner(seg):
            attached, spaced = _P_ATTACHED_SCAN, _P_SPACED_SCAN
        else:
            attached, spaced = _P_ATTACHED, _P_SPACED
        seg = attached.sub(rf"\g<1>{MASK}", seg)
        parts[i] = spaced.sub(rf"\g<1>{MASK}", seg)
    return "".join(parts)


def mask_text(text, literals=()):
    if not isinstance(text, str) or not text:
        return text
    out = text
    for lit in literals or ():
        if isinstance(lit, str) and len(lit) >= MIN_LITERAL_LEN:
            out = out.replace(lit, MASK)
    for pat, repl in _RULES:
        out = pat.sub(repl, out)
    return _mask_p_flags(out)


def mask_input(input: dict, literals=()):
    if not isinstance(input, dict):
        return input
    return {k: (mask_text(v, literals) if isinstance(v, str) else v) for k, v in input.items()}
