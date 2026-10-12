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

# PEM / private-key block — mask the WHOLE block (DOTALL, non-greedy). Must run
# first so later rules never pick at the base64 body. The terminator also
# accepts end-of-string (\Z) so a block whose END marker was cut off by the
# 4KB excerpt limit is still masked.
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END[^-]*-----|\Z)",
    re.DOTALL,
)

# (pattern, replacement) -- every rule carries its own explicit replacement
# template rather than relying on group counts. The -p rules are applied
# separately, per command segment (see _mask_p_flags).
#
# _RULES matches BOTH command-line credential forms AND common pentest-OUTPUT
# secrets (the appendix ships up to 4KB of raw tool output). Every output rule
# is bounded/anchored to avoid catastrophic backtracking; over-masking is the
# accepted trade (a surviving secret is the only real failure).
_RULES = [
    # PEM / private-key block (whole block -> MASK)
    (_PEM_RE, MASK),
    # key=value / key: value. The key may carry non-keyword affixes so embedded
    # keywords match: AWS_SECRET_ACCESS_KEY=, db_password=, client_secret=,
    # MYSQL_PWD=, SOME_TOKEN=. The required [=:] assignment means a bare word
    # ("the password is strong") is left untouched. The value group is masked,
    # so an AWS 40-char secret given as aws_secret_access_key=<value> is covered.
    # ReDoS-safe: the start is anchored with a lookbehind (so in an all-word-char
    # input there is a single viable match start, not one per index) and BOTH
    # affixes are length-bounded, so there is no catastrophic backtracking on
    # target-controlled output. Do NOT drop the anchor or unbound the affixes.
    (re.compile(rf"(?i)(?<![A-Za-z0-9_])([A-Za-z0-9_]{{0,40}}(?:{_KEY})[A-Za-z0-9_]{{0,40}})(\s*[=:]\s*)(\S+)"),
     rf"\g<1>\g<2>{MASK}"),
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
    # Unix crypt hashes ($1$ md5 / $2a$|$2b$|$2y$ bcrypt / $5$ sha256 / $6$ sha512
    # / $7$ scrypt / $y$ yescrypt (modern Kali/Debian/Ubuntu shadow default) /
    # $apr1$ apache md5 — /etc/shadow)
    (re.compile(r"\$(?:1|2[aby]?|5|6|7|y|apr1)\$[./A-Za-z0-9$]{10,}"), MASK),
    # AWS access key id (AKIA/ASIA + 16 upper/alnum)
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    # JWT (header.payload.signature)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), MASK),
    # Bearer token — keep the word "Bearer", mask the token
    (re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._-]{8,})"), rf"\g<1>{MASK}"),
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

    Any quote character in the segment is a hard fail-safe: str.split() ignores
    shell quoting, so a quoted scanner word (`DB="a nmap" mysql -p<pass>`) or a
    separator inside quotes (`mysql -e "select 1; nmap" -p<pass>`) would be
    mis-read as a command/segment. We do NOT build a shell tokenizer; a quote
    means we cannot safely confirm a scanner, so we return False (mask the -p
    value). This over-masks a legitimately-quoted scanner command, which is an
    acceptable fail-safe for a redactor.
    """
    if '"' in segment or "'" in segment:
        return False
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
