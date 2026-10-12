import secret_mask as sm


def test_literal_masking():
    out = sm.mask_text("login with Hunter2!! here", literals=["Hunter2!!"])
    assert "Hunter2!!" not in out and sm.MASK in out


def test_literal_mask_ignores_short_and_escapes_special():
    # short literal not masked everywhere (would shred normal text)
    assert sm.mask_text("a cat sat", literals=["a"]) == "a cat sat"
    # regex-special literal is masked literally, no error
    out = sm.mask_text("pw=p@ss.*(x end", literals=["p@ss.*(x"])
    assert "p@ss.*(x" not in out


def test_pattern_kv():
    cases = {
        "password=s3cret": "password=********",
        "passwd: s3cret": "passwd: ********",
        "pwd=s3cret": "pwd=********",
        "api_key = abcdef123456": "api_key = ********",
        "token: abcdef123456": "token: ********",
        "secret=longsecretvalue": "secret=********",
    }
    for src, expected in cases.items():
        out = sm.mask_text(src)
        assert sm.MASK in out
        assert out == expected


def test_pattern_flags_and_urls():
    assert "s3cret" not in sm.mask_text("hydra -p s3cretvalue -l admin")
    assert "s3cret" not in sm.mask_text("mysql -u root:s3cretvalue@host")
    assert "s3cret" not in sm.mask_text("curl https://user:s3cretvalue@host/path")
    assert "s3cret" not in sm.mask_text("smbclient -Uuser%s3cretvalue //host")


def test_pattern_hash_pair():
    h = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    assert h not in sm.mask_text(f"found {h} in dump")


def test_mask_input_copies():
    src = {"command": "psql password=s3cretvalue", "n": 5}
    out = sm.mask_input(src)
    assert "s3cretvalue" not in out["command"] and out["n"] == 5 and "s3cretvalue" in src["command"]


def test_username_preserved():
    out = sm.mask_text("mysql -u admin:s3cretvalue@h")
    assert "admin" in out
    assert "s3cretvalue" not in out and sm.MASK in out
    assert out == "mysql -u admin:********@h"


def test_p_attached_masked():
    assert sm.mask_text("mysql -pMyPassword db") == "mysql -p******** db"


def test_numeric_p_password_masked_without_scanner():
    assert sm.mask_text("mysql -p123456") == "mysql -p********"
    assert sm.mask_text("mysql -p12345 db") == "mysql -p******** db"
    assert sm.mask_text("mysql -p 123456 db") == "mysql -p ******** db"
    # bare port-looking value with no scanner named fails safe (masked)
    assert sm.mask_text("tool -p 80,443") == "tool -p ********"


def test_port_lists_preserved_for_scanners():
    for cmd in ["nmap -p 80,443 host", "nmap -p22 host", "nmap -p 22-25,80 host",
                "masscan -p1-1000 10.0.0.0/8", "NMAP -p- host", "rustscan -a h -p 1-65535"]:
        assert sm.mask_text(cmd) == cmd
    # scanner present but non-numeric -p value is still masked
    assert sm.mask_text("nmap -p MyPassword host") == "nmap -p ******** host"


def test_scanner_word_elsewhere_does_not_exempt():
    assert sm.mask_text("mysql -p123456 -h nmap.example.com") == "mysql -p******** -h nmap.example.com"
    assert sm.mask_text("echo nmap; mysql -p123456") == "echo nmap; mysql -p********"
    assert sm.mask_text("NMAP=1 mysql -p123456") == "NMAP=1 mysql -p********"


def test_scanner_exemption_is_per_segment():
    assert sm.mask_text("nmap -sV -p 80 h && mysql -p123456") == "nmap -sV -p 80 h && mysql -p********"
    assert sm.mask_text("mysql -p123456 && nmap -p 80 h") == "mysql -p******** && nmap -p 80 h"
    assert sm.mask_text("mysql -p123456 | nmap -p 80 h") == "mysql -p******** | nmap -p 80 h"
    assert sm.mask_text("nmap -p 80 h\nmysql -p123456") == "nmap -p 80 h\nmysql -p********"


def test_scanner_invocation_forms_preserved():
    for cmd in ["nmap -p 80,443", "nmap -p22", "masscan -p1-1000", "/usr/bin/nmap -p 1-1000",
                "rustscan -p 1-65535", "FOO=1 nmap -p 80 h"]:
        assert sm.mask_text(cmd) == cmd
