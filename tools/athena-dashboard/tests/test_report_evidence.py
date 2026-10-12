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
    for s in ["password=s3cret", "passwd: s3cret", "pwd=s3cret", "api_key = abcdef123456",
              "token: abcdef123456", "secret=longsecretvalue"]:
        out = sm.mask_text(s)
        assert "s3cret" not in out and "abcdef123456" not in out and "longsecretvalue" not in out


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
