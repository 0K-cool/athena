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


def test_wrapper_prefixed_scanners_preserved():
    for cmd in ["sudo nmap -p 80 h", "sudo nmap -p 80,443", "time nmap -p22",
                "env nmap -p 1-100", "nohup nmap -p-", "env FOO=1 nmap -p 80 h",
                "sudo env nmap -p 80 h"]:
        assert sm.mask_text(cmd) == cmd


def test_wrapper_prefixed_non_scanners_masked():
    assert sm.mask_text("sudo mysql -p123456") == "sudo mysql -p********"
    assert sm.mask_text("sudo -u root mysql -p123456") == "sudo -u root mysql -p********"
    assert sm.mask_text("time mysql -p123456") == "time mysql -p********"


def test_wrapper_flag_argument_named_scanner_does_not_exempt():
    # -u/-n argument is literally a scanner NAME; mysql is the real command.
    # The password MUST be masked (the under-masking leak this fix closes).
    assert sm.mask_text("sudo -u nmap mysql -p123456") == "sudo -u nmap mysql -p********"
    assert sm.mask_text("env -u nmap mysql -p123456") == "env -u nmap mysql -p********"
    assert sm.mask_text("nice -n nmap mysql -p123456") == "nice -n nmap mysql -p********"
    assert sm.mask_text("sudo -u nmap mysql -p123456 | cat") == "sudo -u nmap mysql -p******** | cat"


def test_wrapper_then_command_word_still_resolves_scanner():
    # A wrapper DIRECTLY followed by the command word (no intervening flags)
    # still resolves to the scanner -> port list preserved (no regression).
    for cmd in ["nmap -p 80,443", "nmap -p22", "masscan -p1-1000", "/usr/bin/nmap -p 1-1000",
                "rustscan -p 1-65535", "sudo nmap -p 80 h", "sudo nmap -p 80,443",
                "time nmap -p22", "env nmap -p 1-100", "nohup nmap -p-", "sudo env nmap -p 80"]:
        assert sm.mask_text(cmd) == cmd


def test_quoted_scanner_word_does_not_exempt():
    # str.split() ignores shell quoting: a scanner name inside quotes, or a
    # separator inside quotes, must NOT exempt the -p value (fail safe: any
    # quote in the segment forces masking).
    assert sm.mask_text('DB="a nmap" mysql -p123456') == 'DB="a nmap" mysql -p********'
    assert sm.mask_text("X='x nmap' mysql -p123456") == "X='x nmap' mysql -p********"
    assert sm.mask_text('mysql -e "select 1; nmap" -p123456') == 'mysql -e "select 1; nmap" -p********'
    assert sm.mask_text('mysql -h "x&nmap" -p123456') == 'mysql -h "x&nmap" -p********'


# ---- Task 8: appendix, report-data evidence, masked credentials, snapshot, CLI ----
import json

import command_log as cl
import command_log_report as clr
import finding_links as fl
import pytest


@pytest.fixture
def seeded(tmp_path):
    d = tmp_path / "eng-rep" / "08-evidence"
    log = cl.CommandLog(d, "eng-rep")
    s = log.append_start(agent="WV", backend="host", tool="Bash", tool_use_id="t1",
                         input={"command": "mysql -u root:S3cretPass@10.0.0.1"})
    log.append_complete(start_seq=s["seq"], output="connected as root", is_error=False)
    return d, log


def test_finding_evidence_masks_input(seeded):
    d, log = seeded
    links = fl._link_rows(log, [2], "cited")
    ev = clr.finding_evidence(log, links)
    assert ev[0]["seq"] == 2 and ev[0]["entry_hash"] == log.get(2)["entry_hash"]
    assert "S3cretPass" not in ev[0]["input_summary"]
    assert ev[0]["output_sha256"] == log.get(2)["output_sha256"]


def test_appendix_is_deterministic(seeded):
    d, log = seeded
    findings = [{"id": "f1", "title": "SQLi", "severity": "high",
                 "links": fl._link_rows(log, [2], "cited")}]
    a = clr.render_appendix(d, engagement_id="eng-rep", findings=findings)
    b = clr.render_appendix(d, engagement_id="eng-rep", findings=findings)
    assert a == b
    assert "S3cretPass" not in a
    assert "eng-rep" in a and log.head()["entry_hash"] in a


def test_appendix_flags_unsupported_high(seeded):
    d, log = seeded
    findings = [{"id": "f9", "title": "Unproven RCE", "severity": "critical", "links": []}]
    a = clr.render_appendix(d, engagement_id="eng-rep", findings=findings)
    assert "Unsupported" in a


def test_summary(seeded):
    d, log = seeded
    s = clr.command_log_summary(d)
    assert s["verify_status"] == "ok" and s["head_seq"] == 2 and s["entry_count"] == 2


def test_cli_matches_api(seeded, tmp_path):
    import subprocess, sys
    from pathlib import Path
    d, log = seeded
    out = subprocess.run([sys.executable, "verify_command_log.py", str(d)],
                         capture_output=True, text=True,
                         cwd=str(Path(__file__).resolve().parent.parent))
    assert out.returncode == 0
    assert json.loads(out.stdout)["status"] == cl.verify(d)["status"]


def test_cli_exit_2_on_broken(seeded):
    import subprocess, sys
    from pathlib import Path
    d, log = seeded
    p = d / cl.LOG_NAME
    p.write_bytes(p.read_bytes().replace(b'"seq": 1', b'"seq": 7', 1) if b'"seq": 1' in p.read_bytes()
                  else p.read_bytes()[:-5] + b"xxxx\n")
    out = subprocess.run([sys.executable, "verify_command_log.py", str(d)],
                         capture_output=True, text=True,
                         cwd=str(Path(__file__).resolve().parent.parent))
    assert out.returncode == 2


@pytest.mark.asyncio
async def test_report_data_has_evidence_and_log_block(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-rd", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {"command": "sqlmap"}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-rd", "start_seq": 1, "output": "injectable", "is_error": False})
    await client.post("/api/findings", json={
        "title": "SQL injection here", "severity": "high", "category": "injection",
        "target": "10.0.0.1", "agent": "WV", "description": "x", "engagement": "eng-rd",
        "evidence_seqs": [2]})
    rd = (await client.get("/api/engagements/eng-rd/report-data")).json()
    assert rd["command_log"]["verify_status"] in ("ok", "ok_with_gaps")
    assert rd["command_log"]["head_seq"] == 2
    findings = [f for h in rd["findings_by_host"].values() for f in h["findings"]]
    assert findings and findings[0]["evidence"][0]["seq"] == 2
    assert "output" not in findings[0]["evidence"][0]


@pytest.mark.asyncio
async def test_report_data_masks_credentials(client, tmp_path, monkeypatch):
    import secret_mask as sm
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    rd = (await client.get("/api/engagements/eng-empty/report-data")).json()
    for c in rd.get("credentials", []):
        assert c.get("password") in (None, "", sm.MASK)  # never a plaintext value


@pytest.mark.asyncio
async def test_reports_snapshot_is_server_computed(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-rpt", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-rpt", "start_seq": 1, "output": "x", "is_error": False})
    r = await client.post("/api/reports", json={
        "engagement_id": "eng-rpt", "type": "technical", "title": "T",
        "command_log_head": {"seq": 999, "entry_hash": "FORGED"}})
    rid = r.json()["report_id"]
    listing = (await client.get("/api/reports?engagement=eng-rpt")).json()
    reports = listing.get("reports", listing) if isinstance(listing, dict) else listing
    rep = next(x for x in reports if x["id"] == rid)
    assert rep["command_log_head"]["seq"] == 2 and rep["command_log_head"]["entry_hash"] != "FORGED"
    assert rep["command_log_head"]["verify_status"] == "ok"


@pytest.mark.asyncio
async def test_appendix_route(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-app", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {"command": "x"}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-app", "start_seq": 1, "output": "y", "is_error": False})
    r = await client.get("/api/engagements/eng-app/command-log/appendix")
    assert r.status_code == 200
    assert "## Integrity" in r.json()["appendix_md"]
    bad = await client.get("/api/engagements/..%2Fx/command-log/appendix")
    assert bad.status_code in (400, 404, 422)


# ---- Task 8 fix round 1 ----
def test_input_summary_masks_password_field(tmp_path):
    d = tmp_path / "eng-k" / "08-evidence"
    log = cl.CommandLog(d, "eng-k")
    s = log.append_start(agent="EX", backend="host", tool="login", tool_use_id="t1",
                         input={"host": "10.0.0.1", "username": "admin", "password": "Winter2024!"})
    log.append_complete(start_seq=s["seq"], output="ok", is_error=False)
    ev = clr.finding_evidence(log, fl._link_rows(log, [2], "cited"))
    assert "Winter2024!" not in ev[0]["input_summary"]
    assert "admin" in ev[0]["input_summary"]


def test_literals_mask_input_and_output_excerpt(tmp_path):
    d = tmp_path / "eng-l" / "08-evidence"
    log = cl.CommandLog(d, "eng-l")
    s = log.append_start(agent="EX", backend="host", tool="Bash", tool_use_id="t1",
                         input={"command": "ssh root@h 'echo Zq9-plain-secret'"})
    log.append_complete(start_seq=s["seq"], output="dump: Zq9-plain-secret found", is_error=False)
    links = fl._link_rows(log, [2], "cited")
    ev = clr.finding_evidence(log, links, literals=["Zq9-plain-secret"])
    assert "Zq9-plain-secret" not in ev[0]["input_summary"]
    findings = [{"id": "f", "title": "T", "severity": "high", "links": links}]
    leaked = clr.render_appendix(d, engagement_id="eng-l", findings=findings)
    assert "Zq9-plain-secret" in leaked  # not caught by pattern rules alone
    safe = clr.render_appendix(d, engagement_id="eng-l", findings=findings,
                               literals=["Zq9-plain-secret"])
    assert "Zq9-plain-secret" not in safe


def test_mask_credentials_pure():
    import server
    import secret_mask as sm
    out = server._mask_credentials([
        {"username": "u", "password": "hunter2hunter2", "host": "10.0.0.1", "service": "ssh"},
        {"username": "v", "password": None, "host": "10.0.0.2", "service": "ftp"}])
    assert out[0]["password"] == sm.MASK and out[0]["password_masked"] is True
    assert (out[0]["username"], out[0]["host"], out[0]["service"]) == ("u", "10.0.0.1", "ssh")
    assert out[1]["password"] is None and "password_masked" not in out[1]


@pytest.mark.asyncio
async def test_appendix_route_masks_known_credential_values(client, tmp_path, monkeypatch):
    import server
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-cr", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {"command": "cat /etc/x"}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-cr", "start_seq": 1, "output": "pw is Kq77-vault-value", "is_error": False})
    r = await client.post("/api/findings", json={
        "title": "Credential leak in output", "severity": "high", "category": "injection", "target": "10.0.0.1",
        "agent": "WV", "description": "x", "engagement": "eng-cr", "evidence_seqs": [2]})
    assert r.status_code == 200, r.text
    monkeypatch.setitem(server.state._credentials, "eng-cr",
                        [{"username": "u", "password": "Kq77-vault-value"}])
    md = (await client.get("/api/engagements/eng-cr/command-log/appendix")).json()["appendix_md"]
    assert "Kq77-vault-value" not in md and "seq 2" in md


@pytest.mark.asyncio
async def test_report_data_degrades_not_500_on_corrupt_log(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-bad", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-bad", "start_seq": 1, "output": "x", "is_error": False})
    await client.post("/api/findings", json={
        "title": "F", "severity": "high", "category": "injection", "target": "10.0.0.1",
        "agent": "WV", "description": "x", "engagement": "eng-bad", "evidence_seqs": [2]})

    def boom(self, *a, **k):
        raise ValueError("corrupt")
    monkeypatch.setattr(cl.CommandLog, "entries", boom)
    r = await client.get("/api/engagements/eng-bad/report-data")
    assert r.status_code == 200
    rd = r.json()
    assert rd["command_log"]["verify_status"] in ("ok", "ok_with_gaps", "broken")
    assert all("evidence" not in f for h in rd["findings_by_host"].values() for f in h["findings"])

    # and when verify itself explodes
    def vboom(*a, **k):
        raise ValueError("corrupt")
    monkeypatch.setattr(cl, "verify", vboom)
    r = await client.get("/api/engagements/eng-bad/report-data")
    assert r.status_code == 200 and r.json()["command_log"]["verify_status"] == "broken"


@pytest.mark.asyncio
async def test_report_update_path_refreshes_head_and_attaches_appendix(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)

    async def add(tid):
        s = await client.post("/api/command-log/start", json={
            "engagement_id": "eng-up", "agent": "WV", "backend": "host", "tool": "Bash",
            "tool_use_id": tid, "input": {}})
        await client.post("/api/command-log/complete", json={
            "engagement_id": "eng-up", "start_seq": s.json()["seq"], "output": "x", "is_error": False})
    await add("t1")
    r1 = await client.post("/api/reports", json={"engagement_id": "eng-up", "type": "technical", "title": "T"})
    rid = r1.json()["report_id"]
    await add("t2")
    r2 = await client.post("/api/reports", json={"engagement_id": "eng-up", "type": "Technical Report",
                                                 "title": "T2"})
    assert r2.json().get("updated") is True and r2.json()["report_id"] == rid
    listing = (await client.get("/api/reports?engagement=eng-up")).json()
    reports = listing.get("reports", listing) if isinstance(listing, dict) else listing
    rep = next(x for x in reports if x["id"] == rid)
    assert rep["command_log_head"]["seq"] == 4
    assert "## Integrity" in rep["command_log_appendix_md"]


@pytest.mark.asyncio
async def test_patch_final_refreshes_head(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)
    r1 = await client.post("/api/reports", json={"engagement_id": "eng-pf", "type": "executive", "title": "T"})
    rid = r1.json()["report_id"]
    await client.post("/api/command-log/start", json={
        "engagement_id": "eng-pf", "agent": "WV", "backend": "host", "tool": "Bash",
        "tool_use_id": "t1", "input": {}})
    await client.post("/api/command-log/complete", json={
        "engagement_id": "eng-pf", "start_seq": 1, "output": "x", "is_error": False})
    p = await client.patch(f"/api/reports/{rid}?engagement=eng-pf", json={"status": "final"})
    assert p.status_code == 200
    listing = (await client.get("/api/reports?engagement=eng-pf")).json()
    reports = listing.get("reports", listing) if isinstance(listing, dict) else listing
    assert next(x for x in reports if x["id"] == rid)["command_log_head"]["seq"] == 2


# ---- Task 8 fix round 2: non-bad_eid CommandLogError must fail closed ----
@pytest.mark.asyncio
async def test_report_data_corrupt_code_is_broken_not_ok(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)

    def boom(*a, **k):
        raise cl.CommandLogError("corrupt", "x")
    monkeypatch.setattr(cl, "verify", boom)
    r = await client.get("/api/engagements/eng-co/report-data")
    assert r.status_code == 200
    assert r.json()["command_log"]["verify_status"] == "broken"


@pytest.mark.asyncio
async def test_report_data_corrupt_code_with_working_verify_still_broken(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)

    def boom(self, *a, **k):
        raise cl.CommandLogError("lock_timeout", "x")
    monkeypatch.setattr(cl.CommandLog, "entries", boom)
    r = await client.get("/api/engagements/eng-lt/report-data")
    assert r.status_code == 200
    assert r.json()["command_log"]["verify_status"] == "broken"


@pytest.mark.asyncio
async def test_report_data_bad_eid_stays_ok(client):
    r = await client.get("/api/engagements/bad.eid/report-data")
    assert r.status_code == 200
    assert r.json()["command_log"]["verify_status"] == "ok"


@pytest.mark.asyncio
async def test_create_report_corrupt_code_marks_integrity_broken(client, tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "ENGAGEMENTS_ROOT", tmp_path)

    def boom(*a, **k):
        raise cl.CommandLogError("corrupt", "x")
    monkeypatch.setattr(cl, "verify", boom)
    rid = (await client.post("/api/reports", json={
        "engagement_id": "eng-ci", "type": "technical", "title": "T"})).json()["report_id"]
    listing = (await client.get("/api/reports?engagement=eng-ci")).json()
    reports = listing.get("reports", listing) if isinstance(listing, dict) else listing
    rep = next(x for x in reports if x["id"] == rid)
    assert rep["command_log_head"]["verify_status"] == "broken" and rep["integrity"] == "broken"


@pytest.mark.asyncio
async def test_create_report_bad_eid_stays_clean(client):
    rid = (await client.post("/api/reports", json={
        "engagement_id": "bad.eid", "type": "technical", "title": "T"})).json()["report_id"]
    listing = (await client.get("/api/reports?engagement=bad.eid")).json()
    reports = listing.get("reports", listing) if isinstance(listing, dict) else listing
    rep = next(x for x in reports if x["id"] == rid)
    assert rep["command_log_head"]["verify_status"] == "ok" and "integrity" not in rep
