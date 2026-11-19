"""Tests for siem_enricher.py.  Run:  python -m pytest -q test_siem_enricher.py

No network needed: VirusTotal is faked at the HTTP layer with real urllib
HTTPError/URLError objects, so the retry and error paths run exactly as they
would against the real API.
"""

import builtins
import io
import json
import os
import threading
import time
import urllib.error

try:
    import pytest
except ImportError:
    raise SystemExit(
        "pytest is not installed. Install it with:\n"
        "    python -m pip install pytest\n"
        "(In an IDE, run that in the IDE's own terminal so it goes into the same Python.)\n"
        "Note: pytest is only needed for these tests - siem_enricher.py itself needs nothing extra."
    )

sys_path_dir = os.path.dirname(os.path.abspath(__file__))
if sys_path_dir not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path_dir)  # find siem_enricher.py when run from another folder

import siem_enricher as se


# ----------------------------------------------------------------------------- helpers

def vt_body(mal=12, sus=1, harmless=50, undetected=31, country="RU", owner="Evil Hosting"):
    return {"data": {"id": "x", "type": "ip_address", "attributes": {
        "last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": harmless,
                                "undetected": undetected, "timeout": 0},
        "last_analysis_results": {
            "Fortinet": {"category": "malicious", "result": "malware"},
            "ESET": {"category": "malicious", "result": "malicious"},
            "Google Safebrowsing": {"category": "harmless", "result": "clean"},
        },
        "last_analysis_date": 1763500000, "reputation": -42, "country": country,
        "as_owner": owner, "asn": 64500, "network": "45.155.205.0/24", "tags": ["scanner"],
    }}}


class FakeResp:
    def __init__(self, body):
        self._data = json.dumps(body).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, err_code="", message=""):
    body = json.dumps({"error": {"code": err_code, "message": message}}).encode()
    return urllib.error.HTTPError("https://www.virustotal.com", code, "err", {}, io.BytesIO(body))


class FakeOpener:
    """Pops one scripted outcome per request: a dict (200 body) or an exception."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def __call__(self, req, timeout=None, context=None):
        self.requests.append(req)
        out = self.outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        return FakeResp(out)


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture
def cfg(tmp_path):
    return se.Config(api_key="k" * 64, out_dir=str(tmp_path / "out"), rate_per_min=0)


def make_enricher(cfg, *outcomes, clock=None):
    opener = FakeOpener(*outcomes)
    clock = clock or FakeClock()
    e = se.Enricher(cfg, opener=opener, sleeper=clock.sleep, backoff_sleeper=lambda s: None, clock=clock)
    return e, opener


def feed_input(monkeypatch, answers):
    it = iter(answers)

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    monkeypatch.setattr(builtins, "input", fake_input)


SAMPLE_LINE = ("2026-11-18T21:04:11Z | sev=HIGH | device=fw-edge-01 | event=SSH brute force | "
               "src_ip=45.155.205.233 | dst_ip=10.0.20.15 | dst_port=22 | action=allowed | msg=37 failed logins")


# ----------------------------------------------------------------------------- parsing

def test_parse_known_format():
    ev = se.parse_line(SAMPLE_LINE, 7)
    assert ev.known_format and ev.line_no == 7
    assert ev.timestamp == "2026-11-18T21:04:11Z"
    assert ev.severity == "HIGH" and ev.name == "SSH brute force"
    assert ev.fields["dst_port"] == "22"
    assert [(r.ip, r.role, r.public) for r in ev.ips] == [
        ("45.155.205.233", "src", True), ("10.0.20.15", "dst", False)]
    assert ev.public_ips == ["45.155.205.233"]


def test_parse_syslog_and_freeform():
    ev = se.parse_line("Nov 18 21:04:11 web01 sshd[22]: Failed password for root from 194.26.29.113 port 5 ssh2", 1)
    assert ev.timestamp == "Nov 18 21:04:11"
    assert ev.public_ips == ["194.26.29.113"]
    assert ev.ips[0].role == "other"
    ev2 = se.parse_line("garbage <<< 77.247.181.162:51515 >>>", 2)
    assert ev2.public_ips == ["77.247.181.162"]


def test_parse_space_kv():
    ev = se.parse_line('2026-11-18 21:04:11 action=deny src=185.220.101.4 dst=10.1.1.1 msg="port scan"', 1)
    assert ev.known_format
    assert ev.fields["msg"] == "port scan"
    assert ev.ips[0].ip == "185.220.101.4" and ev.ips[0].role == "src"


def test_custom_pattern():
    import re
    pat = re.compile(r"^(?P<timestamp>\S+) (?P<event>.+?) from (?P<attacker_ip>[\d.]+)")
    ev = se.parse_line("2026-11-18T01:00:00Z Brute force from 45.155.205.233 detected", 1, pat)
    assert ev.known_format and ev.name == "Brute force"
    assert ev.ips[0].role == "src"  # attacker_ip is treated as a source key


def test_skips_comments_and_blank():
    assert se.parse_line("   ", 1) is None
    assert se.parse_line("# comment 8.8.8.8", 1) is None


def test_ip_extraction_edge_cases():
    assert se.find_ips("999.1.1.1 and 1.2.3.4.5 and v10.0.0.1x") == []
    assert se.find_ips("ends with 8.8.8.8.") == ["8.8.8.8"]
    assert se.find_ips("at 21:04:11 from 2606:4700:4700:0::1111") == ["2606:4700:4700::1111"]
    assert se.find_ips("[2001:db8::1]:443") == ["2001:db8::1"]


def test_public_ip_classification():
    assert se.is_public_ip("8.8.8.8")
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1", "169.254.1.1", "100.64.0.1",
               "203.0.113.5", "224.0.0.1", "::1", "fe80::1", "not-an-ip"):
        assert not se.is_public_ip(ip), ip
    assert se.is_public_ip("::ffff:8.8.8.8")


def test_severity_rank():
    assert se.severity_rank("critical") > se.severity_rank("HIGH") > se.severity_rank("medium")
    assert se.severity_rank("12") == 5 and se.severity_rank("3") == 2 and se.severity_rank("??") == 0


def test_read_events_encodings(tmp_path):
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        p = tmp_path / ("log_" + enc)
        p.write_text("# header\n" + SAMPLE_LINE + "\n\nno ip here\n", encoding=enc)
        events, lines = se.read_events(str(p))
        assert lines == 2 and events[0].public_ips == ["45.155.205.233"], enc


def test_sample_log_is_parseable(tmp_path):
    p = se.make_sample_log(str(tmp_path / "s.log"), events=60, seed=1)
    events, _ = se.read_events(p)
    assert len(events) == 62  # 60 + 2 off-format lines
    assert sum(1 for e in events if e.known_format) >= 60
    assert len({ip for e in events for ip in e.public_ips}) >= 6


# ----------------------------------------------------------------------------- verdicts

def test_score_verdict():
    assert se.score_verdict({"malicious": 3, "harmless": 50}) == "MALICIOUS"
    assert se.score_verdict({"malicious": 1, "harmless": 50}) == "SUSPICIOUS"
    assert se.score_verdict({"suspicious": 2, "harmless": 50}) == "SUSPICIOUS"
    assert se.score_verdict({"harmless": 60, "undetected": 30}) == "CLEAN"
    assert se.score_verdict({}) == "UNKNOWN"
    assert se.score_verdict({"malicious": 3}, threshold=5) == "SUSPICIOUS"


def test_parse_vt_ip():
    i = se.parse_vt_ip("45.155.205.233", vt_body(), 3)
    assert i.verdict == "MALICIOUS" and i.detections == "12/94"
    assert i.country == "RU" and i.as_owner == "Evil Hosting" and i.asn == 64500
    assert i.flagged_by == ["ESET: malicious", "Fortinet: malware"]
    assert i.last_analysis.startswith("2025-")
    assert i.to_dict()["vt_link"].endswith("/ip-address/45.155.205.233")


# ----------------------------------------------------------------------------- enrichment

def test_lookup_success_and_cache(cfg):
    e, opener = make_enricher(cfg, vt_body())
    i = e.lookup("45.155.205.233")
    assert i.verdict == "MALICIOUS" and i.source == "live"
    req = opener.requests[0]
    assert req.full_url.endswith("/ip_addresses/45.155.205.233")
    assert req.get_header("X-apikey") == "k" * 64
    assert os.path.exists(cfg.cache_path)
    # brand-new process: served from disk cache, no HTTP request
    e2, opener2 = make_enricher(cfg)
    i2 = e2.lookup("45.155.205.233")
    assert i2.source == "cache" and i2.detections == "12/94" and opener2.requests == []


def test_cache_respects_threshold_change(cfg):
    e, _ = make_enricher(cfg, vt_body(mal=4))
    assert e.lookup("45.155.205.233").verdict == "MALICIOUS"
    cfg.threshold = 10
    assert e.lookup("45.155.205.233").verdict == "SUSPICIOUS"


def test_cache_expiry(cfg):
    e, _ = make_enricher(cfg, vt_body())
    e.lookup("45.155.205.233")
    data = json.load(open(cfg.cache_path))
    data["45.155.205.233"]["fetched"] = time.time() - 48 * 3600
    json.dump(data, open(cfg.cache_path, "w"))
    e2, opener2 = make_enricher(cfg, vt_body(mal=0))
    assert e2.lookup("45.155.205.233").verdict == "CLEAN" and len(opener2.requests) == 1


def test_404_unknown(cfg):
    e, _ = make_enricher(cfg, http_error(404, "NotFoundError"))
    assert e.lookup("45.155.205.233").verdict == "UNKNOWN"


def test_bad_key_stops_further_calls(cfg):
    e, opener = make_enricher(cfg, http_error(401, "WrongCredentialsError"))
    assert e.lookup("45.155.205.233").verdict == "ERROR"
    i = e.lookup("185.220.101.4")
    assert i.verdict == "ERROR" and "API key" in i.error and len(opener.requests) == 1
    e.reset_auth()  # e.g. user entered a new key in Settings
    opener.outcomes.append(vt_body())
    assert e.lookup("185.220.101.4").verdict == "MALICIOUS"


def test_rate_limit_429_retry_then_success(cfg):
    e, opener = make_enricher(cfg, http_error(429, "QuotaExceededError"), vt_body())
    assert e.lookup("45.155.205.233").verdict == "MALICIOUS" and len(opener.requests) == 2


def test_quota_exhausted(cfg):
    e, opener = make_enricher(cfg, *[http_error(429, "QuotaExceededError")] * 4)
    i = e.lookup("45.155.205.233")
    assert i.verdict == "ERROR" and "quota" in i.error.lower()
    assert e.lookup("1.2.3.4").verdict == "ERROR" and len(opener.requests) == 4


def test_server_error_retry(cfg):
    e, _ = make_enricher(cfg, http_error(503), vt_body())
    assert e.lookup("45.155.205.233").verdict == "MALICIOUS"


def test_network_down_pauses_and_refunds_quota(cfg):
    cfg.rate_per_min = 4
    clock = FakeClock()
    down = urllib.error.URLError("unreachable")
    e, opener = make_enricher(cfg, down, down, down, down, clock=clock)
    i = e.lookup("45.155.205.233")
    assert i.verdict == "ERROR" and e.api_calls == 0
    assert e.limiter.seconds_until_free() == 0  # failed attempts didn't eat the 4/min budget
    assert e.lookup("185.220.101.4").verdict == "ERROR" and len(opener.requests) == 4  # paused, no call
    clock.t += se.Enricher.NETWORK_PAUSE_S + 1
    opener.outcomes.append(vt_body())
    assert e.lookup("185.220.101.4").verdict == "MALICIOUS"


def test_errors_are_not_cached(cfg):
    e, opener = make_enricher(cfg, http_error(400, "BadRequestError", "bad"), vt_body())
    assert e.lookup("45.155.205.233").verdict == "ERROR"
    assert e.lookup("45.155.205.233").verdict == "MALICIOUS"


def test_private_invalid_and_no_key(cfg):
    e, opener = make_enricher(cfg)
    assert e.lookup("10.0.0.5").verdict == "INTERNAL"
    assert e.lookup("nope").verdict == "ERROR"
    cfg.api_key = ""
    assert e.lookup("8.8.8.8").verdict == "UNKNOWN"
    assert opener.requests == []


def test_mock_mode_no_network(cfg):
    cfg.mock = True
    e, opener = make_enricher(cfg)
    assert e.lookup("185.220.101.4").verdict == "MALICIOUS"
    assert e.lookup("8.8.8.8").verdict == "CLEAN"
    assert e.lookup("80.94.95.115").verdict == "UNKNOWN"
    a, b = e.lookup("203.0.114.9"), se.mock_intel("203.0.114.9", 3)
    assert a.verdict == b.verdict and a.source == "mock"
    assert opener.requests == [] and not os.path.exists(cfg.cache_path)


def test_rate_limiter_paces():
    clock = FakeClock()
    rl = se.RateLimiter(2, clock=clock, sleeper=clock.sleep)
    rl.wait(); rl.wait()
    start = clock.t
    rl.wait()
    assert 59 < clock.t - start <= 60.5


# ----------------------------------------------------------------------------- firewall

def test_contain_release_and_audit(cfg):
    fw = se.Firewall(cfg)
    intel = se.parse_vt_ip("45.155.205.233", vt_body(), 3)
    assert fw.contain("45.155.205.233", intel, "brute force", "alice") == (True, "45.155.205.233 written to firewall blocklist")
    ok, msg = fw.contain("45.155.205.233")
    assert not ok and "already" in msg
    assert fw.blocked() == ["45.155.205.233"]
    rows = fw.audit_rows()
    assert rows[0]["action"] == "CONTAIN" and rows[0]["verdict"] == "MALICIOUS" and rows[0]["analyst"] == "alice"
    assert fw.release("45.155.205.233", "false positive")[0]
    assert fw.blocked() == [] and fw.audit_rows()[-1]["action"] == "RELEASE"
    assert open(cfg.blocklist_path).read().startswith("# SIMULATED")  # header kept
    assert not fw.release("45.155.205.233")[0]


def test_allowlist_cidr_and_private_rules(cfg):
    fw = se.Firewall(cfg)
    assert "allowlist" in fw.contain("8.8.8.8")[1]
    with open(cfg.allowlist_path, "a") as fh:
        fh.write("140.82.112.0/20   # GitHub\n")
    assert not fw.contain("140.82.112.3")[0]
    ok, msg = fw.contain("10.0.0.5")
    assert not ok and "private" in msg
    assert fw.contain("10.0.0.5", force=True)[0]
    cfg.allow_private = True
    assert fw.contain("192.168.1.9")[0]
    assert not fw.contain("not.an.ip")[0]


def test_manual_edits_and_ipv6(cfg):
    fw = se.Firewall(cfg)
    with open(cfg.blocklist_path, "a") as fh:
        fh.write("185.220.101.4   # added by hand\ngarbage line\n45.155.205.233")  # no trailing newline
    assert fw.blocked() == ["185.220.101.4", "45.155.205.233"]
    assert fw.contain("2606:4700:4700:0:0:0:0:1001")[0]
    content = open(cfg.blocklist_path).read()
    assert "45.155.205.233\n2606:4700:4700::1001\n" in content
    assert fw.is_blocked("2606:4700:4700::1001")
    assert fw.release("185.220.101.4")[0]
    assert "garbage line" in open(cfg.blocklist_path).read()


# ----------------------------------------------------------------------------- app

@pytest.fixture
def mock_app(cfg):
    cfg.mock = True
    return se.App(cfg)


def test_analyze_auto_contain_no_prompt(mock_app, tmp_path):
    mock_app.cfg.auto_contain = "malicious"
    mock_app.cfg.prompt = False
    log = se.make_sample_log(str(tmp_path / "s.log"), seed=7)
    res = mock_app.analyze_file(log)
    blocked = set(mock_app.fw.blocked())
    mal = {ip for ip, i in res["intel"].items() if i.verdict == "MALICIOUS"}
    assert mal and mal <= blocked
    assert "8.8.8.8" not in blocked and "1.1.1.1" not in blocked
    assert res["malicious_uncontained"] == []
    recs = [json.loads(l) for l in open(mock_app.cfg.enriched_path)]
    assert len(recs) == 42 and any(r["overall_verdict"] == "MALICIOUS" for r in recs)
    # second run: everything already contained, nothing new
    mock_app.contained_this_session.clear()
    mock_app.analyze_file(log)
    assert mock_app.contained_this_session == []


def test_analyze_interactive_bulk_and_manual(mock_app, tmp_path, monkeypatch):
    log = se.make_sample_log(str(tmp_path / "s.log"), seed=7)
    # 'a' = contain all malicious; then answer n to remaining non-malicious ones; then
    # manually contain a CLEAN IP from the log with a custom reason; then finish.
    feed_input(monkeypatch, ["a"] + ["n"] * 5 + ["140.82.112.3", "VPN abuse", ""])
    res = mock_app.analyze_file(log)
    blocked = set(mock_app.fw.blocked())
    assert {ip for ip, i in res["intel"].items() if i.verdict == "MALICIOUS"} <= blocked
    assert "140.82.112.3" in blocked
    assert any(r["reason"] == "VPN abuse" for r in mock_app.fw.audit_rows())


def test_analyze_handles_eof_safely(mock_app, tmp_path, monkeypatch):
    log = se.make_sample_log(str(tmp_path / "s.log"), seed=7)
    feed_input(monkeypatch, [])  # stdin closed immediately
    mock_app.analyze_file(log)
    assert mock_app.fw.blocked() == []  # nothing blocked without consent


def test_live_mode_auto_contain_and_fw_drop(mock_app, tmp_path):
    mock_app.cfg.auto_contain = "malicious"
    mock_app.cfg.prompt = False
    log = tmp_path / "live.log"
    log.write_text("# old content\n" + SAMPLE_LINE + "\n")
    stop = threading.Event()
    result = {}
    t = threading.Thread(target=lambda: result.update(
        mock_app.follow_file(str(log), stop_event=stop, max_events=3, poll=0.02)))
    t.start()
    time.sleep(0.3)
    with open(log, "a") as fh:
        fh.write(SAMPLE_LINE.replace("45.155.205.233", "185.220.101.4") + "\n")
        fh.write("2026-11-18T21:05:00Z | sev=HIGH | event=RDP br")  # partial write...
        fh.flush()
        time.sleep(0.2)
        fh.write("ute force | src_ip=185.220.101.4 | dst_ip=10.0.0.9\n")  # ...completed later
        fh.write("2026-11-18T21:05:01Z | sev=INFO | event=DNS query | src_ip=10.0.0.9 | dst_ip=8.8.8.8\n")
    t.join(5)
    stop.set()
    assert not t.is_alive()
    assert result == {"events": 3, "with_external_ip": 3, "dropped": 1, "malicious_uncontained": []}
    assert mock_app.fw.blocked() == ["185.220.101.4"]  # pre-existing line was skipped (not from_start)


def test_live_prompt_contain(mock_app, monkeypatch):
    feed_input(monkeypatch, ["d", "y", "live reason"])
    ev = se.parse_line(SAMPLE_LINE, 1)
    decided = set()
    mock_app.handle_live_event(ev, decided, "x.log")
    assert mock_app.fw.blocked() == ["45.155.205.233"]
    assert mock_app.fw.audit_rows()[-1]["reason"] == "live reason"
    assert mock_app.handle_live_event(ev, decided, "x.log") == 1  # now dropped by FW, no new prompt


def test_tail_handles_truncation(tmp_path):
    p = tmp_path / "t.log"
    p.write_text("")
    stop = threading.Event()
    got = []

    def run():
        for n, line in se.tail_lines(str(p), poll=0.02, stop_event=stop):
            got.append(line)

    t = threading.Thread(target=run)
    t.start()
    time.sleep(0.1)
    with open(p, "a") as fh:
        fh.write("one long first line here\n")
    time.sleep(0.2)
    p.write_text("two\n")  # truncated + rewritten (log rotation)
    time.sleep(0.3)
    stop.set()
    t.join(2)
    assert got == ["one long first line here", "two"]


def test_feed_simulator_writes_valid_events(tmp_path):
    p = tmp_path / "sim.log"
    sim = se.FeedSimulator(str(p), 0.01, 0.02, seed=3)
    sim.start()
    time.sleep(0.3)
    sim.halt()
    sim.join(1)
    events, n = se.read_events(str(p))
    assert n >= 5 and all(e.known_format for e in events)


# ----------------------------------------------------------------------------- CLI + menu

def test_cli_commands(tmp_path, capsys):
    out = str(tmp_path / "o")
    assert se.main(["--mock", "--out-dir", out, "--contain", "45.155.205.233", "10.0.0.1",
                    "--reason", "test", "--no-color"]) == 0
    text = capsys.readouterr().out
    assert "CONTAINED" in text and "private/internal" in text
    assert se.main(["--out-dir", out, "--list", "--no-color"]) == 0
    assert "45.155.205.233" in capsys.readouterr().out
    assert se.main(["--out-dir", out, "--release", "45.155.205.233", "--no-color"]) == 0
    assert "RELEASED" in capsys.readouterr().out
    log = se.make_sample_log(str(tmp_path / "s.log"))
    assert se.main([log, "--mock", "--no-prompt", "--out-dir", out, "--no-color"]) == 2  # malicious left open
    assert se.main([log, "--mock", "--no-prompt", "--auto-contain", "malicious", "--out-dir", out]) == 0


def test_cli_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(se, "load_key_from_dotenv", lambda: "")
    out = str(tmp_path / "o")
    log = se.make_sample_log(str(tmp_path / "s.log"))
    assert se.main([log, "--no-prompt", "--out-dir", out]) == 1                  # no key
    assert se.main([str(tmp_path / "missing.log"), "--mock", "--out-dir", out]) == 1
    assert se.main([log, "--mock", "--pattern", "(unclosed", "--out-dir", out]) == 1


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Tests must behave the same on a laptop and inside the Docker image."""
    for var in ("SIEM_DOTENV", "SIEM_OUT_DIR", "SIEM_NO_GUI", "VT_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def test_container_env_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_OUT_DIR", str(tmp_path / "data_out"))
    monkeypatch.setenv("SIEM_DOTENV", str(tmp_path / "data.env"))
    assert se.Config().out_dir == str(tmp_path / "data_out")
    se.save_key_to_dotenv("abc123")
    assert (tmp_path / "data.env").read_text() == "VT_API_KEY=abc123\n"
    assert se.load_key_from_dotenv() == "abc123"


def test_menu_without_gui(cfg, monkeypatch, capsys):
    monkeypatch.setenv("SIEM_NO_GUI", "1")
    cfg.mock = True
    feed_input(monkeypatch, ["1", "", "0"])  # Enter at the path prompt must not try to open a window
    se.Menu(se.App(cfg)).run()
    assert "Type the path" in capsys.readouterr().out


def test_dotenv_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "SCRIPT_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("OTHER=1\nVT_API_KEY=old\n")
    se.save_key_to_dotenv("newkey")
    assert (tmp_path / ".env").read_text() == "OTHER=1\nVT_API_KEY=newkey\n"
    assert se.load_key_from_dotenv() == "newkey"


def test_menu_full_tour(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(se, "SCRIPT_DIR", str(tmp_path))
    cfg = se.Config(api_key="", out_dir=str(tmp_path / "o"))
    app = se.App(cfg)
    sample = str(tmp_path / "menu.log")
    feed_input(monkeypatch, [
        "2",                                  # no key -> mock mode
        "7", sample,                          # create sample log
        "1", "l", "q", "",                    # analyze last log, quit review immediately
        "3", "45.155.205.233", "",            # contain manually, default reason
        "3", "10.0.0.7", "", "y",             # internal IP -> refused -> force
        "6", "185.220.101.4", "y", "",        # lookup + contain
        "4", "10.0.0.7", "",                  # release
        "5",                                  # show blocklist
        "8", "3", "5", "4", "m", "0",         # settings: threshold 5, auto-contain malicious
        "9",                                  # invalid option
        "0",
    ])
    se.Menu(app).run()
    out = capsys.readouterr().out
    assert os.path.exists(sample)
    assert app.fw.blocked() == ["45.155.205.233", "185.220.101.4"]
    assert cfg.threshold == 5 and cfg.auto_contain == "malicious" and cfg.mock
    assert "Unknown option" in out and "Bye." in out


def test_menu_exits_on_eof(cfg, monkeypatch):
    cfg.mock = True
    feed_input(monkeypatch, [])
    se.Menu(se.App(cfg)).run()  # must not raise


if __name__ == "__main__":
    # Lets you press "Run" on this file in any IDE, or use: python test_siem_enricher.py
    import sys
    sys.exit(pytest.main([os.path.abspath(__file__), "-v"]))
