# SIEM IP Enricher & Containment Simulator

Reads a SIEM log feed, pulls out the IP addresses, enriches each public IP with **VirusTotal** threat intelligence, and lets an analyst **contain** an IP by writing it to a firewall blocklist. Text files stand in for the SIEM feed and the firewall, so the full **detect → enrich → respond** loop runs anywhere.

```
SIEM feed (log file) -> parse -> VirusTotal enrichment -> analyst decision
                                                           |-> firewall_blocklist.txt  (simulated firewall)
                                                           |-> containment_audit.csv   (who / when / why)
```

## Option 1: Docker (everything preinstalled)

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) on Windows/macOS, or Docker Engine on Linux.

```bash
docker compose build                       # first time only (runs the test suite during the build)
docker compose run --rm siem demo          # analyze a sample log with simulated intel (no API key)
docker compose run --rm siem               # interactive menu
docker compose run --rm siem live-demo     # watch a live simulated SIEM feed (Ctrl+C to stop)
docker compose run --rm siem test          # run the 42 tests
```

**Your files live in the `data` folder** next to `docker-compose.yml` (it's mounted at `/data` in the container). Put your log files there and refer to them as `/data/yourfile.log`:

```bash
docker compose run --rm siem /data/firewall.log                         # analyze your own log
docker compose run --rm siem /data/firewall.log --follow                # watch it live
docker compose run --rm siem /data/firewall.log --auto-contain malicious --no-prompt
docker compose run --rm siem --list                                     # show blocklist + audit trail
```

Results appear in `data/siem_output/`: `firewall_blocklist.txt`, `containment_audit.csv`, `enriched_events.jsonl`.

**API key:** get a free one at https://www.virustotal.com/gui/my-apikey, then either
- create a file named `.env` next to `docker-compose.yml` containing `VT_API_KEY=your_key`, or
- paste it when the menu asks and choose to save it (it's stored in `data/.env`).

Never commit either `.env` file; both are in `.gitignore`.

<details><summary>Without Compose (plain <code>docker run</code>)</summary>

```bash
docker build -t siem-enricher .
# PowerShell: use ${PWD}  |  Command Prompt: use %cd%  |  macOS/Linux: use $PWD
docker run --rm -it -v "${PWD}/data:/data" siem-enricher demo
docker run --rm -it -v "${PWD}/data:/data" -e VT_API_KEY=your_key siem-enricher
docker run --rm siem-enricher help
```
</details>

<details><summary>Linux: "/data is not writable"</summary>

The container runs as an unprivileged user (uid 10001). On Linux, either run as yourself:
`docker compose run --rm --user "$(id -u):$(id -g)" siem`, or make the folder writable: `chmod a+rwx data`.
Docker Desktop on Windows/macOS doesn't need this.
</details>

## Option 2: plain Python

Python 3.8+ only, with no packages needed to run it. In an IDE, open `siem_enricher.py` and press **Run**.

```bash
python siem_enricher.py                                   # interactive menu
python siem_enricher.py sample_siem.log --mock            # try without an API key
python siem_enricher.py sample_siem.log                   # live VirusTotal lookups
python siem_enricher.py live.log --follow --simulate --mock
python siem_enricher.py --contain 45.155.205.233 --reason "SSH brute force"
python siem_enricher.py --release 45.155.205.233
```

Tests: `python -m pip install -r requirements-dev.txt`, then `python test_siem_enricher.py`.

## Features

- **Batch analysis**: parse, enrich, triage table, then a containment review (default answer is *no*; nothing is blocked without confirmation).
- **Live mode** (`--follow`): processes new events as they're written, like `tail -f`. Traffic from contained IPs is tagged `[FW DROP]`.
- **Containment safeguards**: an allowlist (`firewall_allowlist.txt`, supports CIDR ranges); internal IPs are refused unless forced; full audit trail; release (unblock) support.
- **SOAR-style automation**: `--auto-contain malicious --no-prompt`. Exit code `2` means malicious IPs were left uncontained.
- **Free-API friendly**: paced to 4 lookups/min with a countdown, a 24h cache, a pause when VirusTotal is unreachable, and failed connections don't count against the quota.
- **Flexible parsing**: the expected `key=value | ...` format, syslog lines, space-separated `key=value`, any line containing an IPv4/IPv6 address, or your own regex via `--pattern`.
- **Mock mode** (`--mock`): realistic simulated intel for demos without an API key.

### Expected log format

```
2026-11-18T21:04:11Z | sev=HIGH | device=fw-edge-01 | event=SSH brute force | src_ip=185.220.101.4 | dst_ip=10.0.20.15 | dst_port=22 | action=allowed | msg=37 failed logins for root
```

## Project layout

| File | Purpose |
|---|---|
| `siem_enricher.py` | The tool (single file, standard library only) |
| `test_siem_enricher.py` | 42 tests; VirusTotal is faked at the HTTP layer, so no key or network is needed |
| `sample_siem.log` | Realistic sample SIEM feed |
| `Dockerfile`, `docker-entrypoint.sh`, `docker-compose.yml` | Container packaging; the image build fails if any test fails |
| `requirements-dev.txt` | pytest (tests only) |
