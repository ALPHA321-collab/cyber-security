# Network Intrusion Detection System (NIDS) — Setup Guide

A step-by-step guide to deploying, tuning, and monitoring a network-based IDS using **Suricata** (with Snort notes where it differs), including alerting, response, and visualization.

---

## 0. Architecture Overview

```
                 ┌──────────────────────┐
   Internet ───► │   Router / Firewall  │
                 └──────────┬───────────┘
                             │  (mirrored/SPAN port or TAP)
                             ▼
                 ┌──────────────────────┐
                 │   NIDS Sensor Host   │
                 │  Suricata / Snort    │
                 └──────────┬───────────┘
                             │  eve.json / unified2 logs
                             ▼
                 ┌──────────────────────┐
                 │ Log pipeline (Filebeat)│
                 └──────────┬───────────┘
                             ▼
                 ┌──────────────────────┐
                 │ Elasticsearch + Kibana│
                 │   (visualization)     │
                 └──────────────────────┘
```

Key idea: the IDS needs to **see** traffic, not just sit inline on one host's NIC. On a switch you need a **SPAN/mirror port** or a network **TAP**; on a home lab you can put the sensor on a bridge or monitor a VM's virtual switch.

---

## 1. Installing the IDS

### Option A — Suricata (recommended, multi-threaded, active development)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
```

**Check install & interface:**
```bash
suricata --build-info
ip a          # identify the monitoring interface, e.g. eth1
```

**Set the monitored interface** in `/etc/suricata/suricata.yaml`:
```yaml
af-packet:
  - interface: eth1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

**Enable community-id and eve.json (JSON alert/event log) output** — important for dashboards later:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
        - ssh
community-id: yes
```

### Option B — Snort (classic, single-threaded per process, huge community rule base)

```bash
sudo apt install snort -y
# during install you'll be prompted for the monitored interface and local network CIDR (HOME_NET)
```

Snort 3 (current gen) is closer in architecture to Suricata; if starting fresh, prefer Snort 3 or Suricata over legacy Snort 2.

---

## 2. Configuring Rules and Alerts

### 2.1 Rule sources

Both tools use the same-ish rule syntax (Snort rule language, which Suricata also consumes).

- **ET Open (Emerging Threats)** — free, broad community ruleset.
- **Snort Community Rules** — free, maintained by Cisco Talos.
- Paid feeds (Snort Subscriber, ET Pro) for faster updates — optional.

**Suricata rule management with `suricata-update`:**
```bash
sudo apt install python3-pip -y
sudo pip3 install --upgrade suricata-update
sudo suricata-update            # pulls ET Open by default into /var/lib/suricata/rules/
sudo suricata-update list-sources   # see other available sources
sudo suricata-update enable-source oisf/trafficid
```

Point Suricata at the compiled ruleset in `suricata.yaml`:
```yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
```

### 2.2 Writing custom rules

Rule anatomy:
```
action proto src_ip src_port -> dst_ip dst_port (options)
```

**Example — detect ICMP ping sweep:**
```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
```

**Example — detect plaintext FTP login attempt:**
```
alert tcp any any -> $HOME_NET 21 (msg:"FTP Login Attempt"; content:"USER"; nocase; sid:1000002; rev:1;)
```

**Example — detect a specific known-bad User-Agent (basic malware C2 pattern):**
```
alert http any any -> any any (msg:"Suspicious User-Agent String"; http.user_agent; content:"curl/"; sid:1000003; rev:1;)
```

**Example — SSH brute-force (rate-based detection):**
```
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000004; rev:1;)
```

Put custom rules in `/etc/suricata/rules/local.rules` and reference it:
```yaml
rule-files:
  - suricata.rules
  - local.rules
```

### 2.3 Test config and rule syntax
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### 2.4 Tuning to reduce false positives

- Set `$HOME_NET` accurately in `suricata.yaml` (your actual internal subnet), not the default placeholder.
- Disable noisy rule categories you don't care about via `threshold.config` or by setting rule state (`disable`) per SID in `suricata-update`'s `disable.conf`.
- Use `classification.config` severities to prioritize alert triage.

---

## 3. Continuous Monitoring

### 3.1 Run as a service
```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

### 3.2 Live alert tail
```bash
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### 3.3 Automatic rule updates (cron)
```bash
sudo crontab -e
# add:
0 3 * * * /usr/bin/suricata-update && systemctl restart suricata
```

### 3.4 Health/performance checks
```bash
suricatasc -c "iface-stat eth1"     # dropped packets, throughput
```
Watch for packet drops — if the sensor can't keep up with line rate, alerts get silently missed. Multi-queue NICs + `af-packet` clustering (as configured above) helps scale across CPU cores.

---

## 4. Response Mechanisms

IDS = *detect*. To *respond*, you have a few tiers:

### 4.1 Passive alerting (simplest)
- Email/Slack/webhook on alert. Example using a simple log-watcher script:

```python
# alert_notifier.py — tails eve.json and posts high-severity alerts to a webhook
import json, time, requests

WEBHOOK_URL = "https://your-webhook-endpoint"
LOGFILE = "/var/log/suricata/eve.json"

def follow(f):
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

with open(LOGFILE) as f:
    for line in follow(f):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert" and event["alert"]["severity"] <= 2:
            requests.post(WEBHOOK_URL, json={
                "text": f"[ALERT] {event['alert']['signature']} "
                        f"{event['src_ip']} -> {event['dest_ip']}"
            })
```

### 4.2 Active response — IPS mode (inline blocking)

Suricata can run **inline** (as an IPS, not just IDS) using `nfqueue` or `af-packet` in IPS mode, actively dropping malicious packets:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -q 0
```
```yaml
# suricata.yaml
af-packet:
  - interface: eth1
    copy-mode: ips
    copy-iface: eth2   # traffic bridged out the second interface after filtering
```
Change `alert` to `drop` in the rules you want actively enforced.

### 4.3 Automated blocking via firewall (fail2ban-style)

Pair Suricata alerts with `fail2ban` or a custom script that inserts firewall rules on repeated offenders:
```bash
sudo iptables -I INPUT -s <offending_ip> -j DROP
```
A basic fail2ban jail watching Suricata's fast.log:
```ini
[suricata]
enabled  = true
filter   = suricata
logpath  = /var/log/suricata/fast.log
action   = iptables-allports[name=suricata]
maxretry = 1
bantime  = 3600
```

### 4.4 SOAR-style orchestration
For anything beyond a lab, feed alerts into a SIEM (e.g., Wazuh, Elastic Security, Splunk) and use its built-in active-response/playbook features rather than hand-rolled scripts — it gives you audit trails, rollback, and case management.

---

## 5. Visualization (Optional but Recommended)

### 5.1 Elastic Stack (Suricata → Filebeat → Elasticsearch → Kibana)

**Install Filebeat and enable the Suricata module:**
```bash
sudo apt install filebeat -y
sudo filebeat modules enable suricata
```

`/etc/filebeat/modules.d/suricata.yml`:
```yaml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
```

```bash
sudo filebeat setup -e
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

Kibana ships pre-built Suricata dashboards (alerts over time, top signatures, top talkers, geo-map of source IPs) once the module is enabled — visible under **Analytics → Dashboards → [Filebeat Suricata]**.

### 5.2 Lighter-weight alternative — EveBox
Purpose-built Suricata alert viewer, easier than standing up the full Elastic stack:
```bash
# see https://github.com/jasonish/evebox for current install instructions
evebox oneshot /var/log/suricata/eve.json   # quick local review
```

### 5.3 Lightest alternative — Grafana + Loki
If you already run Grafana, ship `eve.json` via Promtail/Loki and build panels for alert counts by signature/severity/source IP over time.

---

## Suggested Build Order (for a lab/portfolio project)

1. Stand up Suricata on a VM with a mirrored interface (or use a pcap replay for testing, see below).
2. Pull ET Open rules + write 3–5 custom rules covering scans, brute force, and a suspicious protocol pattern.
3. Confirm detection using safe test traffic (`nmap` scan of your own lab host, `hping3` SYN flood on a test VM, EICAR test string over HTTP).
4. Wire up eve.json → Filebeat → Elastic/Kibana for a dashboard.
5. Add the alert_notifier webhook script or fail2ban integration for automated response.
6. Document detections and response actions in a short incident-report template — good for a portfolio writeup.

### Safe test traffic for validating detection (only against systems you own/control)
```bash
nmap -sS -T4 <your-test-vm-ip>          # should trigger a port-scan rule
curl http://<test-vm-ip>/ -A "curl/testing"   # triggers the custom UA rule above
```

---

## Notes
- Always run scans/tests only against infrastructure you own or are explicitly authorized to test — this applies even in a home lab if other devices share the network.
- Keep rules updated; a stale ruleset misses newly disclosed threats.
- Log rotation matters — `eve.json` grows fast under real traffic; configure `logrotate` for `/var/log/suricata/`.
