#!/usr/bin/env python3
"""
seed_demo.py
============
Populates sysmon.db with 7 days of realistic multi-host monitoring data
so the dashboard looks impressive during a PFE demo.

Usage:
    python seed_demo.py                      # uses sysmon.db in current dir
    python seed_demo.py --db /path/to/sysmon.db
    python seed_demo.py --days 3             # seed only 3 days
    python seed_demo.py --clear              # wipe existing seed data first

What it creates:
    4 hosts with distinct, realistic personalities:
      - web-server-01   : web server, normally low CPU, occasional traffic spikes
      - db-server-01    : database, stable high RAM, low CPU
      - worker-01       : background jobs, variable CPU, gradual memory leak
      - monitoring-01   : the host running sysmon itself, stable and quiet

    Each host has:
      - Metrics every 60 seconds for N days
      - Realistic disk usage that grows slowly
      - Network traffic that follows a day/night pattern
      - Services that occasionally go down and recover
      - Alerts that fired and resolved naturally
      - A few log events (auth failures, etc.)
"""

import sqlite3
import json
import math
import random
import argparse
import time
import os
import sys

# ── Argument parsing ──────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Seed sysmon.db with demo data")
parser.add_argument("--db",    default="sysmon.db", help="Path to sysmon.db")
parser.add_argument("--days",  type=int, default=7,  help="Days of history to generate")
parser.add_argument("--clear", action="store_true",  help="Clear existing data before seeding")
args = parser.parse_args()

DB_PATH = args.db
DAYS    = args.days
NOW     = int(time.time())
START   = NOW - DAYS * 86400
INTERVAL = 60   # one sample per minute

if not os.path.exists(DB_PATH):
    print(f"✘ Database not found: {DB_PATH}")
    print("  Start the server at least once to create it, then run this script.")
    sys.exit(1)

print(f"🌱 Seeding {DAYS} days of demo data into {DB_PATH}")
print(f"   From: {time.strftime('%Y-%m-%d %H:%M', time.gmtime(START))}")
print(f"   To:   {time.strftime('%Y-%m-%d %H:%M', time.gmtime(NOW))}")

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

if args.clear:
    hosts_to_clear = ['web-server-01', 'db-server-01', 'worker-01', 'monitoring-01']
    for h in hosts_to_clear:
        conn.execute("DELETE FROM metrics       WHERE hostname=?", (h,))
        conn.execute("DELETE FROM log_events    WHERE hostname=?", (h,))
        conn.execute("DELETE FROM alert_history WHERE hostname=?", (h,))
        conn.execute("DELETE FROM service_state WHERE hostname=?", (h,))
        conn.execute("DELETE FROM host_config   WHERE hostname=?", (h,))
    conn.commit()
    print("   ✔ Cleared existing seed data")

# ── Helper: smooth noise ──────────────────────────────────────────────────────
def smooth_noise(t, freq=0.01, amp=1.0, seed=0):
    """Smooth sinusoidal noise with a random seed offset."""
    return amp * math.sin(t * freq + seed)

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def day_fraction(ts):
    """0.0 at midnight, 1.0 at midnight next day."""
    return (ts % 86400) / 86400

def business_hours_factor(ts):
    """
    Returns 0.0 at 3am, 1.0 at peak (10am-3pm).
    Models realistic load that's higher during business hours.
    """
    h = (ts % 86400) / 3600  # hour of day (UTC ≈ CET - 1h)
    # Bell curve peaking at h=11
    return clamp(math.exp(-((h - 11) ** 2) / 18), 0.05, 1.0)

# ── Host definitions ──────────────────────────────────────────────────────────
HOSTS = [
    {
        "hostname":   "web-server-01",
        "tags":       "prod,web",
        "cpu_thr":    80.0,
        "ram_thr":    85.0,
        "services":   ["nginx", "sshd"],
        "disks":      [{"path": "/", "base": 45.0, "growth": 0.002}],
        "ifaces":     ["eth0"],
        # CPU: low base, spikes during business hours
        "cpu_base":   15.0,
        "cpu_amp":    35.0,
        "cpu_seed":   1.7,
        # RAM: moderate, stable
        "ram_base":   40.0,
        "ram_amp":    12.0,
        "ram_seed":   2.3,
        # Incident: CPU spike on day 3 (DDoS-like event)
        "incidents": [
            {"day": 3, "hour": 14, "duration_h": 2,
             "type": "cpu_spike", "value": 93.0,
             "service_down": None},
        ],
        "log_messages": [
            "Failed password for root from 185.220.101.42 port 54312",
            "Failed password for admin from 192.168.1.100 port 22",
            "Invalid user deploy from 10.0.0.5 port 41256",
            "Accepted publickey for zyzz from 192.168.1.5 port 52341",
            "Connection closed by 185.220.101.42 port 54312",
        ],
    },
    {
        "hostname":   "db-server-01",
        "tags":       "prod,db",
        "cpu_thr":    70.0,
        "ram_thr":    90.0,
        "services":   ["postgresql", "sshd"],
        "disks":      [
            {"path": "/",        "base": 30.0, "growth": 0.001},
            {"path": "/var/lib", "base": 62.0, "growth": 0.008},  # DB data grows
        ],
        "ifaces":     ["eth0"],
        # CPU: low, stable — DB mostly waits on I/O
        "cpu_base":   18.0,
        "cpu_amp":    14.0,
        "cpu_seed":   0.5,
        # RAM: high — PostgreSQL caches everything it can
        "ram_base":   72.0,
        "ram_amp":    8.0,
        "ram_seed":   3.1,
        "incidents": [
            # postgresql goes down briefly on day 5 (maintenance)
            {"day": 5, "hour": 2, "duration_h": 0.5,
             "type": "service_down", "value": None,
             "service_down": "postgresql"},
        ],
        "log_messages": [
            "FATAL: password authentication failed for user \"app\"",
            "LOG: checkpoint complete: wrote 843 buffers",
            "LOG: autovacuum: processing database \"sysmon\"",
            "WARNING: out of shared memory",
        ],
    },
    {
        "hostname":   "worker-01",
        "tags":       "prod,worker",
        "cpu_thr":    85.0,
        "ram_thr":    88.0,
        "services":   ["sshd"],
        "disks":      [{"path": "/", "base": 55.0, "growth": 0.003}],
        "ifaces":     ["eth0"],
        # CPU: variable — background job processing
        "cpu_base":   30.0,
        "cpu_amp":    40.0,
        "cpu_seed":   4.2,
        # RAM: gradual leak over 7 days (realistic memory leak scenario)
        "ram_base":   35.0,
        "ram_amp":    6.0,
        "ram_seed":   1.1,
        "ram_leak":   0.0018,   # % per minute — adds up to ~18% over 7 days
        "incidents": [
            # CPU goes critical on day 6 (runaway job)
            {"day": 6, "hour": 9, "duration_h": 3,
             "type": "cpu_spike", "value": 97.0,
             "service_down": None},
        ],
        "log_messages": [
            "Job #4821 failed after 3 retries: Connection timeout",
            "Queue depth: 1204 pending tasks",
            "Worker process restarted after OOM kill",
            "Slow job detected: task_id=9921 took 847s",
        ],
    },
    {
        "hostname":   "monitoring-01",
        "tags":       "infra,monitoring",
        "cpu_thr":    85.0,
        "ram_thr":    90.0,
        "services":   ["sshd"],
        "disks":      [{"path": "/", "base": 28.0, "growth": 0.0005}],
        "ifaces":     ["eth0"],
        # CPU: very low and stable — this is the monitoring server itself
        "cpu_base":   8.0,
        "cpu_amp":    5.0,
        "cpu_seed":   0.9,
        # RAM: low, stable
        "ram_base":   25.0,
        "ram_amp":    4.0,
        "ram_seed":   2.7,
        "incidents":  [],
        "log_messages": [
            "sshd: Accepted publickey for zyzz",
        ],
    },
]

# ── Insert host configs ───────────────────────────────────────────────────────
for h in HOSTS:
    existing = conn.execute(
        "SELECT hostname FROM host_config WHERE hostname=?", (h["hostname"],)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO host_config (hostname, cpu_threshold, ram_threshold, monitoring, tags) "
            "VALUES (?,?,?,1,?)",
            (h["hostname"], h["cpu_thr"], h["ram_thr"],
             ",".join(h["tags"].split(",")))
        )
print(f"   ✔ Host configs inserted")

# ── Generate metrics ──────────────────────────────────────────────────────────
total_metrics = 0

for host in HOSTS:
    hn     = host["hostname"]
    rows   = []
    svc_states = {s: "active" for s in host["services"]}

    # Pre-compute incident windows
    incident_windows = []
    for inc in host.get("incidents", []):
        inc_start = START + inc["day"] * 86400 + inc["hour"] * 3600
        inc_end   = inc_start + int(inc["duration_h"] * 3600)
        incident_windows.append((inc_start, inc_end, inc))

    ts = START
    minute = 0

    while ts <= NOW:
        bf  = business_hours_factor(ts)
        df  = day_fraction(ts)
        t   = float(minute)

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu = (host["cpu_base"]
               + host["cpu_amp"] * bf * 0.7
               + smooth_noise(t, freq=0.008, amp=host["cpu_amp"] * 0.3, seed=host["cpu_seed"])
               + smooth_noise(t, freq=0.05,  amp=4.0, seed=host["cpu_seed"] + 1)
               + random.gauss(0, 2))

        # ── RAM ───────────────────────────────────────────────────────────────
        leak = host.get("ram_leak", 0) * minute
        ram  = (host["ram_base"]
                + leak
                + host["ram_amp"] * 0.4
                + smooth_noise(t, freq=0.003, amp=host["ram_amp"] * 0.6, seed=host["ram_seed"])
                + random.gauss(0, 1.5))

        # ── Apply incidents ───────────────────────────────────────────────────
        in_incident = False
        for (istart, iend, inc) in incident_windows:
            if istart <= ts <= iend:
                in_incident = True
                if inc["type"] == "cpu_spike":
                    progress = (ts - istart) / (iend - istart)
                    # Bell curve: ramps up and down
                    factor = math.sin(progress * math.pi)
                    cpu = inc["value"] * factor + cpu * (1 - factor)
                if inc["service_down"] and ts >= istart:
                    svc_states[inc["service_down"]] = "failed"
            else:
                if inc.get("service_down") and ts > iend:
                    svc_states[inc["service_down"]] = "active"

        cpu = clamp(cpu, 0.5, 100.0)
        ram = clamp(ram, 5.0,  100.0)

        # ── Disks ─────────────────────────────────────────────────────────────
        disks = []
        for d in host["disks"]:
            pct = clamp(d["base"] + d["growth"] * minute + random.gauss(0, 0.3), 0, 99)
            disks.append({"path": d["path"], "percent": round(pct, 1)})

        # ── Network ───────────────────────────────────────────────────────────
        # Traffic follows business hours + some noise
        net_base = 50000 * bf + random.gauss(0, 5000)
        if in_incident and host["hostname"] == "web-server-01":
            net_base *= 8   # DDoS: 8x traffic
        network = [{"interface": iface,
                    "rx_bps": max(0, net_base + random.gauss(0, 3000)),
                    "tx_bps": max(0, net_base * 0.3 + random.gauss(0, 1000))}
                   for iface in host["ifaces"]]

        # ── Services ──────────────────────────────────────────────────────────
        services = [{"name": s, "status": svc_states[s]}
                    for s in host["services"]]

        raw = {
            "hostname":    hn,
            "timestamp":   ts,
            "cpu_percent": round(cpu, 2),
            "ram_percent": round(ram, 2),
            "disks":       disks,
            "network":     network,
            "services":    services,
        }

        rows.append((
            hn, ts,
            round(cpu, 2),
            round(ram, 2),
            json.dumps(raw)
        ))

        ts     += INTERVAL
        minute += 1

    # Batch insert
    conn.executemany(
        "INSERT OR IGNORE INTO metrics (hostname, timestamp, cpu_percent, ram_percent, raw_json) "
        "VALUES (?,?,?,?,?)",
        rows
    )
    total_metrics += len(rows)
    print(f"   ✔ {hn}: {len(rows)} metric samples")

conn.commit()

# ── Generate alert history ────────────────────────────────────────────────────
alerts_inserted = 0
for host in HOSTS:
    hn = host["hostname"]
    for inc in host.get("incidents", []):
        inc_start = START + inc["day"] * 86400 + inc["hour"] * 3600
        inc_end   = inc_start + int(inc["duration_h"] * 3600)

        if inc["type"] == "cpu_spike":
            peak = inc["value"]
            conn.execute(
                "INSERT INTO alert_history "
                "(hostname, alert_type, detail, severity, subject, body, status, fired_at, resolved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (hn, "cpu", "high",
                 "critical" if peak > 95 else "warning",
                 f"{hn}: CPU at {peak:.0f}% (threshold {host['cpu_thr']:.0f}%)",
                 f"Host: {hn}\nCPU usage: {peak:.0f}%\nThreshold: {host['cpu_thr']:.0f}%",
                 "resolved", inc_start + 300, inc_end)
            )
            alerts_inserted += 1

            # Also a spike alert
            conn.execute(
                "INSERT INTO alert_history "
                "(hostname, alert_type, detail, severity, subject, body, status, fired_at, resolved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (hn, "cpu", "spike",
                 "warning",
                 f"{hn}: CPU spike +{peak - host['cpu_base']:.0f}% detected",
                 f"Host: {hn}\nSudden CPU increase detected.",
                 "resolved", inc_start + 120, inc_end - 600)
            )
            alerts_inserted += 1

        elif inc["type"] == "service_down":
            svc = inc["service_down"]
            conn.execute(
                "INSERT INTO alert_history "
                "(hostname, alert_type, detail, severity, subject, body, status, fired_at, resolved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (hn, "service", f"{svc}:down",
                 "critical",
                 f"{hn}: Service {svc} is DOWN",
                 f"Host: {hn}\nService: {svc}\nStatus: failed",
                 "resolved", inc_start, inc_end)
            )
            conn.execute(
                "INSERT INTO alert_history "
                "(hostname, alert_type, detail, severity, subject, body, status, fired_at, resolved_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (hn, "service", f"{svc}:up",
                 "info",
                 f"{hn}: Service {svc} recovered",
                 f"Host: {hn}\nService: {svc}\nStatus: active",
                 "resolved", inc_end, None)
            )
            alerts_inserted += 2

    # worker-01 RAM anomaly alert (gradual leak)
    if hn == "worker-01":
        anomaly_ts = START + 5 * 86400  # day 5
        conn.execute(
            "INSERT INTO alert_history "
            "(hostname, alert_type, detail, severity, subject, body, status, fired_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (hn, "ram", "anomaly",
             "warning",
             f"{hn}: RAM anomaly — gradual memory leak detected",
             f"Host: {hn}\nRAM trending upward over 5 days.\n24h mean: 61%  Current: 78%",
             "active", anomaly_ts)
        )
        alerts_inserted += 1

conn.commit()
print(f"   ✔ {alerts_inserted} alert history entries inserted")

# ── Generate log events ───────────────────────────────────────────────────────
logs_inserted = 0
for host in HOSTS:
    hn   = host["hostname"]
    msgs = host.get("log_messages", [])
    if not msgs:
        continue
    # Scatter log events across the time range
    num_logs = random.randint(15, 40)
    for _ in range(num_logs):
        ts  = START + random.randint(0, DAYS * 86400)
        msg = random.choice(msgs)
        conn.execute(
            "INSERT INTO log_events (hostname, timestamp, source, message) VALUES (?,?,?,?)",
            (hn, ts, "auth_failures", msg)
        )
        logs_inserted += 1

conn.commit()
print(f"   ✔ {logs_inserted} log events inserted")

# ── Service state (latest) ────────────────────────────────────────────────────
for host in HOSTS:
    hn = host["hostname"]
    for svc in host["services"]:
        existing = conn.execute(
            "SELECT hostname FROM service_state WHERE hostname=? AND service=?", (hn, svc)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO service_state (hostname, service, last_status, updated_at) "
                "VALUES (?,?,?,?)",
                (hn, svc, "active", NOW)
            )
conn.commit()

conn.close()

print(f"\n✔ Seed complete!")
print(f"   {total_metrics:,} metric samples across {len(HOSTS)} hosts")
print(f"   Hosts: {', '.join(h['hostname'] for h in HOSTS)}")
print(f"\n   Start the server and open the dashboard to see the data.")
print(f"   Dashboard: https://localhost:8443")
