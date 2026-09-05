# 🛡️ netsec-toolkit

> Two small security tools I built from scratch in Python to learn how network
> reconnaissance and log analysis actually work — not just to run existing tools,
> but to understand what they do under the hood.
>
> 1. **`portscan.py`** — a concurrent TCP port scanner (offense / recon)
> 2. **`logparse.py`** — an SSH auth-log analyzer (defense / detection)

⚠️ **Authorized use only.** Only scan hosts you own or have explicit
permission to test. All examples below use `scanme.nmap.org`, a host the Nmap
project provides specifically for legal scanning practice.

---

## Why I built it

I'm aiming to work in 3D art, but I'm studying IT and wanted hands-on security
skills to go with the theory from my coursework. I built these to understand how
port scanning, service reconnaissance, and log-based attack detection actually
work under the hood, rather than just running tools like `nmap` or `fail2ban`
without knowing what they do. The two tools cover both sides: the scanner
*probes* systems, the parser *watches* them.

---

# 🔍 Tool 1: portscan.py — concurrent TCP port scanner

---

## What it does

A concurrent TCP port scanner that checks which ports are open on a target host
and grabs service banners where it can.

```bash
# Scan specific ports
python portscan.py scanme.nmap.org -p 22,80,443

# Scan a range
python portscan.py scanme.nmap.org -p 1-1024

# Mix, and save results to JSON
python portscan.py scanme.nmap.org -p 22,80,8000-8100 --json scan.json
```

It accepts a single port, a range, or a comma-separated list, connects to each
one, and prints the open ports with any banner the service returns. Results can
be exported to a JSON file with `--json`.

---

## How I built it — the journey

<!-- TODO (fill from memory — this is the most important section):
     Write 1–2 sentences per stage. You lived all of these. -->

**1. Connecting to one port.**
<!-- What was the very first thing you got working? Just a socket
     connecting to a single port to learn how connect_ex works. -->

**2. Banner grabbing.**
I learned that SSH sends its info **immediately** on connect, but HTTP stays
silent **until you send it a request first**. So passive banner grabbing only
works on "server-speaks-first" protocols.

**3. The slow version.**
My first version scanned ports one at a time. I timed a 10-port scan at ~9.7
seconds — because each closed port sat waiting the full 1-second timeout before
giving up. Scaled to ~1000 ports, that would be roughly **17 minutes**.

**4. Making it concurrent.**
I rewrote it with a `ThreadPoolExecutor` (100 workers). The same ~1000-port scan
dropped from ~17 minutes to **~11.5 seconds** — about **90x faster**.

I learned threads help here because the work is **I/O-bound** — most of the time
is spent **waiting for the network**, not computing. So 100 connections can sit
waiting at the same time instead of one after another. (Threads wouldn't give
the same speedup for CPU-heavy work, because of Python's GIL.)

**5. Active HTTP banner grabbing.**
Passive banner grabbing left port 80 blank, because HTTP waits for the client to
speak first. So I made the scanner *send* a minimal `GET / HTTP/1.0` request to
HTTP ports before reading the reply — then extract just the `Server:` header from
the response. Port 80 went from an empty banner to
`Server: Apache/2.4.7 (Ubuntu)` — a real, useful recon detail.

---

## Problems I hit

**The banner that disappeared.** One run, the SSH banner on port 22 came back
empty — even though my code was correct. Then on the next run it came back.

I learned that banner grabbing depends on **timing**. When you connect to a
port, some services (like SSH) send their banner a fraction of a second after
the connection opens. Your `recv` has to still be waiting when that greeting
arrives to catch it. If the window closes first — because the server was slow,
the machine was busy running 100 threads, or the network hiccupped — you get
nothing.

The key lesson: the network isn't deterministic. The **same code, same command,
same target** can grab the banner on one run and miss it on the next. A
production tool would handle this with retries or a longer timeout for the
banner read.

---

## What I'd add next (scanner)

- HTTPS (port 443) banner grabbing — needs a TLS handshake via the `ssl` module
  before sending the request, since 443 expects encryption first
- Retries / adaptive timeouts for more reliable banner grabbing
- UDP scan support

---

# 🛡️ Tool 2: logparse.py — SSH auth-log analyzer

## What it does

Reads a Linux SSH authentication log and flags security-relevant patterns:
failed logins grouped by source IP, likely brute-force sources, and — the most
important signal — IPs that failed repeatedly and *then* succeeded (a possible
breach).

```bash
# Analyze a log with the default threshold (5 failures = brute-force)
python logparse.py auth.log

# Use a real system log and a custom threshold
python logparse.py /var/log/auth.log -t 10

# Save findings to JSON
python logparse.py auth.log --json findings.json
```

Example output:

```
IP 203.0.113.44: 6 failed login attempts
IP 192.0.2.88: 2 failed login attempts
IP 203.0.113.44 has exceeded the threshold with 6 failed attempts.

[!] Suspicious: failed then succeeded (possible breach):
  192.0.2.88 — 2 failures, then a successful login
```

## How I built it — the journey

<!-- TODO (your words — you built each of these):
     1–2 sentences per stage. -->

**1. Reading the log by eye first.**
<!-- Before writing code, you read the sample log like an analyst and spotted
     the three cases yourself. What were they? (legit user, brute-force IP,
     failed-then-succeeded IP) -->

**2. First regex — extracting IP and username.**
<!-- What did regex let you do that plain string matching couldn't? You went
     from "is this a failed line? yes/no" to pulling the actual IP and user
     OUT of the line as data. Mention \d+ for digits, \. for a literal dot,
     and () capture groups. -->

**3. Counting failures per IP.**
<!-- You built a dictionary to tally failures per IP by hand (if/else), then
     learned Counter does the same in one line. What does Counter do under the
     hood? (a dict that defaults missing keys to 0) -->

**4. Detection — brute-force and breach.**
<!-- Two rules: an IP over the threshold = brute-force; an IP that appears in
     BOTH the failed set AND the accepted set = possible breach. Why is the
     second signal more important than the first? -->

## Problems I hit (parser)

<!-- TODO: pick a real one. Candidates:
     - the report printed twice, and it turned out NOT to be a code bug —
       just stacked terminal runs. What did that teach you about debugging?
     - a whole detection block went missing during the argparse edit, and you
       caught it by comparing against your last working version.
     - the > vs >= threshold decision — why >= matters for a detection rule. -->

## What I'd add next (parser)

- Track most-targeted usernames (root, admin, etc.)
- Handle "Invalid user" log lines as a separate signal
- Detection across a time window, like `fail2ban` (X failures in Y minutes)
- GeoIP lookup to show where attacking IPs are located

---

## What I learned (whole project)

<!-- TODO: 4–6 bullets IN YOUR OWN WORDS. Seeds below — rewrite them: -->
- How TCP connect scanning works at the socket level
- The difference between server-speaks-first (SSH) and client-speaks-first (HTTP) protocols
- Why concurrency helps I/O-bound work but not CPU-bound work
- That network behavior is non-deterministic and tools must be robust to it
- How regex turns unstructured log text into structured data you can count and analyze
- How simple detection rules (thresholds, set membership) catch real attack patterns
- That offense (scanning) and defense (log analysis) are two sides of the same skill set

---

*Built step by step as a learning project. Every line is code I wrote and can
explain.*
