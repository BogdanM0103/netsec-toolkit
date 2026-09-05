# 🛡️ netsec-toolkit

> Three small security tools I built from scratch in Python to learn how network
> reconnaissance, log analysis, and traffic inspection actually work — not just to
> run existing tools, but to understand what they do under the hood.
>
> 1. **`portscan.py`** — a concurrent TCP port scanner (offense / recon)
> 2. **`logparse.py`** — an SSH auth-log analyzer (defense / detection)
> 3. **`packetsniff.py`** — a live packet sniffer with DNS logging, plaintext-HTTP
>    flagging, and port-scan detection (defense / monitoring)

⚠️ **Authorized use only.** Only scan hosts you own or have explicit
permission to test. All examples below use `scanme.nmap.org`, a host the Nmap
project provides specifically for legal scanning practice.

---

## Why I built it

I'm aiming to work in 3D art, but I'm studying IT and wanted hands-on security
skills to go with the theory from my coursework. I built these to understand how
port scanning, service reconnaissance, and log-based attack detection actually
work under the hood, rather than just running tools like `nmap` or `fail2ban`
without knowing what they do. The tools cover both sides: the scanner
*probes* systems, while the parser and sniffer *watch* them.

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

# 🔬 Tool 3: packetsniff.py — live packet sniffer

⚠️ **Local machine only.** This captures traffic on my own machine's network
interface. Only ever run a sniffer on networks and devices you own or have
explicit permission to monitor — capturing other people's traffic is illegal.

## What it does

Captures live network packets (using `scapy`) and inspects each one. It parses
the layers (Ethernet → IP → TCP/UDP), labels well-known ports, and adds three
security features on top:

1. **DNS query logging** — prints every domain the machine looks up, revealing
   the background chatter of the OS and apps.
2. **Plaintext HTTP flagging** — flags unencrypted HTTP (port 80) and shows its
   readable payload, in contrast to the encrypted gibberish of HTTPS.
3. **Port-scan detection** — tracks how many distinct ports each source IP hits,
   and flags any source that crosses a threshold as a possible scanner.

```bash
# Capture 10 packets (needs admin/root + Npcap on Windows)
python packetsniff.py -c 10

# Only HTTPS traffic
python packetsniff.py -f "tcp port 443" -c 20

# Watch DNS lookups
python packetsniff.py -f "udp port 53" -c 20
```

Example output:

```
[DNS Query] ... -> ...  Domain: github.com
[HTTPS] [TCP] 192.168.1.139:51654 -> 140.82.112.21:443
Insecure HTTP traffic detected: 192.168.1.139:50663 -> 34.223.124.45:80
    Readable data: b'GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 ...'
[!!!] Potential port scan from 20.184.175.4 - hit 6 unique ports
```

## How I built it — the journey

<!-- TODO (your words — you built each of these):
     1–2 sentences per stage. -->

**1. Capturing and reading one packet.**
My very first captured packet was a DNS query my own machine sent to a Microsoft
server — `Ether / IPv6 / UDP / DNS`. What stood out was seeing a packet as a
stack of layers, each one wrapped inside the next: Ethernet (hardware/MAC
addresses) carries IP (source/destination addresses), which carries TCP or UDP
(ports), which carries the actual payload. Seeing that structure live, instead of
as a textbook diagram, made the whole TCP/IP model click.

**2. Extracting fields — addresses, ports, protocol.**
I pulled the source/destination addresses, ports, and protocol out of each
packet. I had to handle both IPv4 and IPv6 (`packet[IP]` vs `packet[IPv6]`),
since my real traffic used both — a naive version that only checked one would
crash on the other. I read ports from the TCP/UDP layers and labeled well-known
ones (443 → HTTPS, 53 → DNS) so each line was readable at a glance.

**3. The three security features.**
- **DNS logging** — parsing the DNS layer to print every domain my machine looks
  up. Eye-opening: I could see the OS and apps quietly contacting telemetry
  servers I never opened.
- **Plaintext HTTP flagging** — the biggest lesson of the project. When I captured
  plain HTTP I could read the payload directly (`GET / HTTP/1.1...`). HTTPS traffic,
  by contrast, was just encrypted bytes (`\x17\x03\x03...`). **HTTPS exists to
  encrypt the data travelling across the network — without it, anyone capturing
  the traffic can read it in plain text.** I didn't read that in a book; I saw
  both cases with my own tool.
- **Scan detection** — tracking the set of destination ports each source IP hits
  (using a `defaultdict(set)`), and flagging any IP that crosses a threshold,
  warning only once per source.

## Problems I hit (sniffer)

**A false positive taught me about threshold tuning.** My scan detector flagged a
*Microsoft server* as a port scanner. It wasn't an attack — it was a normal app
opening many parallel HTTPS connections at once, which tripped my threshold of 5.
The lesson: a detection rule set too sensitively flags normal traffic. Real
tuning means watching normal traffic first, seeing how high it legitimately goes,
and setting the threshold above that — high enough to catch real scans (which hit
dozens or hundreds of ports) but not everyday bursts.

**Where you capture matters.** When I ran my own port scanner against my own
machine, the sniffer never detected it — even though the scan was clearly
happening (it found open ports). The reason: traffic from a machine to its own IP
loops back internally and doesn't cross the network interface the sniffer captures
on, so scapy never sees it. To demonstrate scan detection properly, the scan needs
to come from a *separate* machine. That's a real limitation of capture placement,
not a bug in the detector — and a good reason to build a proper multi-machine lab.

## What I'd add next (sniffer)

- Save captures to a `.pcap` file to open in Wireshark
- A live protocol-count dashboard (TCP vs UDP vs DNS, top talkers)
- HTTPS handling limitation: 443 payloads are encrypted, so only metadata
  (who talks to whom) is visible — this is by design, and worth documenting
- Detect scans from a separate machine in a proper lab setup

---

## What I learned (whole project)

<!-- TODO: 4–6 bullets IN YOUR OWN WORDS. Seeds below — rewrite them: -->
- How TCP connect scanning works at the socket level
- The difference between server-speaks-first (SSH) and client-speaks-first (HTTP) protocols
- Why concurrency helps I/O-bound work but not CPU-bound work
- That network behavior is non-deterministic and tools must be robust to it
- How regex turns unstructured log text into structured data you can count and analyze
- How simple detection rules (thresholds, set membership) catch real attack patterns
- How network packets are layered (Ethernet → IP → TCP/UDP → payload), seen live
- Why HTTPS matters — I saw readable HTTP payloads next to encrypted HTTPS on the wire
- That detection rules need tuning: too low a threshold flags normal traffic (false positives)
- That offense (scanning) and defense (log analysis, sniffing) are two sides of the same skill set

---

*Built step by step as a learning project. Every line is code I wrote and can
explain.*
