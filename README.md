# 🔍 openport — a concurrent TCP port scanner

> A port scanner I built from scratch in Python to learn how network
> reconnaissance actually works — not just to run `nmap`, but to understand
> what it does under the hood.

⚠️ **Authorized use only.** Only scan hosts you own or have explicit
permission to test. All examples below use `scanme.nmap.org`, a host the Nmap
project provides specifically for legal scanning practice.

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

## Why I built it

I'm aiming to work in 3D art, but I'm studying IT and wanted hands-on security
skills to go with the theory from my coursework. I built this to understand how
port scanning and service reconnaissance actually work under the hood, rather
than just running tools like `nmap` without knowing what they do.

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
My first version scanned ports one at a time. Scanning ~1000 ports would take
about **____ minutes**.
<!-- fill in the number — remember the Measure-Command result -->

**4. Making it concurrent.**
I rewrote it with a thread pool. The same scan then took only **____ seconds**
— about **____x faster**.
<!-- fill in: ~11 seconds, ~90x -->

I learned threads help here because the work is **____-bound** — most of the
time is spent **____ for the network**, not computing. So many connections can
wait at the same time instead of one after another.
<!-- fill in: I/O-bound / waiting -->

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

## What I learned

<!-- TODO: 3–4 bullets in your own words. Some you could mention: -->
- How TCP connect scanning works at the socket level
- The difference between server-speaks-first (SSH) and client-speaks-first (HTTP) protocols
- Why concurrency helps I/O-bound work but not CPU-bound work
- That network behavior is non-deterministic and tools must be robust to it

---

## What I'd add next

<!-- TODO: pick a few. Ideas we discussed: -->
- Active HTTP banner grabbing (send a request, then read the response)
- Retries / adaptive timeouts for more reliable banner grabbing
- UDP scan support
- A companion SSH log parser (detecting brute-force attempts)

---

*Built step by step as a learning project. Every line is code I wrote and can
explain.*
