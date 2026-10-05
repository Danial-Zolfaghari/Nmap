# NMAP COMPLETE SCHEMATIC DIAGRAM
**Version 7.96SVN** | Visual Reference Guide

---

## 📊 NMAP WORKFLOW OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NMAP SCAN WORKFLOW                           │
└─────────────────────────────────────────────────────────────────────┘

    START
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  TARGET SPECIFICATION                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Direct IP    │  │ Hostname     │  │ Network      │          │
│  │ 192.168.1.1  │  │ domain.com   │  │ 192.168.1.0/24│          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -iL file.txt │  │ -iR 10000    │  │ --exclude    │          │
│  │ List input   │  │ Random       │  │ Exclude hosts│          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  HOST DISCOVERY                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -sL          │  │ -sn          │  │ -Pn          │          │
│  │ List Scan    │  │ Ping Only    │  │ No Ping      │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -PS/PA/PU/PY │  │ -PE/PP/PM    │  │ -PO          │          │
│  │ TCP/SCTP     │  │ ICMP Probes  │  │ IP Protocol  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -n / -R      │  │ --dns-servers│  │ --traceroute │          │
│  │ DNS Control  │  │ Custom DNS   │  │ Path Trace   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  SCAN TECHNIQUE SELECTION                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  TCP Scans                                                │   │
│  │  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐        │   │
│  │  │-sS │  │-sT │  │-sA │  │-sW │  │-sM │  │-sN │        │   │
│  │  │SYN │  │Conn│  │ACK │  │Win │  │Mai │  │Null│        │   │
│  │  └────┘  └────┘  └────┘  └────┘  └────┘  └────┘        │   │
│  │  ┌────┐  ┌────┐                                          │   │
│  │  │-sF │  │-sX │  ┌──────────────────────┐               │   │
│  │  │FIN │  │Xmas│  │--scanflags <custom>  │               │   │
│  │  └────┘  └────┘  └──────────────────────┘               │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  UDP & Other Scans                                        │   │
│  │  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐                 │   │
│  │  │-sU │  │-sY │  │-sZ │  │-sO │  │-sI │                 │   │
│  │  │UDP │  │SCTP│  │SCTP│  │IP  │  │Idle│                 │   │
│  │  └────┘  └────┘  └────┘  └────┘  └────┘                 │   │
│  │  ┌──────────────────────┐                                │   │
│  │  │-b <FTP relay>        │                                │   │
│  │  │FTP Bounce            │                                │   │
│  │  └──────────────────────┘                                │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  PORT SPECIFICATION                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -p 22        │  │ -p 1-1000    │  │ -p-          │          │
│  │ Single       │  │ Range        │  │ All Ports    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -p U:53,137  │  │ -p T:80,443  │  │ -p S:9       │          │
│  │ UDP Ports    │  │ TCP Ports    │  │ SCTP Port    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -F           │  │ --top-ports  │  │ -r            │          │
│  │ Fast (100)   │  │ N Common     │  │ Sequential    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  ADVANCED FEATURES                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -sV          │  │ -O           │  │ -sC          │          │
│  │ Version      │  │ OS Detect    │  │ Scripts      │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -A           │  │ --script     │  │ --traceroute │          │
│  │ Aggressive   │  │ Custom NSE   │  │ Trace Path   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT FORMAT                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -oN          │  │ -oX          │  │ -oG          │          │
│  │ Normal       │  │ XML          │  │ Grepable     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ -oA          │  │ -v / -vv     │  │ -d / -dd     │          │
│  │ All Formats  │  │ Verbose      │  │ Debug        │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
     END
```

---

## 🎯 SCAN TECHNIQUE DECISION TREE

```
                    START SCAN
                       │
                       ▼
            ┌──────────────────────┐
            │ Privileged User?     │
            └──────────────────────┘
                   │         │
              YES  │         │  NO
                   │         │
                   ▼         ▼
            ┌──────────┐  ┌──────────┐
            │ -sS      │  │ -sT      │
            │ TCP SYN  │  │ TCP Conn │
            └──────────┘  └──────────┘
                   │         │
                   └────┬────┘
                        │
                        ▼
            ┌──────────────────────┐
            │ Stealth Needed?      │
            └──────────────────────┘
                   │         │
              YES  │         │  NO
                   │         │
                   ▼         ▼
        ┌──────────────┐  ┌──────────┐
        │ -sN / -sF    │  │ Continue │
        │ Null / FIN   │  │ Normal   │
        └──────────────┘  └──────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ UDP Ports?           │
        └──────────────────────┘
                   │         │
              YES  │         │  NO
                   │         │
                   ▼         ▼
            ┌──────────┐  ┌──────────┐
            │ -sU      │  │ Continue │
            │ UDP Scan │  │ TCP Scan │
            └──────────┘  └──────────┘
```

---

## 🔍 PORT STATE DETECTION FLOW

```
┌─────────────────────────────────────────────────────────────┐
│                    PORT SCANNING PROCESS                     │
└─────────────────────────────────────────────────────────────┘

    Send Probe Packet
           │
           ▼
    ┌─────────────────┐
    │ Receive Response│
    └─────────────────┘
           │
           ├─────────────────┬─────────────────┬──────────────┐
           │                 │                 │              │
           ▼                 ▼                 ▼              ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ SYN-ACK  │    │ RST-ACK  │    │ No Response│   │ ICMP     │
    │ Received │    │ Received │    │ Received  │    │ Unreach  │
    └──────────┘    └──────────┘    └──────────┘    └──────────┘
           │                 │                 │              │
           ▼                 ▼                 ▼              ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  OPEN    │    │ CLOSED   │    │ FILTERED │    │ FILTERED │
    └──────────┘    └──────────┘    └──────────┘    └──────────┘
```

---

## 🛡️ FIREWALL EVASION TECHNIQUES

```
┌─────────────────────────────────────────────────────────────┐
│              FIREWALL EVASION OPTIONS                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Fragmentation  │      │  Timing         │      │  Decoy/Stealth  │
│  ────────────── │      │  ────────────── │      │  ────────────── │
│  -f             │      │  -T0 (Paranoid) │      │  -D <decoy>     │
│  --mtu <val>    │      │  -T1 (Sneaky)   │      │  -S <spoof IP>  │
│  Small packets  │      │  --scan-delay   │      │  --source-port  │
└─────────────────┘      └─────────────────┘      └─────────────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  Advanced Techniques   │
                    │  ─────────────────────│
                    │  --data <hex>         │
                    │  --data-string        │
                    │  --ttl <val>          │
                    │  --spoof-mac          │
                    │  --badsum             │
                    │  --proxies            │
                    └────────────────────────┘
```

---

## ⚡ TIMING TEMPLATES HIERARCHY

```
┌─────────────────────────────────────────────────────────────┐
│                   TIMING TEMPLATES (-T)                      │
└─────────────────────────────────────────────────────────────┘

    -T0 (Paranoid)
    │  ├─ Very Slow (5 minutes between probes)
    │  ├─ Maximum Stealth
    │  └─ IDS Evasion: ⭐⭐⭐⭐⭐
    │
    -T1 (Sneaky)
    │  ├─ Slow (15 seconds between probes)
    │  ├─ High Stealth
    │  └─ IDS Evasion: ⭐⭐⭐⭐
    │
    -T2 (Polite)
    │  ├─ Moderate Speed (0.4 seconds between probes)
    │  ├─ Normal Stealth
    │  └─ IDS Evasion: ⭐⭐⭐
    │
    -T3 (Normal) ← DEFAULT
    │  ├─ Balanced Speed
    │  ├─ Standard Operations
    │  └─ IDS Evasion: ⭐⭐
    │
    -T4 (Aggressive)
    │  ├─ Fast (no delay <10ms)
    │  ├─ Recommended for most scans
    │  └─ IDS Evasion: ⭐
    │
    -T5 (Insane)
    │  ├─ Very Fast (no delay <5ms)
    │  ├─ May miss things
    │  └─ IDS Evasion: ⭐
```

---

## 📜 NSE (NMAP SCRIPTING ENGINE) ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│              NSE SCRIPT EXECUTION FLOW                       │
└─────────────────────────────────────────────────────────────┘

    -sC or --script
           │
           ▼
    ┌─────────────────┐
    │ Load Scripts    │
    └─────────────────┘
           │
           ├─────────────────┬─────────────────┬──────────────┐
           │                 │                 │              │
           ▼                 ▼                 ▼              ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ default  │    │ vuln     │    │ exploit  │    │ auth     │
    │ Safe     │    │ Security │    │ Attacks  │    │ Auth     │
    └──────────┘    └──────────┘    └──────────┘    └──────────┘
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ discovery│    │ brute    │    │ dos      │    │ malware  │
    │ Network  │    │ Force    │    │ DoS      │    │ Detection│
    └──────────┘    └──────────┘    └──────────┘    └──────────┘
           │
           ▼
    ┌─────────────────┐
    │ Parse Arguments │
    │ --script-args   │
    └─────────────────┘
           │
           ▼
    ┌─────────────────┐
    │ Execute Scripts │
    └─────────────────┘
           │
           ▼
    ┌─────────────────┐
    │ Collect Results │
    └─────────────────┘
```

---

## 🔬 SERVICE/VERSION DETECTION PROCESS

```
┌─────────────────────────────────────────────────────────────┐
│          SERVICE/VERSION DETECTION WORKFLOW                  │
└─────────────────────────────────────────────────────────────┘

    -sV Option
           │
           ▼
    ┌─────────────────┐
    │ Find Open Ports │
    └─────────────────┘
           │
           ▼
    ┌─────────────────┐
    │ Send Probes     │
    │ (Banners, etc)  │
    └─────────────────┘
           │
           ├─────────────────┬─────────────────┬──────────────┐
           │                 │                 │              │
           ▼                 ▼                 ▼              ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Match    │    │ Match    │    │ No Match │    │ Timeout  │
    │ Exact    │    │ Pattern  │    │ Found    │    │ Occurred │
    └──────────┘    └──────────┘    └──────────┘    └──────────┘
           │                 │                 │              │
           ▼                 ▼                 ▼              ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Version  │    │ Possible │    │ Unknown  │    │ Retry or │
    │ Detected │    │ Version  │    │ Service  │    │ Skip     │
    └──────────┘    └──────────┘    └──────────┘    └──────────┘

    Intensity Levels:
    ──────────────────
    --version-intensity 0-9
    ├─ 0-2: Light (faster, less accurate)
    ├─ 3-6: Normal (balanced)
    └─ 7-9: Heavy (slower, more accurate)
```

---

## 💻 OS DETECTION PROCESS

```
┌─────────────────────────────────────────────────────────────┐
│              OS DETECTION WORKFLOW (-O)                      │
└─────────────────────────────────────────────────────────────┘

    -O Option
           │
           ▼
    ┌─────────────────┐
    │ Gather TCP/IP   │
    │ Fingerprints    │
    └─────────────────┘
           │
           ├─────────────────┬─────────────────┬──────────────┐
           │                 │                 │              │
           ▼                 ▼                 ▼              ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ TCP      │    │ ICMP     │    │ IP       │    │ Others   │
    │ Options  │    │ Responses│    │ Options  │    │          │
    └──────────┘    └──────────┘    └──────────┘    └──────────┘
           │
           ▼
    ┌─────────────────┐
    │ Match Against   │
    │ Fingerprint DB  │
    └─────────────────┘
           │
           ├─────────────────┬─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Exact    │    │ Possible │    │ No Match │
    │ Match    │    │ Match    │    │ Found    │
    └──────────┘    └──────────┘    └──────────┘
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Display  │    │ --osscan │    │ --osscan │
    │ OS Info  │    │ -guess   │    │ -limit   │
    └──────────┘    └──────────┘    └──────────┘
```

---

## 📤 OUTPUT FORMATS COMPARISON

```
┌─────────────────────────────────────────────────────────────┐
│                  OUTPUT FORMAT OPTIONS                       │
└─────────────────────────────────────────────────────────────┘

    -oN (Normal)              -oX (XML)                -oG (Grepable)
    ─────────────             ─────────                ──────────────
    Human-readable            Machine-readable         Grep-friendly
    │                         │                        │
    ├─ Standard output        ├─ Structured data       ├─ One line per host
    ├─ Easy to read           ├─ Parsable              ├─ Easy to grep
    ├─ Detailed info          ├─ Schema validation     ├─ Quick filtering
    └─ Default format         └─ Best for automation   └─ Log analysis

    -oA (All Formats)
    ─────────────────
    Creates all three formats with same basename
    Example: -oA scan → scan.nmap, scan.xml, scan.gnmap
```

---

## 🎯 COMPLETE SCAN EXAMPLE FLOW

```
┌─────────────────────────────────────────────────────────────┐
│         EXAMPLE: nmap -sS -sV -sC -O -A -T4 target          │
└─────────────────────────────────────────────────────────────┘

1. TARGET SPECIFICATION
   └─> target (192.168.1.1 or domain.com)

2. TIMING SETTING
   └─> -T4 (Aggressive timing template)

3. HOST DISCOVERY (Implicit)
   └─> Standard ICMP/TCP ping probes

4. SCAN TECHNIQUE
   └─> -sS (TCP SYN scan)

5. PORT SCANNING
   └─> Default top 1000 ports

6. SERVICE DETECTION
   └─> -sV (Version detection on open ports)

7. SCRIPT SCANNING
   └─> -sC (Default NSE scripts)

8. OS DETECTION
   └─> -O (OS detection)

9. TRACEROUTE (Included in -A)
   └─> Path to target

10. OUTPUT
    └─> Standard output (add -oN for file)

RESULT: Comprehensive scan with all features enabled
```

---

## 🔧 COMMAND LINE OPTION CATEGORIES

```
┌─────────────────────────────────────────────────────────────┐
│              NMAP OPTION CATEGORIES                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ TARGET SPECIFICATION                                          │
├─────────────────────────────────────────────────────────────┤
│ -iL, -iR, --exclude, --excludefile                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ HOST DISCOVERY                                                │
├─────────────────────────────────────────────────────────────┤
│ -sL, -sn, -Pn, -PS/PA/PU/PY, -PE/PP/PM, -PO                │
│ -n, -R, --dns-servers, --system-dns, --traceroute           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCAN TECHNIQUES                                               │
├─────────────────────────────────────────────────────────────┤
│ -sS, -sT, -sA, -sW, -sM, -sU, -sN, -sF, -sX                │
│ -sY, -sZ, -sO, -sI, -b, --scanflags                         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ PORT SPECIFICATION                                            │
├─────────────────────────────────────────────────────────────┤
│ -p, --exclude-ports, -F, -r, --top-ports, --port-ratio      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SERVICE/VERSION DETECTION                                     │
├─────────────────────────────────────────────────────────────┤
│ -sV, --version-intensity, --version-light, --version-all    │
│ --version-trace                                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCRIPT SCAN                                                   │
├─────────────────────────────────────────────────────────────┤
│ -sC, --script, --script-args, --script-args-file            │
│ --script-trace, --script-updatedb, --script-help            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ OS DETECTION                                                  │
├─────────────────────────────────────────────────────────────┤
│ -O, --osscan-limit, --osscan-guess                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ TIMING AND PERFORMANCE                                        │
├─────────────────────────────────────────────────────────────┤
│ -T<0-5>, --min/max-hostgroup, --min/max-parallelism         │
│ --min/max/initial-rtt-timeout, --max-retries                │
│ --host-timeout, --scan-delay, --max-scan-delay              │
│ --min-rate, --max-rate                                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ FIREWALL/IDS EVASION                                          │
├─────────────────────────────────────────────────────────────┤
│ -f, --mtu, -D, -S, -e, -g, --source-port, --proxies        │
│ --data, --data-string, --data-length, --ip-options          │
│ --ttl, --spoof-mac, --badsum                                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ OUTPUT                                                        │
├─────────────────────────────────────────────────────────────┤
│ -oN, -oX, -oS, -oG, -oA, -v, -d, --reason, --open          │
│ --packet-trace, --iflist, --append-output, --resume         │
│ --noninteractive, --stylesheet, --webxml, --no-stylesheet   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ MISCELLANEOUS                                                 │
├─────────────────────────────────────────────────────────────┤
│ -6, -A, --datadir, --send-eth, --send-ip                    │
│ --privileged, --unprivileged, -V, -h                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 SCAN STRATEGY DECISION MATRIX

```
┌─────────────────────────────────────────────────────────────┐
│         SCAN STRATEGY BY USE CASE                            │
└─────────────────────────────────────────────────────────────┘

USE CASE                    │ COMMAND                     │ NOTES
────────────────────────────┼─────────────────────────────┼────────────────
Quick Host Check            │ nmap -sn target             │ Ping only
Basic Port Scan             │ nmap target                 │ Default scan
Fast Port Scan              │ nmap -F target              │ Top 100 ports
All Ports Scan              │ nmap -p- target             │ Full port scan
Stealth Scan                │ nmap -sS -T1 target         │ Slow, stealthy
Stealthiest Scan            │ nmap -sN -T0 target         │ Null, paranoid
UDP Scan                    │ nmap -sU target             │ UDP ports
Version Detection           │ nmap -sV target             │ Service versions
OS Detection                │ nmap -O target              │ Operating system
Comprehensive Scan          │ nmap -A target              │ All features
Vulnerability Scan          │ nmap --script vuln target   │ Security scan
Firewall Bypass             │ nmap -f -D RND:10 target    │ Fragment + decoys
Network Discovery           │ nmap -sn 192.168.1.0/24     │ Host discovery
Full Network Scan           │ nmap 192.168.1.0/24         │ Complete subnet
```

---

## 📊 PORT STATE DIAGRAM

```
┌─────────────────────────────────────────────────────────────┐
│                    PORT STATES                               │
└─────────────────────────────────────────────────────────────┘

         ┌─────────────────┐
         │   OPEN          │  ← Port is accepting connections
         │   (open)        │
         └─────────────────┘
                  │
                  ├─────────────────┐
                  │                 │
         ┌─────────────────┐       │
         │   FILTERED      │       │
         │   (filtered)    │  ← Firewall/IDS blocking
         └─────────────────┘       │
                  │                 │
                  │         ┌─────────────────┐
                  │         │   CLOSED        │
                  │         │   (closed)      │  ← Port not listening
                  │         └─────────────────┘
                  │
         ┌─────────────────┐
         │   OPEN|FILTERED │  ← Uncertain (UDP, FIN, etc)
         │   (open|filtered)│
         └─────────────────┘
                  │
         ┌─────────────────┐
         │   CLOSED|FILTERED│  ← Uncertain (rare)
         │   (closed|filtered)│
         └─────────────────┘

Detection Methods:
──────────────────
OPEN:        SYN-ACK received
CLOSED:      RST received
FILTERED:    No response or ICMP unreachable
UNCERTAIN:   Used with scans that can't distinguish
```

---

**Last Updated:** Based on Nmap 7.96SVN
**Complete Visual Reference:** All aspects covered

