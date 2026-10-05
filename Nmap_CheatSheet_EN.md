# NMAP COMPLETE CHEAT SHEET
**Version 7.96SVN** | Complete Reference Guide

---

## 📋 BASIC USAGE
```bash
nmap [Scan Type(s)] [Options] {target specification}
```

---

## 🎯 TARGET SPECIFICATION

| Option | Description | Example |
|--------|-------------|---------|
| Direct targets | Hostnames, IP addresses, networks | `scanme.nmap.org`, `microsoft.com/24`, `192.168.0.1` |
| `-iL <file>` | Input from list of hosts/networks | `-iL hosts.txt` |
| `-iR <num>` | Choose random targets | `-iR 10000` |
| `--exclude <hosts>` | Exclude hosts/networks | `--exclude 192.168.1.1,10.0.0.1` |
| `--excludefile <file>` | Exclude list from file | `--excludefile exclude.txt` |

**Examples:**
- `scanme.nmap.org`
- `microsoft.com/24`
- `192.168.0.1`
- `10.0.0-255.1-254`

---

## 🔍 HOST DISCOVERY

| Option | Description |
|--------|-------------|
| `-sL` | List Scan - simply list targets to scan |
| `-sn` | Ping Scan - disable port scan |
| `-Pn` | Treat all hosts as online -- skip host discovery |
| `-PS[portlist]` | TCP SYN discovery to given ports |
| `-PA[portlist]` | TCP ACK discovery to given ports |
| `-PU[portlist]` | UDP discovery to given ports |
| `-PY[portlist]` | SCTP discovery to given ports |
| `-PE` | ICMP echo discovery probe |
| `-PP` | ICMP timestamp discovery probe |
| `-PM` | ICMP netmask request discovery probe |
| `-PO[protocol list]` | IP Protocol Ping |
| `-n` | Never do DNS resolution |
| `-R` | Always resolve DNS [default: sometimes] |
| `--dns-servers <servers>` | Specify custom DNS servers | `--dns-servers 8.8.8.8,1.1.1.1` |
| `--system-dns` | Use OS's DNS resolver |
| `--traceroute` | Trace hop path to each host |

---

## 🔎 SCAN TECHNIQUES

| Option | Description | Use Case |
|--------|-------------|----------|
| `-sS` | TCP SYN scan (stealth scan) | Fast, stealthy, default for privileged users |
| `-sT` | TCP Connect() scan | When SYN scan not available |
| `-sA` | TCP ACK scan | Firewall rule detection |
| `-sW` | TCP Window scan | Similar to ACK scan, uses window size |
| `-sM` | TCP Maimon scan | Uses FIN/ACK probes |
| `-sU` | UDP Scan | Scan UDP ports |
| `-sN` | TCP Null scan | Sets no flags |
| `-sF` | TCP FIN scan | Sets FIN flag |
| `-sX` | TCP Xmas scan | Sets FIN, PSH, URG flags |
| `--scanflags <flags>` | Customize TCP scan flags | Advanced customization |
| `-sI <zombie[:port]>` | Idle scan | Stealthiest scan, uses zombie host |
| `-sY` | SCTP INIT scan | SCTP protocol scan |
| `-sZ` | SCTP COOKIE-ECHO scan | SCTP cookie echo scan |
| `-sO` | IP protocol scan | Scan IP protocols |
| `-b <FTP relay>` | FTP bounce scan | Use FTP server as proxy |

---

## 🔌 PORT SPECIFICATION AND SCAN ORDER

| Option | Description | Example |
|--------|-------------|---------|
| `-p <ranges>` | Only scan specified ports | `-p22`, `-p1-65535`, `-p U:53,111,137,T:21-25,80,139,8080,S:9` |
| `--exclude-ports <ranges>` | Exclude specified ports | `--exclude-ports 22,80,443` |
| `-F` | Fast mode - Scan fewer ports | Top 100 ports |
| `-r` | Scan ports sequentially - don't randomize | Ordered scan |
| `--top-ports <number>` | Scan N most common ports | `--top-ports 1000` |
| `--port-ratio <ratio>` | Scan ports more common than ratio | `--port-ratio 0.1` |

**Port Range Examples:**
- `-p22` - Single port
- `-p1-65535` - All ports
- `-p U:53,111,137` - UDP ports
- `-p T:21-25,80,139,8080` - TCP ports
- `-p S:9` - SCTP port

---

## 🔬 SERVICE/VERSION DETECTION

| Option | Description |
|--------|-------------|
| `-sV` | Probe open ports to determine service/version info |
| `--version-intensity <0-9>` | Set intensity (0=light, 9=all probes) |
| `--version-light` | Limit to most likely probes (intensity 2) |
| `--version-all` | Try every single probe (intensity 9) |
| `--version-trace` | Show detailed version scan activity (debugging) |

---

## 📜 SCRIPT SCAN (NSE - Nmap Scripting Engine)

| Option | Description | Example |
|--------|-------------|---------|
| `-sC` | Equivalent to `--script=default` | Run default scripts |
| `--script=<scripts>` | Run specific scripts/categories | `--script=http-enum,vuln` |
| `--script-args=<args>` | Provide arguments to scripts | `--script-args user=admin,pass=test` |
| `--script-args-file=<file>` | Provide NSE script args in a file | `--script-args-file args.txt` |
| `--script-trace` | Show all data sent and received | Debug script execution |
| `--script-updatedb` | Update the script database | Update NSE scripts |
| `--script-help=<scripts>` | Show help about scripts | `--script-help http-enum` |

**Script Categories:**
- `default` - Default safe scripts
- `vuln` - Vulnerability detection
- `exploit` - Exploitation scripts
- `auth` - Authentication bypass
- `brute` - Brute force attacks
- `discovery` - Host/service discovery
- `dos` - Denial of service
- `malware` - Malware detection
- `safe` - Safe scripts only
- `version` - Version detection

---

## 💻 OS DETECTION

| Option | Description |
|--------|-------------|
| `-O` | Enable OS detection |
| `--osscan-limit` | Limit OS detection to promising targets |
| `--osscan-guess` | Guess OS more aggressively |

---

## ⚡ TIMING AND PERFORMANCE

**Time Format:** seconds, or append `ms` (milliseconds), `s` (seconds), `m` (minutes), `h` (hours)
**Example:** `30m`, `500ms`, `2h`

| Option | Description | Example |
|--------|-------------|---------|
| `-T<0-5>` | Set timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane) | `-T4` |
| `--min-hostgroup <size>` | Parallel host scan group sizes (minimum) | `--min-hostgroup 10` |
| `--max-hostgroup <size>` | Parallel host scan group sizes (maximum) | `--max-hostgroup 256` |
| `--min-parallelism <num>` | Probe parallelization (minimum) | `--min-parallelism 10` |
| `--max-parallelism <num>` | Probe parallelization (maximum) | `--max-parallelism 100` |
| `--min-rtt-timeout <time>` | Minimum probe round trip time | `--min-rtt-timeout 100ms` |
| `--max-rtt-timeout <time>` | Maximum probe round trip time | `--max-rtt-timeout 1000ms` |
| `--initial-rtt-timeout <time>` | Initial probe round trip time | `--initial-rtt-timeout 500ms` |
| `--max-retries <tries>` | Caps port scan probe retransmissions | `--max-retries 3` |
| `--host-timeout <time>` | Give up on target after this long | `--host-timeout 30m` |
| `--scan-delay <time>` | Adjust delay between probes | `--scan-delay 1s` |
| `--max-scan-delay <time>` | Maximum delay between probes | `--max-scan-delay 5s` |
| `--min-rate <number>` | Send packets no slower than N per second | `--min-rate 100` |
| `--max-rate <number>` | Send packets no faster than N per second | `--max-rate 1000` |

**Timing Templates:**
- `-T0` - Paranoid (very slow, stealthy)
- `-T1` - Sneaky (slow, stealthy)
- `-T2` - Polite (slower, less intrusive)
- `-T3` - Normal (default)
- `-T4` - Aggressive (faster)
- `-T5` - Insane (very fast, may miss things)

---

## 🛡️ FIREWALL/IDS EVASION AND SPOOFING

| Option | Description | Example |
|--------|-------------|---------|
| `-f` | Fragment packets | Fragment IP packets |
| `--mtu <val>` | Fragment packets with given MTU | `--mtu 16` |
| `-D <decoys>` | Cloak scan with decoys | `-D RND:10,192.168.1.1,ME` |
| `-S <IP>` | Spoof source address | `-S 192.168.1.100` |
| `-e <iface>` | Use specified interface | `-e eth0` |
| `-g <port>` | Use given source port | `-g 53` |
| `--source-port <port>` | Use given source port | `--source-port 53` |
| `--proxies <urls>` | Relay through HTTP/SOCKS4 proxies | `--proxies http://proxy:8080` |
| `--data <hex>` | Append custom hex payload | `--data 0x123456` |
| `--data-string <string>` | Append custom ASCII string | `--data-string "GET / HTTP/1.0"` |
| `--data-length <num>` | Append random data | `--data-length 100` |
| `--ip-options <options>` | Send packets with IP options | `--ip-options "R"` |
| `--ttl <val>` | Set IP time-to-live field | `--ttl 64` |
| `--spoof-mac <mac>` | Spoof MAC address | `--spoof-mac 00:11:22:33:44:55` |
| `--badsum` | Send packets with bogus checksum | Test firewall responses |

---

## 📤 OUTPUT

| Option | Description | Example |
|--------|-------------|---------|
| `-oN <file>` | Output in normal format | `-oN scan.txt` |
| `-oX <file>` | Output in XML format | `-oX scan.xml` |
| `-oS <file>` | Output in Script Kiddie format | `-oS scan.txt` |
| `-oG <file>` | Output in Grepable format | `-oG scan.gnmap` |
| `-oA <basename>` | Output in all three major formats | `-oA scan` (creates .nmap, .xml, .gnmap) |
| `-v` | Increase verbosity level | `-v`, `-vv`, `-vvv` |
| `-d` | Increase debugging level | `-d`, `-dd`, `-ddd` |
| `--reason` | Display reason port is in particular state | Show why port is open/closed |
| `--open` | Only show open (or possibly open) ports | Filter results |
| `--packet-trace` | Show all packets sent and received | Debug network traffic |
| `--iflist` | Print host interfaces and routes | Debug network config |
| `--append-output` | Append to output files | Don't overwrite |
| `--resume <file>` | Resume an aborted scan | `--resume scan.xml` |
| `--noninteractive` | Disable runtime keyboard interactions | Script-friendly |
| `--stylesheet <path/URL>` | XSL stylesheet for XML output | `--stylesheet style.xsl` |
| `--webxml` | Reference stylesheet from Nmap.Org | Portable XML |
| `--no-stylesheet` | Prevent XSL stylesheet association | Plain XML |

---

## 🔧 MISCELLANEOUS

| Option | Description |
|--------|-------------|
| `-6` | Enable IPv6 scanning |
| `-A` | Enable OS detection, version detection, script scanning, and traceroute |
| `--datadir <dirname>` | Specify custom Nmap data file location |
| `--send-eth` | Send using raw ethernet frames |
| `--send-ip` | Send using IP packets |
| `--privileged` | Assume user is fully privileged |
| `--unprivileged` | Assume user lacks raw socket privileges |
| `-V` | Print version number |
| `-h` | Print help summary page |

---

## 💡 COMMON SCAN EXAMPLES

### Basic Scans
```bash
# Simple scan
nmap 192.168.1.1

# Scan specific ports
nmap -p 22,80,443 192.168.1.1

# Scan port range
nmap -p 1-1000 192.168.1.1

# Scan all ports
nmap -p- 192.168.1.1
```

### Stealth Scans
```bash
# SYN scan (stealth)
nmap -sS 192.168.1.1

# Null scan
nmap -sN 192.168.1.1

# FIN scan
nmap -sF 192.168.1.1

# Xmas scan
nmap -sX 192.168.1.1
```

### Comprehensive Scans
```bash
# Aggressive scan (OS, version, scripts, traceroute)
nmap -A 192.168.1.1

# Verbose aggressive scan
nmap -v -A scanme.nmap.org

# Full scan with all options
nmap -sS -sV -sC -O -A -T4 192.168.1.1
```

### Network Scans
```bash
# Scan entire subnet
nmap 192.168.1.0/24

# Ping scan only (host discovery)
nmap -sn 192.168.0.0/16 10.0.0.0/8

# Scan multiple networks
nmap 192.168.1.0/24 10.0.0.0/24
```

### Advanced Scans
```bash
# UDP scan
nmap -sU 192.168.1.1

# Version detection
nmap -sV 192.168.1.1

# OS detection
nmap -O 192.168.1.1

# Script scan
nmap -sC 192.168.1.1

# Specific script category
nmap --script vuln 192.168.1.1
```

### Firewall Evasion
```bash
# Fragment packets
nmap -f 192.168.1.1

# Use decoys
nmap -D RND:10 192.168.1.1

# Spoof source IP
nmap -S 192.168.1.100 192.168.1.1

# Slow scan (evade IDS)
nmap -T1 192.168.1.1
```

### Output Examples
```bash
# Save to file
nmap -oN scan.txt 192.168.1.1

# Save in all formats
nmap -oA scan 192.168.1.1

# Verbose output
nmap -vv 192.168.1.1

# Show only open ports
nmap --open 192.168.1.1
```

### From Examples in Help
```bash
# Verbose aggressive scan
nmap -v -A scanme.nmap.org

# Ping scan multiple networks
nmap -v -sn 192.168.0.0/16 10.0.0.0/8

# Random targets, no ping, port 80
nmap -v -iR 10000 -Pn -p 80
```

---

## 🎯 QUICK REFERENCE BY CATEGORY

### Most Common Commands
- `nmap -sS -sV -sC -O -A -T4 <target>` - Full comprehensive scan
- `nmap -sn <target>` - Host discovery only
- `nmap -p- <target>` - All ports scan
- `nmap -sU <target>` - UDP scan
- `nmap --script vuln <target>` - Vulnerability scan

### Performance Tuning
- `-T0` - Slowest, most stealthy
- `-T3` - Normal (default)
- `-T4` - Aggressive (recommended)
- `-T5` - Fastest (may miss things)

### Output Formats
- `-oN` - Normal (human readable)
- `-oX` - XML (parsable)
- `-oG` - Grepable (grep-friendly)
- `-oA` - All formats

---

## 📚 ADDITIONAL RESOURCES

- **Official Manual:** https://nmap.org/book/man.html
- **Official Website:** https://nmap.org
- **NSE Scripts Documentation:** https://nmap.org/nsedoc/

---

**Last Updated:** Based on Nmap 7.96SVN
**Complete Reference:** All options and examples included

