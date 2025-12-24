# netprobe

A fast, colorful network discovery and SNMP scanner written in Go. Discovers devices on your local subnet, grabs service banners, and queries SNMP-enabled devices for system information.

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Auto-detect subnet** - No configuration needed, just run it
- **Port scanning** - Scan well-known ports or specify custom ranges
- **Banner grabbing** - Identifies services (nginx, Apache, OpenSSH versions, etc.)
- **SNMP v2c queries** - System info, uptime, location, kernel version
- **Beautiful output** - Color-coded, clean table or detailed tree view
- **JSON output** - Pipe to jq or other tools for scripting
- **Fast** - Concurrent scanning with configurable workers

## Installation

```bash
go install github.com/krisarmstrong/netprobe@latest
```

Or build from source:

```bash
git clone https://github.com/krisarmstrong/netprobe.git
cd netprobe
go build
```

## Quick Start

```bash
# Discover devices on your network
netprobe

# Scan common ports with banner grabbing
netprobe -p 22,80,443

# Detailed output with system info
netprobe -v -p 22,80,443

# JSON output for scripting
netprobe -json -p 22,80 | jq '.devices[].hostname'
```

## Usage

```
netprobe [options]

OPTIONS
    -subnet <cidr>     Subnet to scan (auto-detects if not specified)
    -community <str>   SNMP community string (default: "public")
    -timeout <sec>     Connection timeout in seconds (default: 1)
    -workers <num>     Concurrent workers (default: 50)

    -ports             Enable port scan (well-known ports 1-1023)
    -p <spec>          Custom ports: 80 | 22,80,443 | 1-1024 | 22,80,8000-9000

    -v                 Verbose output with detailed device info
    -json              Output as JSON (for scripting)
    -no-color          Disable colored output
    -version           Show version
```

## Example Output

### Default View
```
NETPROBE ───────────────────────────────────────────────────── 10.0.0.0/24

IP              HOSTNAME                     STATUS          SERVICES
─────────────── ──────────────────────────── ─────────────── ────────────────────
10.0.0.1        unifi.localdomain            ·               80 nginx │ 443 nginx
10.0.0.19       ubuntu-server                ● SNMP  10h     22 OpenSSH_9.9p1
10.0.0.117      fedora-linux-42              ● SNMP  9h      22 OpenSSH_10.0
───────────────────────────────────────────────────────────────────────────────────
6 devices │ 3 SNMP │ 8 ports
```

### Verbose View (-v)
```
═══════════════════════════════════════════════════════════════════════════════
  NETPROBE                                              │ 10.0.0.0/24 │ 6 devices
═══════════════════════════════════════════════════════════════════════════════

  ■ 10.0.0.19 ─ ubuntu-server  [SNMP]  ⏱ 10h 4m
    │   Linux ubuntu-server 6.14.0-37-generic aarch64
    │   📍 Home Lab
    └── 22/ssh ─── SSH-2.0-OpenSSH_9.9p1 Ubuntu-3ubuntu3.2

  ■ 10.0.0.117 ─ fedora-linux-42  [SNMP]  ⏱ 9h 58m
    │   Linux fedora-linux-42 6.17.12-300.fc43.aarch64
    │   📍 Home Lab
    └── 22/ssh ─── SSH-2.0-OpenSSH_10.0

═══════════════════════════════════════════════════════════════════════════════
  Summary: 6 devices │ 3 with SNMP │ 8 open ports
═══════════════════════════════════════════════════════════════════════════════
```

### JSON Output (-json)
```json
{
  "subnet": "10.0.0.0/24",
  "devices": [
    {
      "ip": "10.0.0.19",
      "hostname": "ubuntu-server",
      "snmp": {
        "enabled": true,
        "sys_descr": "Linux ubuntu-server 6.14.0-37-generic aarch64",
        "uptime": "10h 4m"
      },
      "ports": [
        {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.9p1"}
      ]
    }
  ],
  "summary": {"total": 6, "with_snmp": 3, "open_ports": 8}
}
```

## Requirements

- Go 1.21+
- Network access to target subnet
- SNMP community string for SNMP-enabled devices (default: "public")

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Support

If you find this tool useful, consider [sponsoring](https://github.com/sponsors/krisarmstrong) to support continued development.
