# netprobe

A fast network discovery and SNMP scanner written in Go. Discovers devices on your local subnet and queries SNMP-enabled devices for system information.

## Features

- Auto-detects local subnet
- Concurrent scanning with configurable workers
- SNMP v2c queries for device information
- Displays hostname, sysName, sysDescr, uptime, and location
- Clean tabular output

## Installation

```bash
go install github.com/krisarmstrong/netprobe@latest
```

Or build from source:

```bash
git clone https://github.com/krisarmstrong/netprobe.git
cd netprobe
go build -o netprobe
```

## Usage

```bash
# Scan auto-detected local subnet
./netprobe

# Scan specific subnet
./netprobe -subnet 10.0.0.0/24

# Use different SNMP community
./netprobe -subnet 192.168.1.0/24 -community private

# Adjust timeout and workers
./netprobe -timeout 2 -workers 100
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-subnet` | auto | Subnet to scan (CIDR notation) |
| `-community` | public | SNMP community string |
| `-timeout` | 1 | Timeout in seconds per host |
| `-workers` | 50 | Number of concurrent workers |

## Example Output

```
Auto-detected subnet: 10.0.0.0/24
Scanning 10.0.0.0/24 with community 'public'...

========================================================================================================================
IP              MAC               Hostname/SysName     Uptime       Description
========================================================================================================================
10.0.0.19       -                 ubuntu-desktop       2d 5h 10m    Linux ubuntu-gnu-linux 6.14.0 aarch64         [SNMP]
10.0.0.117      -                 fedora-linux-42      1d 12h 5m    Linux fedora-linux-42 6.12.0 aarch64          [SNMP]
10.0.0.163      -                 srv-dev-seed         5d 8h 33m    Linux srv-dev-seed 6.17.0 aarch64             [SNMP]
========================================================================================================================
Total: 3 devices found (3 with SNMP)
```

## Requirements

- Go 1.25+
- Network access to target subnet
- SNMP community string for SNMP-enabled devices

## License

MIT License - See [LICENSE](LICENSE) for details.
