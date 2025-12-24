package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Device represents a discovered network device
type Device struct {
	IP          string
	MAC         string
	Hostname    string
	SysName     string
	SysDescr    string
	SysLocation string
	SysContact  string
	Uptime      string
	Reachable   bool
	SNMPEnabled bool
}

var (
	subnet    string
	community string
	timeout   int
	workers   int
	verbose   bool
)

func init() {
	flag.StringVar(&subnet, "subnet", "", "Subnet to scan (e.g., 192.168.1.0/24)")
	flag.StringVar(&community, "community", "public", "SNMP community string")
	flag.IntVar(&timeout, "timeout", 1, "Timeout in seconds for each host")
	flag.IntVar(&workers, "workers", 50, "Number of concurrent workers")
	flag.BoolVar(&verbose, "v", false, "Verbose output - show detailed SNMP info")
}

func main() {
	flag.Parse()

	if subnet == "" {
		subnet = detectLocalSubnet()
		if subnet == "" {
			fmt.Println("Error: Could not detect local subnet. Please specify with -subnet")
			os.Exit(1)
		}
		fmt.Printf("Auto-detected subnet: %s\n", subnet)
	}

	fmt.Printf("Scanning %s with community '%s'...\n\n", subnet, community)

	ips, err := getIPsInSubnet(subnet)
	if err != nil {
		fmt.Printf("Error parsing subnet: %v\n", err)
		os.Exit(1)
	}

	devices := scanNetwork(ips)

	// Sort by IP
	sort.Slice(devices, func(i, j int) bool {
		return ipToInt(devices[i].IP) < ipToInt(devices[j].IP)
	})

	printResults(devices)
}

func detectLocalSubnet() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				// Skip link-local addresses
				if ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				return ipnet.String()
			}
		}
	}
	return ""
}

func getIPsInSubnet(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and larger
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanNetwork(ips []string) []Device {
	var devices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobs := make(chan string, len(ips))

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				device := scanHost(ip)
				if device.Reachable || device.SNMPEnabled {
					mu.Lock()
					devices = append(devices, device)
					mu.Unlock()
				}
			}
		}()
	}

	// Send jobs
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	wg.Wait()
	return devices
}

func scanHost(ip string) Device {
	device := Device{IP: ip}

	// Try SNMP first
	snmpDevice := querySNMP(ip)
	if snmpDevice.SNMPEnabled {
		return snmpDevice
	}

	// Fall back to ping/TCP check
	if isReachable(ip) {
		device.Reachable = true
		device.Hostname = lookupHostname(ip)
		device.MAC = lookupMAC(ip)
	}

	return device
}

func isReachable(ip string) bool {
	conn, err := net.DialTimeout("tcp", ip+":22", time.Duration(timeout)*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	conn, err = net.DialTimeout("tcp", ip+":80", time.Duration(timeout)*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	conn, err = net.DialTimeout("tcp", ip+":443", time.Duration(timeout)*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

func querySNMP(ip string) Device {
	device := Device{IP: ip}

	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		return device
	}
	defer snmp.Conn.Close()

	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
	}

	result, err := snmp.Get(oids)
	if err != nil {
		return device
	}

	device.SNMPEnabled = true
	device.Reachable = true

	for _, variable := range result.Variables {
		switch variable.Name {
		case ".1.3.6.1.2.1.1.1.0":
			device.SysDescr = strings.TrimSpace(toString(variable))
		case ".1.3.6.1.2.1.1.3.0":
			if ticks, ok := variable.Value.(uint32); ok {
				device.Uptime = formatUptime(ticks)
			}
		case ".1.3.6.1.2.1.1.4.0":
			device.SysContact = toString(variable)
		case ".1.3.6.1.2.1.1.5.0":
			device.SysName = toString(variable)
		case ".1.3.6.1.2.1.1.6.0":
			device.SysLocation = toString(variable)
		}
	}

	device.MAC = lookupMAC(ip)
	if device.SysName == "" {
		device.Hostname = lookupHostname(ip)
	}

	return device
}

func toString(v gosnmp.SnmpPDU) string {
	switch v.Type {
	case gosnmp.OctetString:
		return string(v.Value.([]byte))
	default:
		return fmt.Sprintf("%v", v.Value)
	}
}

func formatUptime(ticks uint32) string {
	seconds := ticks / 100
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func truncateString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func lookupHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func lookupMAC(ip string) string {
	// Try to get MAC from ARP cache (works on local subnet)
	// This is a simplified approach - real implementation would use ARP
	return ""
}

func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i, part := range parts {
		var val uint32
		fmt.Sscanf(part, "%d", &val)
		result |= val << (24 - 8*i)
	}
	return result
}

func printResults(devices []Device) {
	if len(devices) == 0 {
		fmt.Println("No devices found.")
		return
	}

	snmpCount := 0
	reachableCount := 0

	if verbose {
		// Verbose output - detailed info for each device
		for _, d := range devices {
			reachableCount++
			if d.SNMPEnabled {
				snmpCount++
			}

			fmt.Println(strings.Repeat("─", 80))
			fmt.Printf("│ %-15s │ %s\n", "IP Address", d.IP)

			name := d.SysName
			if name == "" {
				name = d.Hostname
			}
			if name != "" {
				fmt.Printf("│ %-15s │ %s\n", "Hostname", name)
			}

			if d.MAC != "" {
				fmt.Printf("│ %-15s │ %s\n", "MAC Address", d.MAC)
			}

			if d.SNMPEnabled {
				fmt.Printf("│ %-15s │ %s\n", "SNMP", "✓ Enabled")
				if d.SysDescr != "" {
					fmt.Printf("│ %-15s │ %s\n", "System", d.SysDescr)
				}
				if d.Uptime != "" {
					fmt.Printf("│ %-15s │ %s\n", "Uptime", d.Uptime)
				}
				if d.SysLocation != "" {
					fmt.Printf("│ %-15s │ %s\n", "Location", d.SysLocation)
				}
				if d.SysContact != "" {
					fmt.Printf("│ %-15s │ %s\n", "Contact", d.SysContact)
				}
			} else {
				fmt.Printf("│ %-15s │ %s\n", "SNMP", "✗ Not available")
			}
		}
		fmt.Println(strings.Repeat("─", 80))
	} else {
		// Compact table output
		fmt.Println(strings.Repeat("=", 120))
		fmt.Printf("%-15s %-17s %-20s %-12s %-50s\n", "IP", "MAC", "Hostname/SysName", "Uptime", "Description")
		fmt.Println(strings.Repeat("=", 120))

		for _, d := range devices {
			name := d.SysName
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = "-"
			}

			mac := d.MAC
			if mac == "" {
				mac = "-"
			}

			uptime := d.Uptime
			if uptime == "" {
				uptime = "-"
			}

			desc := d.SysDescr
			if desc == "" {
				if d.SysLocation != "" {
					desc = "Location: " + d.SysLocation
				} else {
					desc = "-"
				}
			}

			status := ""
			if d.SNMPEnabled {
				status = "[SNMP]"
				snmpCount++
			}
			reachableCount++

			fmt.Printf("%-15s %-17s %-20s %-12s %-50s %s\n",
				d.IP, mac, truncateString(name, 20), uptime, truncateString(desc, 50), status)
		}
		fmt.Println(strings.Repeat("=", 120))
	}

	fmt.Printf("\nTotal: %d devices found (%d with SNMP)\n", reachableCount, snmpCount)
}
