package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"
)

// PortInfo represents an open port with service banner
type PortInfo struct {
	Port    int
	Service string
	Banner  string
}

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
	OpenPorts   []PortInfo
}

// Well-known port names
var portNames = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	111:  "rpc",
	135:  "msrpc",
	139:  "netbios",
	143:  "imap",
	443:  "https",
	445:  "smb",
	993:  "imaps",
	995:  "pop3s",
	1433: "mssql",
	1521: "oracle",
	3306: "mysql",
	3389: "rdp",
	5432: "postgres",
	5900: "vnc",
	6379: "redis",
	8080: "http-alt",
	8443: "https-alt",
	27017: "mongodb",
}

// Config represents the configuration file structure
type Config struct {
	Subnet    string `yaml:"subnet"`
	Community string `yaml:"community"`
	Timeout   int    `yaml:"timeout"`
	Workers   int    `yaml:"workers"`
	Ports     string `yaml:"ports"`
	Verbose   bool   `yaml:"verbose"`
	NoColor   bool   `yaml:"no_color"`
}

var (
	subnet      string
	community   string
	timeout     int
	workers     int
	verbose     bool
	scanPorts   bool
	portSpec    string
	noColor     bool
	jsonOutput  bool
	csvOutput   string
	configFile  string
	showVersion bool
	portsToScan []int
	arpCache    map[string]string
	arpMutex    sync.RWMutex
)

const version = "1.1.0"

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBgBlue  = "\033[44m"
)

func init() {
	flag.StringVar(&subnet, "subnet", "", "Subnet to scan (e.g., 192.168.1.0/24)")
	flag.StringVar(&community, "community", "public", "SNMP community string")
	flag.IntVar(&timeout, "timeout", 1, "Timeout in seconds for each host")
	flag.IntVar(&workers, "workers", 50, "Number of concurrent workers")
	flag.BoolVar(&verbose, "v", false, "Verbose output with detailed SNMP info")
	flag.BoolVar(&scanPorts, "ports", false, "Enable port scanning (well-known ports 1-1023)")
	flag.StringVar(&portSpec, "p", "", "Port spec: 80 | 22,80,443 | 1-1024 | 22,80,8000-9000")
	flag.BoolVar(&noColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	flag.StringVar(&csvOutput, "csv", "", "Export results to CSV file")
	flag.StringVar(&configFile, "config", "", "Config file path (default: ~/.netprobe.yaml)")
	flag.BoolVar(&showVersion, "version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
%snetprobe%s v%s - Network discovery and SNMP scanner

%sUSAGE%s
    netprobe [options]

%sOPTIONS%s
    -subnet <cidr>     Subnet to scan (auto-detects if not specified)
    -community <str>   SNMP community string (default: "public")
    -timeout <sec>     Connection timeout in seconds (default: 1)
    -workers <num>     Concurrent workers (default: 50)

    -ports             Enable port scan (well-known ports 1-1023)
    -p <spec>          Custom ports: 80 | 22,80,443 | 1-1024 | 22,80,8000-9000

    -v                 Verbose output with detailed device info
    -json              Output as JSON (for scripting)
    -csv <file>        Export results to CSV file
    -no-color          Disable colored output
    -config <file>     Config file (default: ~/.netprobe.yaml)
    -version           Show version

%sEXAMPLES%s
    netprobe                          Auto-detect subnet, discover devices
    netprobe -p 22,80,443             Scan common ports with banners
    netprobe -v -p 22,80,443          Verbose output with port details
    netprobe -subnet 192.168.1.0/24   Scan specific subnet
    netprobe -json -p 22,80           JSON output for scripting
    netprobe -csv scan.csv -p 22,80   Export to CSV file
    netprobe -community private       Use different SNMP community

%sCONFIG FILE%s (~/.netprobe.yaml)
    subnet: "192.168.1.0/24"
    community: "public"
    timeout: 1
    workers: 50
    ports: "22,80,443"
    verbose: false

`, colorBold, colorReset, version, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset, colorCyan, colorReset)
	}

	// Initialize ARP cache
	arpCache = make(map[string]string)
}

// Color helper functions
func c(color, text string) string {
	if noColor {
		return text
	}
	return color + text + colorReset
}

func bold(text string) string {
	return c(colorBold, text)
}

func dim(text string) string {
	return c(colorDim, text)
}

func green(text string) string {
	return c(colorGreen, text)
}

func red(text string) string {
	return c(colorRed, text)
}

func cyan(text string) string {
	return c(colorCyan, text)
}

func yellow(text string) string {
	return c(colorYellow, text)
}

func blue(text string) string {
	return c(colorBlue, text)
}

func magenta(text string) string {
	return c(colorMagenta, text)
}

func main() {
	flag.Parse()

	// Handle version flag
	if showVersion {
		fmt.Printf("netprobe version %s\n", version)
		os.Exit(0)
	}

	// Load config file (before processing other flags so CLI can override)
	loadConfig()

	// JSON/CSV output disables colors
	if jsonOutput || csvOutput != "" {
		noColor = true
	}

	// Populate ARP cache for MAC detection
	populateARPCache()

	// If -p is specified, enable port scanning
	if portSpec != "" {
		scanPorts = true
	}

	// Parse port specification
	if scanPorts {
		var err error
		if portSpec != "" {
			portsToScan, err = parsePorts(portSpec)
			if err != nil {
				fmt.Printf("Error parsing ports: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Default to well-known ports (1-1023)
			portsToScan = make([]int, 1023)
			for i := 1; i <= 1023; i++ {
				portsToScan[i-1] = i
			}
		}
	}

	if subnet == "" {
		subnet = detectLocalSubnet()
		if subnet == "" {
			fmt.Fprintln(os.Stderr, "Error: Could not detect local subnet. Please specify with -subnet")
			os.Exit(1)
		}
		if !jsonOutput {
			fmt.Printf("Auto-detected subnet: %s\n", subnet)
		}
	}

	if !jsonOutput {
		fmt.Printf("Scanning %s with community '%s'", subnet, community)
		if scanPorts {
			fmt.Printf(" (port scan: %d ports)", len(portsToScan))
		}
		fmt.Println("...\n")
	}

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

	// Export to CSV if requested
	if csvOutput != "" {
		if err := writeCSV(devices, csvOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
			os.Exit(1)
		}
		if !jsonOutput {
			fmt.Printf("Results exported to %s\n", csvOutput)
		}
	}
}

// parsePorts parses a port specification string into a list of ports
// Supports: single (80), list (22,80,443), range (1-1024), or mixed (22,80,8000-9000)
func parsePorts(spec string) ([]int, error) {
	var ports []int
	portSet := make(map[int]bool)

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}
			if start > end {
				start, end = end, start
			}
			for p := start; p <= end; p++ {
				if p > 0 && p <= 65535 && !portSet[p] {
					portSet[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			// Single port
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p > 0 && p <= 65535 && !portSet[p] {
				portSet[p] = true
				ports = append(ports, p)
			}
		}
	}

	sort.Ints(ports)
	return ports, nil
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
		device = snmpDevice
	} else if isReachable(ip) {
		device.Reachable = true
		device.Hostname = lookupHostname(ip)
		device.MAC = lookupMAC(ip)
	}

	// Port scan if enabled and device is reachable
	if scanPorts && (device.Reachable || device.SNMPEnabled) {
		device.OpenPorts = scanPortsForHost(ip)
	}

	return device
}

func scanPortsForHost(ip string) []PortInfo {
	var openPorts []PortInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent port scans per host
	sem := make(chan struct{}, 100)

	for _, port := range portsToScan {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
			if err == nil {
				portInfo := PortInfo{Port: p, Service: getServiceName(p)}
				portInfo.Banner = grabBanner(conn, ip, p)
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})
	return openPorts
}

func getServiceName(port int) string {
	if name, ok := portNames[port]; ok {
		return name
	}
	return ""
}

func grabBanner(conn net.Conn, ip string, port int) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	switch port {
	case 80, 8080, 8000, 8888:
		return grabHTTPBanner(ip, port, false)
	case 443, 8443:
		return grabHTTPBanner(ip, port, true)
	case 22:
		return grabSSHBanner(conn)
	case 21:
		return grabFTPBanner(conn)
	case 25, 587:
		return grabSMTPBanner(conn)
	default:
		return grabGenericBanner(conn)
	}
}

func grabHTTPBanner(ip string, port int, useTLS bool) string {
	var conn net.Conn
	var err error
	address := fmt.Sprintf("%s:%d", ip, port)

	if useTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: 2 * time.Second},
			"tcp", address,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		conn, err = net.DialTimeout("tcp", address, 2*time.Second)
	}
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)

	reader := bufio.NewReader(conn)
	var server string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
			break
		}
	}
	return cleanBanner(server)
}

func grabSSHBanner(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return cleanBanner(strings.TrimSpace(line))
}

func grabFTPBanner(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	// Remove FTP response code (e.g., "220 ")
	banner := strings.TrimSpace(line)
	if len(banner) > 4 && banner[3] == ' ' {
		banner = banner[4:]
	}
	return cleanBanner(banner)
}

func grabSMTPBanner(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	// Remove SMTP response code (e.g., "220 ")
	banner := strings.TrimSpace(line)
	if len(banner) > 4 && banner[3] == ' ' {
		banner = banner[4:]
	}
	return cleanBanner(banner)
}

func grabGenericBanner(conn net.Conn) string {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return cleanBanner(string(buf[:n]))
}

func cleanBanner(s string) string {
	// Remove control characters and clean up
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	// Remove non-printable characters
	re := regexp.MustCompile(`[^\x20-\x7E]`)
	s = re.ReplaceAllString(s, "")
	// Truncate if too long
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

func formatPort(p PortInfo) string {
	var parts []string
	if p.Service != "" {
		parts = append(parts, fmt.Sprintf("%d/%s", p.Port, p.Service))
	} else {
		parts = append(parts, strconv.Itoa(p.Port))
	}
	if p.Banner != "" {
		parts = append(parts, fmt.Sprintf("(%s)", p.Banner))
	}
	return strings.Join(parts, " ")
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
	arpMutex.RLock()
	defer arpMutex.RUnlock()
	if mac, ok := arpCache[ip]; ok {
		return mac
	}
	return ""
}

// populateARPCache reads the system ARP table
func populateARPCache() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin", "freebsd":
		cmd = exec.Command("arp", "-an")
	case "linux":
		cmd = exec.Command("arp", "-n")
	case "windows":
		cmd = exec.Command("arp", "-a")
	default:
		return
	}

	output, err := cmd.Output()
	if err != nil {
		return
	}

	arpMutex.Lock()
	defer arpMutex.Unlock()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var ip, mac string

		switch runtime.GOOS {
		case "darwin", "freebsd":
			// Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
			re := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 3 {
				ip = matches[1]
				mac = strings.ToUpper(matches[2])
			}
		case "linux":
			// Format: 192.168.1.1  ether   aa:bb:cc:dd:ee:ff   C   eth0
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == "ether" {
				ip = fields[0]
				mac = strings.ToUpper(fields[2])
			}
		case "windows":
			// Format: 192.168.1.1      aa-bb-cc-dd-ee-ff     dynamic
			re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 3 {
				ip = matches[1]
				mac = strings.ToUpper(strings.ReplaceAll(matches[2], "-", ":"))
			}
		}

		if ip != "" && mac != "" && mac != "FF:FF:FF:FF:FF:FF" && mac != "(INCOMPLETE)" {
			arpCache[ip] = mac
		}
	}
}

// loadConfig loads configuration from file
func loadConfig() {
	// Determine config file path
	cfgPath := configFile
	if cfgPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		cfgPath = filepath.Join(home, ".netprobe.yaml")
	}

	// Read config file
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return // Config file doesn't exist or can't be read - that's OK
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not parse config file: %v\n", err)
		return
	}

	// Apply config values only if CLI flags weren't set
	if subnet == "" && cfg.Subnet != "" {
		subnet = cfg.Subnet
	}
	if community == "public" && cfg.Community != "" {
		community = cfg.Community
	}
	if timeout == 1 && cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}
	if workers == 50 && cfg.Workers > 0 {
		workers = cfg.Workers
	}
	if portSpec == "" && cfg.Ports != "" {
		portSpec = cfg.Ports
	}
	if !verbose && cfg.Verbose {
		verbose = cfg.Verbose
	}
	if !noColor && cfg.NoColor {
		noColor = cfg.NoColor
	}
}

// writeCSV exports results to a CSV file
func writeCSV(devices []Device, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"IP", "MAC", "Hostname", "SNMP", "Uptime", "System", "Location", "Ports", "Banners"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, d := range devices {
		hostname := d.SysName
		if hostname == "" {
			hostname = d.Hostname
		}

		snmp := "No"
		if d.SNMPEnabled {
			snmp = "Yes"
		}

		var ports, banners []string
		for _, p := range d.OpenPorts {
			portStr := fmt.Sprintf("%d", p.Port)
			if p.Service != "" {
				portStr += "/" + p.Service
			}
			ports = append(ports, portStr)
			if p.Banner != "" {
				banners = append(banners, fmt.Sprintf("%d:%s", p.Port, p.Banner))
			}
		}

		row := []string{
			d.IP,
			d.MAC,
			hostname,
			snmp,
			d.Uptime,
			d.SysDescr,
			d.SysLocation,
			strings.Join(ports, ";"),
			strings.Join(banners, ";"),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
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

// JSONOutput represents the JSON output structure
type JSONOutput struct {
	Subnet  string       `json:"subnet"`
	Devices []JSONDevice `json:"devices"`
	Summary struct {
		Total     int `json:"total"`
		WithSNMP  int `json:"with_snmp"`
		OpenPorts int `json:"open_ports"`
	} `json:"summary"`
}

// JSONDevice represents a device in JSON output
type JSONDevice struct {
	IP       string     `json:"ip"`
	MAC      string     `json:"mac,omitempty"`
	Hostname string     `json:"hostname,omitempty"`
	SNMP     *JSONSNMP  `json:"snmp,omitempty"`
	Ports    []JSONPort `json:"ports,omitempty"`
}

// JSONSNMP represents SNMP data in JSON output
type JSONSNMP struct {
	Enabled     bool   `json:"enabled"`
	SysName     string `json:"sys_name,omitempty"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
}

// JSONPort represents a port in JSON output
type JSONPort struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

func printResults(devices []Device) {
	// Count totals
	snmpCount := 0
	portCount := 0
	for _, d := range devices {
		if d.SNMPEnabled {
			snmpCount++
		}
		portCount += len(d.OpenPorts)
	}

	if jsonOutput {
		printJSONResults(devices, snmpCount, portCount)
		return
	}

	if len(devices) == 0 {
		fmt.Println(yellow("No devices found."))
		return
	}

	if verbose {
		printVerboseResults(devices, snmpCount, portCount)
	} else {
		printCompactResults(devices, snmpCount, portCount)
	}
}

func printJSONResults(devices []Device, snmpCount, portCount int) {
	output := JSONOutput{
		Subnet: subnet,
	}
	output.Summary.Total = len(devices)
	output.Summary.WithSNMP = snmpCount
	output.Summary.OpenPorts = portCount

	for _, d := range devices {
		jd := JSONDevice{
			IP:  d.IP,
			MAC: d.MAC,
		}

		// Hostname
		if d.SysName != "" {
			jd.Hostname = d.SysName
		} else if d.Hostname != "" {
			jd.Hostname = d.Hostname
		}

		// SNMP data
		if d.SNMPEnabled {
			jd.SNMP = &JSONSNMP{
				Enabled:     true,
				SysName:     d.SysName,
				SysDescr:    d.SysDescr,
				SysLocation: d.SysLocation,
				SysContact:  d.SysContact,
				Uptime:      d.Uptime,
			}
		}

		// Ports
		for _, p := range d.OpenPorts {
			jd.Ports = append(jd.Ports, JSONPort{
				Port:    p.Port,
				Service: p.Service,
				Banner:  p.Banner,
			})
		}

		output.Devices = append(output.Devices, jd)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

// printCompactResults - Option C: Minimal clean table
func printCompactResults(devices []Device, snmpCount, portCount int) {
	// Header
	fmt.Println()
	fmt.Printf("%s %s %s\n",
		bold("NETPROBE"),
		dim("─────────────────────────────────────────────────────────────────────"),
		cyan(subnet))
	fmt.Println()

	// Column headers
	fmt.Printf("%s%-15s %-28s %-15s %s%s\n",
		colorBold,
		"IP", "HOSTNAME", "STATUS", "SERVICES",
		colorReset)
	fmt.Println(dim("─────────────── ──────────────────────────── ─────────────── ────────────────────────────────────────"))

	// Device rows
	for _, d := range devices {
		name := d.SysName
		if name == "" {
			name = d.Hostname
		}
		if name == "" {
			name = dim("·")
		}

		// Status column
		status := dim("·")
		if d.SNMPEnabled {
			uptime := ""
			if d.Uptime != "" {
				uptime = " " + d.Uptime
			}
			status = green("● SNMP") + dim(uptime)
		}

		// Services column
		services := formatServicesCompact(d.OpenPorts)

		fmt.Printf("%-15s %-28s %-15s %s\n",
			cyan(d.IP),
			truncateString(name, 28),
			status,
			services)
	}

	// Footer
	fmt.Println(dim("───────────────────────────────────────────────────────────────────────────────────────────────────────"))
	fmt.Printf("%s%d devices%s │ %s%d SNMP%s │ %s%d ports%s\n",
		colorBold, len(devices), colorReset,
		colorGreen, snmpCount, colorReset,
		colorCyan, portCount, colorReset)
	fmt.Println()
}

// printVerboseResults - Option B: Tree/card style
func printVerboseResults(devices []Device, snmpCount, portCount int) {
	// Header box
	fmt.Println()
	fmt.Println(dim("═══════════════════════════════════════════════════════════════════════════════════════════════════════"))
	fmt.Printf("  %s%s%s", colorBold, "NETPROBE", colorReset)
	fmt.Printf("%s│ %s │ %d devices%s\n",
		strings.Repeat(" ", 55),
		cyan(subnet),
		len(devices),
		colorReset)
	fmt.Println(dim("═══════════════════════════════════════════════════════════════════════════════════════════════════════"))
	fmt.Println()

	// Device cards
	for _, d := range devices {
		name := d.SysName
		if name == "" {
			name = d.Hostname
		}
		if name == "" {
			name = dim("(unknown)")
		}

		// Device header line
		snmpBadge := ""
		uptimeBadge := ""
		if d.SNMPEnabled {
			snmpBadge = "  " + green("[SNMP]")
			if d.Uptime != "" {
				uptimeBadge = "  " + dim("⏱ "+d.Uptime)
			}
		}

		fmt.Printf("  %s %s %s %s%s%s\n",
			bold("■"),
			cyan(d.IP),
			dim("─"),
			bold(name),
			snmpBadge,
			uptimeBadge)

		// System description (if SNMP)
		if d.SNMPEnabled && d.SysDescr != "" {
			// Parse out kernel info for cleaner display
			sysInfo := truncateString(d.SysDescr, 80)
			fmt.Printf("    %s   %s\n", dim("│"), dim(sysInfo))
		}

		// Location (if available)
		if d.SysLocation != "" && d.SysLocation != "Unknown" {
			fmt.Printf("    %s   %s %s\n", dim("│"), dim("📍"), dim(d.SysLocation))
		}

		// Ports
		if len(d.OpenPorts) > 0 {
			for i, p := range d.OpenPorts {
				prefix := "├──"
				if i == len(d.OpenPorts)-1 {
					prefix = "└──"
				}

				portNum := fmt.Sprintf("%d", p.Port)
				service := p.Service
				if service == "" {
					service = "unknown"
				}

				banner := ""
				if p.Banner != "" {
					banner = " " + dim("─── "+p.Banner)
				}

				fmt.Printf("    %s %s/%s%s\n",
					dim(prefix),
					yellow(portNum),
					cyan(service),
					banner)
			}
		} else if scanPorts {
			fmt.Printf("    %s %s\n", dim("└──"), dim("no open ports detected"))
		}

		fmt.Println()
	}

	// Footer
	fmt.Println(dim("═══════════════════════════════════════════════════════════════════════════════════════════════════════"))
	fmt.Printf("  %sSummary:%s %d devices │ %s%d with SNMP%s │ %s%d open ports%s\n",
		colorBold, colorReset,
		len(devices),
		colorGreen, snmpCount, colorReset,
		colorCyan, portCount, colorReset)
	fmt.Println(dim("═══════════════════════════════════════════════════════════════════════════════════════════════════════"))
	fmt.Println()
}

// formatServicesCompact formats ports for compact display
func formatServicesCompact(ports []PortInfo) string {
	if len(ports) == 0 {
		return dim("·")
	}

	var parts []string
	for _, p := range ports {
		part := yellow(fmt.Sprintf("%d", p.Port))
		if p.Banner != "" {
			// Extract short banner (e.g., "nginx" from full server string)
			shortBanner := extractShortBanner(p.Banner)
			if shortBanner != "" {
				part += " " + dim(shortBanner)
			}
		} else if p.Service != "" {
			part += " " + dim(p.Service)
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, dim(" │ "))
}

// extractShortBanner extracts a short service identifier from banner
func extractShortBanner(banner string) string {
	banner = strings.ToLower(banner)

	// Common patterns
	patterns := map[string]string{
		"nginx":    "nginx",
		"apache":   "Apache",
		"openssh":  "",  // Will extract version
		"lighttpd": "lighttpd",
		"iis":      "IIS",
		"tomcat":   "Tomcat",
		"caddy":    "Caddy",
		"haproxy":  "HAProxy",
	}

	for pattern, name := range patterns {
		if strings.Contains(banner, pattern) {
			if pattern == "openssh" {
				// Extract OpenSSH version like "OpenSSH_9.9p1"
				parts := strings.Fields(banner)
				for _, part := range parts {
					if strings.HasPrefix(strings.ToLower(part), "ssh-2.0-openssh") {
						version := strings.TrimPrefix(part, "SSH-2.0-")
						return version
					}
				}
				return "OpenSSH"
			}
			if name != "" {
				return name
			}
		}
	}

	// If no pattern matched, return truncated banner
	if len(banner) > 20 {
		return banner[:17] + "..."
	}
	return banner
}
