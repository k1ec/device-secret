package fingerprint

import (
	"os"
	"regexp"
	"runtime"
	"strings"
)

var (
	readFile = os.ReadFile
	readDir  = func(path string) ([]string, error) {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		return names, nil
	}
	hostname = os.Hostname
	basePath = ""
)

func path(p string) string {
	if basePath != "" {
		return basePath + "/" + p
	}
	return p
}

var virtualNICPattern = regexp.MustCompile(`^(lo|docker\d*|veth\w+|br-.*|tun\d*|tap\d*|virbr\d*|cali\w+|flannel\w+)$`)

func collectMachineID() string {
	data, err := readFile(path("/etc/machine-id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func collectCPUSerial() string {
	data, err := readFile(path("/proc/cpuinfo"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Serial") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" {
					return val
				}
			}
		}
	}
	return ""
}

func collectProductSerial() string {
	data, err := readFile(path("/sys/class/dmi/id/product_serial"))
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(data))
	if val == "" || val == "To be filled by O.E.M." || val == "Not Specified" {
		return ""
	}
	return val
}

func collectProductUUID() string {
	data, err := readFile(path("/sys/class/dmi/id/product_uuid"))
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(data))
	if val == "" {
		return ""
	}
	return val
}

func collectMACs() string {
	entries, err := readDir(path("/sys/class/net"))
	if err != nil {
		return ""
	}
	var macs []string
	for _, iface := range entries {
		if virtualNICPattern.MatchString(iface) {
			continue
		}
		data, err := readFile(path("/sys/class/net/" + iface + "/address"))
		if err != nil {
			continue
		}
		mac := strings.TrimSpace(string(data))
		if mac != "" {
			macs = append(macs, strings.ToLower(mac))
		}
	}
	if len(macs) == 0 {
		return ""
	}
	return strings.Join(macs, ",")
}

func collectEMMCCID() string {
	entries, err := readDir(path("/sys/block"))
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry, "mmcblk") {
			continue
		}
		data, err := readFile(path("/sys/block/" + entry + "/device/cid"))
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(data))
		if val != "" {
			return val
		}
	}
	return ""
}

// GetDeviceMeta returns device metadata not used for fingerprint binding.
func GetDeviceMeta() DeviceMeta {
	h, _ := hostname()
	return DeviceMeta{
		Hostname: h,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
}
