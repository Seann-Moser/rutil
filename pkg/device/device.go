package device

import (
	"crypto/sha1"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Device struct {
	ID          string `db:"id" json:"id" qc:"primary;join,where::="`
	IPv4        string `db:"ip_v4" json:"ip_v4" qc:"primary"`
	IPv6        string `db:"ip_v6" json:"ip_v6" qc:"primary"`
	UserAgent   string `db:"user_agent" json:"user_agent" qc:"data_type::text;primary"`
	Active      bool   `db:"active" json:"active" qc:"default::true;update;where::="`
	UpdatedDate string `db:"updated_date" json:"updated_date" qc:"skip;data_type::TIMESTAMP;default::NOW() ON UPDATE CURRENT_TIMESTAMP"`
	CreatedDate string `db:"created_date" json:"created_date" qc:"skip;data_type::TIMESTAMP;default::NOW()"`
}

func GetDeviceFromRequest(r *http.Request) *Device {
	device := &Device{}
	device.loadIP(r)
	device.UserAgent = r.UserAgent()
	return device
}

func (d *Device) loadIP(r *http.Request) {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}

	for _, ip := range strings.Split(IPAddress, ",") {
		ip = strings.TrimSpace(ip)
		if idx := strings.LastIndex(ip, ":"); idx != -1 && strings.Count(ip, ":") == 1 {
			ip = ip[:idx]
		}

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		if parsedIP.To4() != nil {
			if d.IPv4 != "" {
				d.IPv4 += "," + ip
			} else {
				d.IPv4 = ip
			}
		} else if parsedIP.To16() != nil {
			if d.IPv6 != "" {
				d.IPv6 += "," + ip
			} else {
				d.IPv6 = ip
			}
		}
	}
}

func (d *Device) GenerateDeviceKey(salt string) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s-%s-%s-%s-%v", d.ID, d.UserAgent, d.IPv4, d.IPv6, salt)))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
