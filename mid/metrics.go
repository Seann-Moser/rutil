package mid

import (
	"github.com/Seann-Moser/rutil/pkg/device"
	"go.uber.org/zap"
	"net/http"
)

type Metrics struct {
	logger        *zap.Logger
	LogDeviceInfo bool
}

func NewMetrics(logDevice bool, logger *zap.Logger) *Metrics {
	return &Metrics{
		logger:        logger,
		LogDeviceInfo: logDevice,
	}
}
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.LogDeviceInfo {
			deviceDetails := device.GetDeviceFromRequest(r)
			m.logger.Debug("device hit endpoint",
				zap.String("endpoint", r.URL.String()),
				zap.String("ipv4", deviceDetails.IPv4),
				zap.String("ipv6", deviceDetails.IPv6),
				zap.String("user-agent", deviceDetails.UserAgent),
				zap.String("device-hash", deviceDetails.GenerateDeviceKey("")),
			)
		} else {
			m.logger.Debug("hit endpoint",
				zap.String("endpoint", r.URL.String()))
		}

		next.ServeHTTP(w, r)
	})
}
