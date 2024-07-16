package metric

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var skipEndpoints = map[string]struct{}{
	"/healthcheck": {},
	"/metrics":     {},
}

type HealthCheck struct {
	TotalRequests    int64
	RequestBrakeDown []rb
	Interval         time.Duration
	mutex            *sync.RWMutex
	MaxFailureRatio  float64
	LastUpdated      time.Time
}

func (hc *HealthCheck) AddRequest(ctx context.Context, entry *AuditLog) {
	if _, ok := skipEndpoints[entry.Path]; ok {
		return
	}
	if len(hc.RequestBrakeDown) == 0 {
		hc.RequestBrakeDown = []rb{}
		hc.RequestBrakeDown = append(hc.RequestBrakeDown, rb{})
		hc.LastUpdated = time.Now()
	}

	hc.mutex.Lock()
	hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Total += 1
	if entry.StatusCode >= 200 && entry.StatusCode < 400 {
		hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Success += 1
	} else {
		hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Failed += 1
	}
	hc.mutex.Unlock()
}

func (hc *HealthCheck) Monitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(hc.Interval)
		for {
			select {
			case <-ticker.C:
				hc.RequestBrakeDown = append(hc.RequestBrakeDown, rb{})
				hc.LastUpdated = time.Now()
			case <-ctx.Done():
				return
			}
			if len(hc.RequestBrakeDown) > 5 {
				hc.RequestBrakeDown = hc.RequestBrakeDown[len(hc.RequestBrakeDown)-5:]
			}
		}
	}()
}

func (hc *HealthCheck) Healthy() bool {
	defer hc.mutex.RUnlock()
	hc.mutex.RLock()
	if len(hc.RequestBrakeDown) == 0 || hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Total <= 0 {
		return true
	}

	p := float64(hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Failed) / float64(hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Total)

	return p > hc.MaxFailureRatio
}

func (hc *HealthCheck) Status(w http.ResponseWriter, r *http.Request) {
	isHealthy := hc.Healthy()
	if isHealthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	if len(hc.RequestBrakeDown) > 0 && hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1].Total > 0 {
		lastStats := hc.RequestBrakeDown[len(hc.RequestBrakeDown)-1]
		p := float64(lastStats.Failed) / float64(lastStats.Total)
		w.Header().Set("X-Total-Count", strconv.FormatFloat(p, 'f', 2, 64))
	}
}
