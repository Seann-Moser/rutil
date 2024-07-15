package cookie

import (
	"fmt"
	"github.com/Seann-Moser/cutil/logc"
	"go.uber.org/zap"
	"net/http"
	"time"
)

func getCookieValue(key string, r *http.Request) (string, error) {
	cookie, err := r.Cookie(key)
	if err != nil {
		return "", fmt.Errorf("get cookie value(%s): %w", key, err)
	}
	if cookie.MaxAge < 0 {
		logc.Debug(r.Context(), "invalid max age", zap.String("name", cookie.Name), zap.Time("expires", cookie.Expires), zap.Time("now", time.Now()))
		return "", fmt.Errorf("invalid max age: %s", cookie.Name)
	}

	return cookie.Value, nil
}

func getCookie(auth *Data, key, value, path, domain string) *http.Cookie {
	if len(path) == 0 {
		return &http.Cookie{
			Name:     key,
			Value:    value,
			Expires:  auth.Expires,
			Domain:   domain,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
			MaxAge:   int(time.Until(auth.Expires).Seconds()),
		}
	}
	return &http.Cookie{
		Name:     key,
		Value:    value,
		Expires:  auth.Expires,
		Domain:   domain,
		Path:     path,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Until(auth.Expires).Seconds()),
	}
}
