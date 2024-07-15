package cookie

import (
	"fmt"
	"github.com/Seann-Moser/cutil/logc"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"time"
)

const (
	TokenID   = "token_id"
	AccountID = "account_id"
	Roles     = "roles"
	Timestamp = "timestamp"
	Expires   = "expires"
	Signature = "signature"
	DeviceID  = "device_id"
	UID       = "uid"
)

type Data struct {
	TokenID   string            `json:"token_id"`
	AccountID string            `json:"account_id"`
	UID       string            `json:"uid"`
	DeviceID  string            `json:"device_id"`
	Roles     []string          `json:"roles"`
	Expires   time.Time         `json:"expires"`
	Signature string            `json:"signature"`
	Timestamp time.Time         `json:"timestamp"`
	Meta      map[string]string `json:"meta"`
}

func GetCookieData(r *http.Request) (*Data, error) {
	var err error
	auth := &Data{}
	auth.TokenID, err = getCookieValue(TokenID, r)
	if err != nil {
		return nil, err
	}
	auth.AccountID, err = getCookieValue(AccountID, r)
	if err != nil {
		return nil, err
	}
	auth.Signature, err = getCookieValue(Signature, r)
	if err != nil {
		return nil, err
	}
	if auth.Signature == "" {
		return auth, fmt.Errorf("no cookie data found")
	}
	auth.UID, err = getCookieValue(UID, r)
	if err != nil {
		return nil, err
	}
	if rawExpires, _ := getCookieValue(Expires, r); rawExpires != "" {
		expires, err := strconv.Atoi(rawExpires)
		if err != nil {
			logc.Warn(r.Context(), "failed getting expired", zap.String("raw", rawExpires))
			return nil, err
		}
		auth.Expires = time.Unix(int64(expires), 0).UTC()
	} else {
		logc.Debug(r.Context(), "expired", zap.String("structs", rawExpires))
	}

	if auth.Expires.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("cookie expired: expired: %s now: %s", auth.Expires.String(), time.Now().UTC())
	}
	if timestamp, err := getCookieValue(Timestamp, r); err != nil {
		return nil, err
	} else {
		tp, err := strconv.Atoi(timestamp)
		if err != nil {
			logc.Debug(r.Context(), "failed getting timestamp", zap.String("raw", timestamp))
		}
		auth.Timestamp = time.Unix(int64(tp), 0)
	}
	auth.DeviceID, _ = getCookieValue(DeviceID, r)
	return auth, nil
}

func (d *Data) UniqueID() string {
	return fmt.Sprintf("%s-%s-%s-%s-%d", d.UID, d.TokenID, d.AccountID, d.Roles, d.Expires.Unix())
}
