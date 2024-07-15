package cookie

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/Seann-Moser/cutil/logc"
	"github.com/Seann-Moser/rutil/pkg/device"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	DefaultExpiresDuration time.Duration
	Salt                   string
	VerifySignature        bool
	RotatingSalt           bool
	Domain                 string
	IgnoreSubdomain        bool
}

const (
	cookiesDefaultExpiresFlag  = "cookie-default-expires"
	cookiesSaltFlag            = "cookie-salt"
	cookieDomain               = "cookie-domain"
	cookieIgnoreSubDomain      = "cookie-ignore-subdomain"
	cookiesVerifySignatureFlag = "cookie-verify-signature-flag"
)

func Flags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("cookie", pflag.ExitOnError)
	fs.Duration(cookiesDefaultExpiresFlag, 2*7*24*time.Hour, "")
	fs.String(cookiesSaltFlag, "12345678", "")
	fs.String(cookieDomain, "", "")
	fs.Bool(cookiesVerifySignatureFlag, false, "verify cookie signature")
	fs.Bool(cookieIgnoreSubDomain, false, "ignore subdomain ie. test.example.com => .example.com")
	return fs
}

func NewFromFlags() *Client {
	return &Client{
		DefaultExpiresDuration: viper.GetDuration(cookiesDefaultExpiresFlag),
		Salt:                   viper.GetString(cookiesSaltFlag),
		VerifySignature:        viper.GetBool(cookiesVerifySignatureFlag),
		Domain:                 viper.GetString(cookieDomain),
		IgnoreSubdomain:        viper.GetBool(cookieIgnoreSubDomain),
	}
}

func (c *Client) GenerateSignature(cd *Data) string {
	signatureRaw := cd.UniqueID() + c.Salt
	harsher := sha256.New()
	harsher.Write([]byte(signatureRaw))
	return base64.URLEncoding.EncodeToString(harsher.Sum(nil))
}

func (c *Client) HasValidCookie(r *http.Request) (*Data, bool) {
	requestCookieData, err := GetCookieData(r)
	if err != nil {
		logc.Debug(r.Context(), "invalid cookie", zap.Error(err))
		return nil, false
	}
	cd := c.copyCookieData(r, requestCookieData)
	validSignature := requestCookieData.Signature == c.GenerateSignature(cd)
	if !validSignature {
		logc.Warn(r.Context(), "invalid signature", zap.Any("copy", cd), zap.Any("request", requestCookieData), zap.String("expected", c.GenerateSignature(c.copyCookieData(r, requestCookieData))), zap.String("recieved", requestCookieData.Signature))
	}

	return requestCookieData, validSignature
}
func (c *Client) copyCookieData(r *http.Request, cd *Data) *Data {
	return &Data{
		TokenID:   cd.TokenID,
		AccountID: cd.AccountID,
		UID:       cd.UID,
		DeviceID:  device.GetDeviceFromRequest(r).IPv4,
		Roles:     cd.Roles,
		Expires:   cd.Expires,
		Signature: "",
		Timestamp: cd.Timestamp,
		Meta:      cd.Meta,
	}
}

func (c *Client) GetCookies(r *http.Request, cd *Data) []*http.Cookie {
	key := uuid.New().String()
	if r != nil {
		key = device.GetDeviceFromRequest(r).GenerateDeviceKey(c.Salt)
	}
	var cookies []*http.Cookie
	if cd == nil {
		cd = &Data{}
	}
	cd.DeviceID = key
	cd.Timestamp = time.Now().UTC()
	cd.Expires = time.Now().UTC().Add(c.DefaultExpiresDuration)
	domain := c.Domain
	if domain == "" && c.IgnoreSubdomain && r != nil {
		domain = c.GetDomain(r)
	}

	cookies = append(cookies, getCookie(cd, DeviceID, cd.DeviceID, "", domain))
	cookies = append(cookies, getCookie(cd, AccountID, cd.AccountID, "", domain))
	cookies = append(cookies, getCookie(cd, TokenID, cd.TokenID, "", domain))
	cookies = append(cookies, getCookie(cd, UID, cd.UID, "", domain))
	cookies = append(cookies, getCookie(cd, Timestamp, strconv.Itoa(int(cd.Timestamp.UTC().Unix())), "", domain))
	cookies = append(cookies, getCookie(cd, Expires, strconv.Itoa(int(cd.Expires.UTC().Unix())), "", domain))
	cookies = append(cookies, getCookie(cd, Roles, strings.Join(cd.Roles, ","), "", domain))

	cookies = append(cookies, getCookie(cd, Signature, c.GenerateSignature(cd), "", domain))
	return cookies
}

func (c *Client) SetCookie(r *http.Request, w http.ResponseWriter, cd *Data, clear bool) error {
	if cd == nil {
		cd = &Data{}
		clear = true
	}
	cookies := c.GetCookies(r, cd)
	for _, cookie := range cookies {
		if clear {
			cookie.MaxAge = -1
			cookie.Expires = time.Now()
		}
		r.AddCookie(cookie)
		http.SetCookie(w, cookie)
	}

	return nil
}

func (c *Client) SetRequestCookie(r *http.Request, d *Data) {
	d.DeviceID = device.GetDeviceFromRequest(r).IPv4
	d.Timestamp = time.Now().UTC()
	d.Expires = time.Now().UTC().Add(c.DefaultExpiresDuration)
	var cookies []*http.Cookie
	domain := c.Domain
	if domain == "" && c.IgnoreSubdomain {
		domain = c.GetDomain(r)
	}
	cookies = append(cookies, getCookie(d, DeviceID, d.DeviceID, "", domain))
	cookies = append(cookies, getCookie(d, AccountID, d.AccountID, "", domain))
	cookies = append(cookies, getCookie(d, TokenID, d.TokenID, "", domain))
	cookies = append(cookies, getCookie(d, UID, d.UID, "", domain))
	cookies = append(cookies, getCookie(d, Timestamp, strconv.Itoa(int(d.Timestamp.UTC().Unix())), "", domain))
	cookies = append(cookies, getCookie(d, Expires, strconv.Itoa(int(d.Expires.UTC().Unix())), "", domain))
	cookies = append(cookies, getCookie(d, Roles, strings.Join(d.Roles, ","), "", domain))

	cookies = append(cookies, getCookie(d, Signature, c.GenerateSignature(d), "", domain))
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
}

func (c *Client) GetDomain(r *http.Request) string {
	host := r.URL.Host
	host = strings.TrimSpace(host)
	addr := net.ParseIP(host)
	if addr != nil {
		return ""
	}
	hostParts := strings.Split(host, ".")
	if len(hostParts) > 2 {
		return "." + strings.Join(hostParts[1:], ".")
	}
	return ""
}

func (c *Client) GetAccountID(w http.ResponseWriter, r *http.Request) string {
	user, _ := GetCookieData(r)
	if user != nil && user.AccountID != "" {
		return user.AccountID
	}
	return fmt.Sprintf("%s_acc", c.GetUniqueID(w, r))
}

func (c *Client) SetUniqueID(w http.ResponseWriter, r *http.Request) string {
	uid := uuid.New().String()
	domain := c.Domain
	if domain == "" && c.IgnoreSubdomain {
		domain = c.GetDomain(r)
	}

	cd := &http.Cookie{
		Name:     "nsiuid",
		Value:    uid,
		Domain:   domain,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   0,
	}

	r.AddCookie(cd)
	http.SetCookie(w, cd)

	return uid
}

func (c *Client) GetUniqueID(w http.ResponseWriter, r *http.Request) string {
	user, _ := GetCookieData(r)
	if user != nil && user.UID != "" {
		return user.UID
	}
	nsiuid, err := r.Cookie("nsiuid")
	if err != nil || nsiuid == nil || nsiuid.Value == "" {
		return c.SetUniqueID(w, r)
	}
	return nsiuid.Value
}
