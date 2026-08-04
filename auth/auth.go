package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const sessionCookieName = "jupiterstorm_session"

// Handler manages Google OAuth2 login, callback, and logout.
type Handler struct {
	config        *oauth2.Config
	allowedDomain string
	sessionSecret string
}

// NewHandler creates a new auth Handler.
// allowedDomain restricts login to a specific Google Workspace domain (e.g. "yourrestaurant.com").
// Leave empty to use an allowlist approach instead (implement AllowedEmails check in Callback).
func NewHandler(clientID, clientSecret, baseURL, allowedDomain, sessionSecret string) *Handler {
	return &Handler{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  baseURL + "/auth/callback",
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
		allowedDomain: allowedDomain,
		sessionSecret: sessionSecret,
	}
}

// Login redirects the user to Google's OAuth2 consent screen.
func (h *Handler) Login(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	setStateCookie(c, state)
	url := h.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Callback handles the redirect from Google, validates the user, and sets a session cookie.
func (h *Handler) Callback(c *gin.Context) {
	if err := validateAndClearStateCookie(c, c.Query("state")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	token, err := h.config.Exchange(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token exchange failed"})
		return
	}

	userInfo, err := fetchGoogleUserInfo(c.Request.Context(), token.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user info"})
		return
	}

	// Domain restriction
	if h.allowedDomain != "" {
		parts := strings.Split(userInfo.Email, "@")
		if len(parts) != 2 || parts[1] != h.allowedDomain {
			c.JSON(http.StatusForbidden, gin.H{"error": "email domain not allowed"})
			return
		}
	}

	role := "staff"

	// Create signed session cookie. The direct-Google path has no stable subject
	// claim to carry (googleUserInfo is {Email, Name} only), so sub is empty.
	sessionValue, err := signSession(userInfo.Email, userInfo.Name, role, "", h.sessionSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}

	c.SetCookie(sessionCookieName, sessionValue, int(24*time.Hour/time.Second), "/", "", true, true)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

// Logout clears the session cookie.
func (h *Handler) Logout(c *gin.Context) {
	c.SetCookie(sessionCookieName, "", -1, "/", "", true, true)
	c.Redirect(http.StatusTemporaryRedirect, "/auth/google")
}

// RequireSession is Gin middleware that rejects unauthenticated requests.
// It accepts the signed session value either as a cookie (browser clients) or
// as an Authorization: Bearer <value> header (CLI/API clients).
//
// On success it sets "userEmail", "userName", "userRole", and "userSub" in the Gin context.
// userEmail/userName/userRole are frozen — unchanged by this addition. userSub is Keycloak's
// stable subject claim; it is "" for sessions minted before this change (v1) or by the legacy
// direct-Google path, which has no stable ID.
//
// When authDisabled is true all requests are allowed through with a fixed dev
// identity (admin role) — only set this via AUTH_DISABLED=true in non-production environments.
func RequireSession(sessionSecret string, authDisabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authDisabled {
			c.Set("userEmail", "dev@local")
			c.Set("userName", "Dev User")
			c.Set("userRole", "admin")
			c.Set("userSub", "dev-sub")
			c.Next()
			return
		}

		var sessionValue string

		if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			sessionValue = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			var err error
			sessionValue, err = c.Cookie(sessionCookieName)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
				return
			}
		}

		email, name, role, sub, err := verifySession(sessionValue, sessionSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
			return
		}

		c.Set("userEmail", email)
		c.Set("userName", name)
		c.Set("userRole", role)
		c.Set("userSub", sub)
		c.Next()
	}
}

// RequireRole returns Gin middleware that allows only the specified roles through.
// Must be placed after RequireSession in the middleware chain.
// Roles are checked in order; the first match allows the request.
// Roles: "admin", "manager", "staff".
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		role, _ := c.Get("userRole")
		if allowed[role.(string)] {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	}
}

// --- helpers -----------------------------------------------------------------

type googleUserInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func fetchGoogleUserInfo(ctx context.Context, accessToken string) (*googleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.googleapis.com/oauth2/v2/userinfo?access_token="+accessToken, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var info googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// signSession creates a base64-encoded "email|name|role|sub|timestamp|hmac" cookie value.
// sub is Keycloak's stable subject claim; pass "" for identity providers that don't have one
// (the legacy direct-Google path).
func signSession(email, name, role, sub, secret string) (string, error) {
	if strings.Contains(email, "|") || strings.Contains(name, "|") || strings.Contains(role, "|") || strings.Contains(sub, "|") {
		return "", fmt.Errorf("session fields must not contain '|'")
	}
	payload := fmt.Sprintf("%s|%s|%s|%s|%d", email, name, role, sub, time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(payload + "|" + sig)), nil
}

const sessionMaxAge = 24 * time.Hour

// verifySession validates the HMAC signature, checks expiry, and returns email, name, role, and sub.
//
// Sessions are shared across products via SESSION_SECRET, so this accepts two wire formats:
//   - v1 (5 parts): email|name|role|ts|mac — sub is returned as "" for these
//   - v2 (6 parts): email|name|role|sub|ts|mac
//
// The v1 branch exists only so a cookie/CLI token minted before this change keeps working; it can
// be deleted once every session minted before the deploy has expired (sessionMaxAge after rollout).
func verifySession(cookie, secret string) (string, string, string, string, error) {
	raw, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid cookie encoding")
	}

	parts := strings.Split(string(raw), "|")

	var email, name, role, sub, tsStr, sig string
	switch len(parts) {
	case 5: // v1: email|name|role|ts|sig
		email, name, role, tsStr, sig = parts[0], parts[1], parts[2], parts[3], parts[4]
	case 6: // v2: email|name|role|sub|ts|sig
		email, name, role, sub, tsStr, sig = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	default:
		return "", "", "", "", fmt.Errorf("malformed session")
	}
	payload := strings.Join(parts[:len(parts)-1], "|")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", "", "", "", fmt.Errorf("invalid session signature")
	}

	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil {
		return "", "", "", "", fmt.Errorf("malformed session timestamp")
	}

	issuedAt := time.Unix(ts, 0)
	now := time.Now()
	if issuedAt.After(now) {
		return "", "", "", "", fmt.Errorf("invalid session timestamp")
	}
	if now.Sub(issuedAt) > sessionMaxAge {
		return "", "", "", "", fmt.Errorf("session expired")
	}

	return email, name, role, sub, nil
}

const oauthStateCookie = "oauth_state"

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func setStateCookie(c *gin.Context, state string) {
	c.SetCookie(oauthStateCookie, state, 600, "/", "", true, true) // 10 min
}

func validateAndClearStateCookie(c *gin.Context, state string) error {
	stored, err := c.Cookie(oauthStateCookie)
	c.SetCookie(oauthStateCookie, "", -1, "/", "", true, true) // always clear
	if err != nil || stored == "" {
		return fmt.Errorf("missing state cookie")
	}
	if !hmac.Equal([]byte(stored), []byte(state)) {
		return fmt.Errorf("state mismatch")
	}
	return nil
}
