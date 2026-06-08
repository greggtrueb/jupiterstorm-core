package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// RoleMapping controls how Keycloak realm/client roles are resolved to a single
// session role. Precedence is checked highest-priority first; the first match wins.
// Default is returned when no Precedence role is present in the token.
//
// Storm default: Precedence ["admin","manager","staff"], Default "staff".
// Sportstrak example: Precedence ["admin","org","stat","crowd"], Default "crowd".
type RoleMapping struct {
	Precedence []string
	Default    string
}

var defaultRoleMapping = RoleMapping{
	Precedence: []string{"admin", "manager", "staff"},
	Default:    "staff",
}

// KeycloakHandler manages Keycloak OIDC login, callback, logout, and device flow.
type KeycloakHandler struct {
	config        *oauth2.Config
	userInfoURL   string
	logoutURL     string
	deviceAuthURL string
	cliClientID   string
	sessionSecret string
	baseURL       string
	roleMapping   RoleMapping
	// fwdHost and fwdProto are the public Keycloak hostname and scheme (derived from publicURL).
	// They are sent as X-Forwarded-Host / X-Forwarded-Proto on internal server-to-server calls so
	// that Keycloak (which uses KC_PROXY_HEADERS=xforwarded) computes the correct https:// issuer
	// instead of falling back to the internal http://keycloak:8080 request URL.
	fwdHost  string
	fwdProto string
}

// WithRoleMapping sets a custom role mapping for this handler and returns the handler
// for chaining. When not called, Storm's default mapping is used (admin > manager > staff).
func (h *KeycloakHandler) WithRoleMapping(m RoleMapping) *KeycloakHandler {
	h.roleMapping = m
	return h
}

func (h *KeycloakHandler) effectiveMapping() RoleMapping {
	if len(h.roleMapping.Precedence) == 0 {
		return defaultRoleMapping
	}
	return h.roleMapping
}

// NewKeycloakHandler creates a Keycloak OIDC handler.
//
// serverURL is the URL the API uses to reach Keycloak for server-to-server
// calls (token exchange, userinfo). Inside Docker Compose this is the internal
// service URL, e.g. "http://keycloak:8080".
//
// publicURL is the URL the browser uses to reach Keycloak for login/logout
// redirects, e.g. "http://localhost:8180". When running outside Docker both
// values can be the same. Pass "" to fall back to serverURL.
//
// realm is the Keycloak realm name (e.g. "jupiterstorm").
//
// cliClientID is the Keycloak client ID for the CLI device authorization flow
// (the public client with no client secret). Defaults to "jupiterstorm-cli" if empty.
//
func NewKeycloakHandler(serverURL, publicURL, realm, clientID, clientSecret, baseURL, sessionSecret, cliClientID string) *KeycloakHandler {
	if publicURL == "" {
		publicURL = serverURL
	}
	if cliClientID == "" {
		cliClientID = "jupiterstorm-cli"
	}
	serverBase := strings.TrimRight(serverURL, "/") + "/realms/" + realm + "/protocol/openid-connect"
	publicBase := strings.TrimRight(publicURL, "/") + "/realms/" + realm + "/protocol/openid-connect"

	parsedPublic, _ := url.Parse(strings.TrimRight(publicURL, "/"))
	fwdHost := parsedPublic.Host
	fwdProto := parsedPublic.Scheme

	return &KeycloakHandler{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  baseURL + "/auth/keycloak/callback",
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  publicBase + "/auth",  // browser-facing redirect
				TokenURL: serverBase + "/token", // server-to-server
			},
		},
		userInfoURL:   serverBase + "/userinfo",    // server-to-server
		logoutURL:     publicBase + "/logout",      // browser-facing redirect
		deviceAuthURL: serverBase + "/auth/device", // device authorization endpoint
		cliClientID:   cliClientID,
		sessionSecret: sessionSecret,
		baseURL:       baseURL,
		fwdHost:       fwdHost,
		fwdProto:      fwdProto,
	}
}

// Login redirects the user to the Keycloak login page.
// An optional ?redirect= query parameter is stored in the state cookie so
// Callback can return the user to their original destination after login.
func (h *KeycloakHandler) Login(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	// Embed the post-login redirect path in the state cookie value so it
	// survives the round-trip through Keycloak without an extra session store.
	// Format: "<random-state>|<redirect-path>"
	redirectPath := c.Query("redirect")
	if redirectPath == "" {
		redirectPath = "/"
	}
	stateWithRedirect := state + "|" + redirectPath
	setStateCookie(c, stateWithRedirect)
	authURL := h.config.AuthCodeURL(stateWithRedirect, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback handles the redirect from Keycloak, validates the user, and sets a session cookie.
func (h *KeycloakHandler) Callback(c *gin.Context) {
	rawState := c.Query("state")
	if err := validateAndClearStateCookie(c, rawState); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}

	// Extract the optional redirect path embedded in the state value.
	redirectTo := "/"
	if idx := strings.Index(rawState, "|"); idx >= 0 {
		if p := rawState[idx+1:]; p != "" {
			redirectTo = p
		}
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

	userInfo, err := fetchKeycloakUserInfo(c.Request.Context(), h.userInfoURL, token.AccessToken, h.fwdHost, h.fwdProto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user info"})
		return
	}

	role := extractKeycloakRole(token.AccessToken, h.config.ClientID, h.effectiveMapping())

	sessionValue, err := signSession(userInfo.Email, userInfo.Name, role, h.sessionSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}

	c.SetCookie(sessionCookieName, sessionValue, int(24*time.Hour/time.Second), "/", "", true, true)
	c.Redirect(http.StatusTemporaryRedirect, redirectTo)
}

// DeviceAuthorize proxies a device authorization request to Keycloak and returns
// the device_code, user_code, verification_uri, etc. to the CLI client.
func (h *KeycloakHandler) DeviceAuthorize(c *gin.Context) {
	form := url.Values{
		"client_id": {h.cliClientID},
		"scope":     {"openid email profile"},
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, h.deviceAuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "keycloak unreachable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("keycloak returned %d", resp.StatusCode)})
		return
	}

	var dar map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dar); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode keycloak response"})
		return
	}
	c.JSON(http.StatusOK, dar)
}

type deviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

// DeviceToken polls Keycloak's token endpoint with a device code.
// Returns 200+token on success, 202+pending while authorization is pending,
// 429 on slow_down, or 401 on expiry/denial.
func (h *KeycloakHandler) DeviceToken(c *gin.Context) {
	var req deviceTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.DeviceCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_code required"})
		return
	}

	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {req.DeviceCode},
		"client_id":   {h.cliClientID},
	}
	httpReq, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, h.config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "keycloak unreachable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode keycloak response"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		errCode, _ := body["error"].(string)
		switch errCode {
		case "authorization_pending":
			c.JSON(http.StatusAccepted, gin.H{"status": "pending"})
		case "slow_down":
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "slow_down"})
		case "access_denied":
			c.JSON(http.StatusUnauthorized, gin.H{"error": "access_denied"})
		default:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization_expired"})
		}
		return
	}

	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no access_token in keycloak response"})
		return
	}

	ctx := c.Request.Context()
	userInfo, err := fetchKeycloakUserInfo(ctx, h.userInfoURL, accessToken, h.fwdHost, h.fwdProto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user info"})
		return
	}

	role := extractKeycloakRole(accessToken, h.cliClientID, h.effectiveMapping())

	sessionValue, err := signSession(userInfo.Email, userInfo.Name, role, h.sessionSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	c.JSON(http.StatusOK, gin.H{"token": sessionValue, "expires_at": expiresAt})
}

type exchangeTokenRequest struct {
	AccessToken string `json:"access_token"`
}

// ExchangeToken accepts a Keycloak access token from a trusted server-side caller
// (the Next.js UI), validates it against Keycloak's userinfo endpoint, and returns
// an HMAC-signed API session value. The caller is responsible for setting the cookie.
func (h *KeycloakHandler) ExchangeToken(c *gin.Context) {
	var req exchangeTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.AccessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_token required"})
		return
	}

	ctx := c.Request.Context()
	userInfo, err := fetchKeycloakUserInfo(ctx, h.userInfoURL, req.AccessToken, h.fwdHost, h.fwdProto)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	role := extractKeycloakRole(req.AccessToken, h.config.ClientID, h.effectiveMapping())

	sessionValue, err := signSession(userInfo.Email, userInfo.Name, role, h.sessionSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"session": sessionValue})
}

// Logout clears the local session cookie and redirects to Keycloak's logout endpoint.
func (h *KeycloakHandler) Logout(c *gin.Context) {
	c.SetCookie(sessionCookieName, "", -1, "/", "", true, true)
	logoutURL := h.logoutURL + "?redirect_uri=" + url.QueryEscape(h.baseURL+"/")
	c.Redirect(http.StatusTemporaryRedirect, logoutURL)
}

// --- helpers -----------------------------------------------------------------

type keycloakTokenClaims struct {
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// extractKeycloakRole parses role claims from a JWT access token without verifying the
// JWT signature. This is only intended for access tokens that this server has just
// obtained directly from Keycloak's token endpoint over HTTPS/TLS. Do not reuse this
// helper for tokens supplied by clients or read from headers, cookies, query params,
// logs, or any other untrusted source.
// It returns the highest-priority role from m.Precedence found in realm_access or
// resource_access[clientID], falling back to m.Default.
func extractKeycloakRole(accessToken, clientID string, m RoleMapping) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return m.Default
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return m.Default
	}
	var claims keycloakTokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return m.Default
	}

	roleSet := make(map[string]bool)
	for _, r := range claims.RealmAccess.Roles {
		roleSet[r] = true
	}
	if cr, ok := claims.ResourceAccess[clientID]; ok {
		for _, r := range cr.Roles {
			roleSet[r] = true
		}
	}

	for _, r := range m.Precedence {
		if roleSet[r] {
			return r
		}
	}
	return m.Default
}

type keycloakUserInfo struct {
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

func fetchKeycloakUserInfo(ctx context.Context, userInfoURL, accessToken, fwdHost, fwdProto string) (*keycloakUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	// Tell Keycloak (which uses KC_PROXY_HEADERS=xforwarded) what the public hostname and scheme
	// are, so it computes the correct https:// issuer when validating the token — otherwise it
	// falls back to the internal http://keycloak:8080 request URL and the issuer check fails.
	if fwdHost != "" {
		req.Header.Set("X-Forwarded-Host", fwdHost)
	}
	if fwdProto != "" {
		req.Header.Set("X-Forwarded-Proto", fwdProto)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak userinfo request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak userinfo returned %d", resp.StatusCode)
	}

	var info keycloakUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	// Fall back to preferred_username if name is not populated
	if info.Name == "" {
		info.Name = info.PreferredUsername
	}

	return &info, nil
}
