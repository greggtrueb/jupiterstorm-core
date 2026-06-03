package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// --- NewKeycloakHandler -----------------------------------------------------

func TestNewKeycloakHandler_URLs(t *testing.T) {
	h := NewKeycloakHandler(
		"http://keycloak:8080",
		"http://localhost:8180",
		"myrealm",
		"client-id",
		"client-secret",
		"http://api:8080",
		"session-secret",
		"",
	)

	wantRedirect := "http://api:8080/auth/keycloak/callback"
	if h.config.RedirectURL != wantRedirect {
		t.Errorf("RedirectURL: got %q, want %q", h.config.RedirectURL, wantRedirect)
	}

	// AuthURL should use publicURL (browser-facing)
	wantAuth := "http://localhost:8180/realms/myrealm/protocol/openid-connect/auth"
	if h.config.Endpoint.AuthURL != wantAuth {
		t.Errorf("AuthURL: got %q, want %q", h.config.Endpoint.AuthURL, wantAuth)
	}

	// TokenURL should use serverURL (server-to-server)
	wantToken := "http://keycloak:8080/realms/myrealm/protocol/openid-connect/token"
	if h.config.Endpoint.TokenURL != wantToken {
		t.Errorf("TokenURL: got %q, want %q", h.config.Endpoint.TokenURL, wantToken)
	}

	// userInfoURL should use serverURL
	wantUserInfo := "http://keycloak:8080/realms/myrealm/protocol/openid-connect/userinfo"
	if h.userInfoURL != wantUserInfo {
		t.Errorf("userInfoURL: got %q, want %q", h.userInfoURL, wantUserInfo)
	}

	// logoutURL should use publicURL
	wantLogout := "http://localhost:8180/realms/myrealm/protocol/openid-connect/logout"
	if h.logoutURL != wantLogout {
		t.Errorf("logoutURL: got %q, want %q", h.logoutURL, wantLogout)
	}
}

func TestNewKeycloakHandler_TrailingSlash(t *testing.T) {
	h := NewKeycloakHandler(
		"http://keycloak:8080/",
		"",
		"realm",
		"cid",
		"csec",
		"http://api",
		"sec",
		"",
	)
	// Should not double-slash
	wantToken := "http://keycloak:8080/realms/realm/protocol/openid-connect/token"
	if h.config.Endpoint.TokenURL != wantToken {
		t.Errorf("TokenURL with trailing slash: got %q, want %q", h.config.Endpoint.TokenURL, wantToken)
	}
}

func TestNewKeycloakHandler_PublicURLFallback(t *testing.T) {
	h := NewKeycloakHandler(
		"http://keycloak:8080",
		"", // empty → fall back to serverURL
		"realm",
		"cid", "csec", "http://api", "sec", "",
	)
	wantAuth := "http://keycloak:8080/realms/realm/protocol/openid-connect/auth"
	if h.config.Endpoint.AuthURL != wantAuth {
		t.Errorf("AuthURL fallback: got %q, want %q", h.config.Endpoint.AuthURL, wantAuth)
	}
}

// --- fetchKeycloakUserInfo --------------------------------------------------

func TestFetchKeycloakUserInfo_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer mytoken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(keycloakUserInfo{
			Email: "user@example.com",
			Name:  "Test User",
		})
	}))
	defer srv.Close()

	info, err := fetchKeycloakUserInfo(context.Background(), srv.URL, "mytoken", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Email != "user@example.com" {
		t.Errorf("email: got %q", info.Email)
	}
	if info.Name != "Test User" {
		t.Errorf("name: got %q", info.Name)
	}
}

func TestFetchKeycloakUserInfo_NameFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(keycloakUserInfo{
			Email:             "user@example.com",
			Name:              "",
			PreferredUsername: "jdoe",
		})
	}))
	defer srv.Close()

	info, err := fetchKeycloakUserInfo(context.Background(), srv.URL, "tok", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "jdoe" {
		t.Errorf("name fallback: got %q, want %q", info.Name, "jdoe")
	}
}

func TestFetchKeycloakUserInfo_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := fetchKeycloakUserInfo(context.Background(), srv.URL, "bad-token", "", "")
	if err == nil {
		t.Fatal("expected error for non-200, got nil")
	}
}

func TestFetchKeycloakUserInfo_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := fetchKeycloakUserInfo(context.Background(), srv.URL, "tok", "", "")
	if err == nil {
		t.Fatal("expected error for bad JSON, got nil")
	}
}

func TestFetchKeycloakUserInfo_InvalidURL(t *testing.T) {
	_, err := fetchKeycloakUserInfo(context.Background(), "http://127.0.0.1:1", "tok", "", "")
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestFetchKeycloakUserInfo_ForwardedHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-Host"); got != "auth.example.com" {
			t.Errorf("X-Forwarded-Host: got %q, want auth.example.com", got)
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("X-Forwarded-Proto: got %q, want https", got)
		}
		_ = json.NewEncoder(w).Encode(keycloakUserInfo{Email: "u@example.com", Name: "U"})
	}))
	defer srv.Close()

	if _, err := fetchKeycloakUserInfo(context.Background(), srv.URL, "tok", "auth.example.com", "https"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- extractKeycloakRole ----------------------------------------------------

// makeJWT encodes a payload as a minimal unsigned JWT (header.payload.sig).
func makeJWT(payload any) string {
	b, _ := json.Marshal(payload)
	return "header." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestExtractKeycloakRole_RealmAdmin(t *testing.T) {
	tok := makeJWT(map[string]any{
		"realm_access": map[string]any{"roles": []string{"admin", "offline_access"}},
	})
	if got := extractKeycloakRole(tok, "my-client"); got != "admin" {
		t.Errorf("got %q, want admin", got)
	}
}

func TestExtractKeycloakRole_ClientManager(t *testing.T) {
	tok := makeJWT(map[string]any{
		"resource_access": map[string]any{
			"my-client": map[string]any{"roles": []string{"manager"}},
		},
	})
	if got := extractKeycloakRole(tok, "my-client"); got != "manager" {
		t.Errorf("got %q, want manager", got)
	}
}

func TestExtractKeycloakRole_AdminBeatsManager(t *testing.T) {
	tok := makeJWT(map[string]any{
		"realm_access": map[string]any{"roles": []string{"manager"}},
		"resource_access": map[string]any{
			"my-client": map[string]any{"roles": []string{"admin"}},
		},
	})
	if got := extractKeycloakRole(tok, "my-client"); got != "admin" {
		t.Errorf("got %q, want admin", got)
	}
}

func TestExtractKeycloakRole_NoMatchDefaultsToStaff(t *testing.T) {
	tok := makeJWT(map[string]any{
		"realm_access": map[string]any{"roles": []string{"offline_access", "uma_authorization"}},
	})
	if got := extractKeycloakRole(tok, "my-client"); got != "staff" {
		t.Errorf("got %q, want staff", got)
	}
}

func TestExtractKeycloakRole_MalformedToken(t *testing.T) {
	if got := extractKeycloakRole("notajwt", "client"); got != "staff" {
		t.Errorf("got %q, want staff", got)
	}
}

func TestExtractKeycloakRole_BadBase64(t *testing.T) {
	if got := extractKeycloakRole("h.!!!.s", "client"); got != "staff" {
		t.Errorf("got %q, want staff", got)
	}
}

// --- NewKeycloakHandler device auth fields ----------------------------------

func TestNewKeycloakHandler_DeviceAuthURL(t *testing.T) {
	h := NewKeycloakHandler("http://keycloak:8080", "", "realm", "cid", "csec", "http://api", "sec", "my-cli")
	want := "http://keycloak:8080/realms/realm/protocol/openid-connect/auth/device"
	if h.deviceAuthURL != want {
		t.Errorf("deviceAuthURL: got %q, want %q", h.deviceAuthURL, want)
	}
	if h.cliClientID != "my-cli" {
		t.Errorf("cliClientID: got %q, want my-cli", h.cliClientID)
	}
}

func TestNewKeycloakHandler_CLIClientIDDefault(t *testing.T) {
	h := NewKeycloakHandler("http://keycloak:8080", "", "realm", "cid", "csec", "http://api", "sec", "")
	if h.cliClientID != "jupiterstorm-cli" {
		t.Errorf("cliClientID default: got %q, want jupiterstorm-cli", h.cliClientID)
	}
}

func TestNewKeycloakHandler_ForwardedFields(t *testing.T) {
	h := NewKeycloakHandler(
		"http://keycloak:8080",
		"https://auth.example.com",
		"realm", "cid", "csec", "http://api", "sec", "",
	)
	if h.fwdHost != "auth.example.com" {
		t.Errorf("fwdHost: got %q, want auth.example.com", h.fwdHost)
	}
	if h.fwdProto != "https" {
		t.Errorf("fwdProto: got %q, want https", h.fwdProto)
	}
}

// --- DeviceAuthorize --------------------------------------------------------

func TestDeviceAuthorize_success(t *testing.T) {
	kcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.Form.Get("client_id") != "test-cli" {
			t.Errorf("client_id: got %q, want test-cli", r.Form.Get("client_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev-code",
			"user_code":        "USER-CODE",
			"verification_uri": "http://example.com/device",
			"expires_in":       600,
			"interval":         5,
		})
	}))
	defer kcSrv.Close()

	h := &KeycloakHandler{deviceAuthURL: kcSrv.URL, cliClientID: "test-cli"}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/device-authorize", nil)
	h.DeviceAuthorize(c)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["device_code"] != "dev-code" {
		t.Errorf("device_code: got %v", body["device_code"])
	}
}

func TestDeviceAuthorize_keycloakError(t *testing.T) {
	kcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer kcSrv.Close()

	h := &KeycloakHandler{deviceAuthURL: kcSrv.URL, cliClientID: "test-cli"}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/device-authorize", nil)
	h.DeviceAuthorize(c)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status: got %d, want 502", w.Code)
	}
}

// --- DeviceToken ------------------------------------------------------------

func newDeviceTokenHandler(t *testing.T, tokenStatus int, tokenBody map[string]any, userInfoBody *keycloakUserInfo) *KeycloakHandler {
	t.Helper()
	userInfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(userInfoBody)
	}))
	t.Cleanup(userInfoSrv.Close)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tokenStatus)
		_ = json.NewEncoder(w).Encode(tokenBody)
	}))
	t.Cleanup(tokenSrv.Close)

	return &KeycloakHandler{
		config:        &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: tokenSrv.URL}},
		userInfoURL:   userInfoSrv.URL,
		cliClientID:   "test-cli",
		sessionSecret: "test-secret",
	}
}

func TestDeviceToken_success(t *testing.T) {
	accessTok := makeJWT(map[string]any{"realm_access": map[string]any{"roles": []string{"staff"}}})
	h := newDeviceTokenHandler(t,
		http.StatusOK,
		map[string]any{"access_token": accessTok},
		&keycloakUserInfo{Email: "user@example.com", Name: "Test User"},
	)

	body := `{"device_code":"dev-abc"}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.DeviceToken(c)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["token"] == "" || resp["token"] == nil {
		t.Error("expected non-empty token")
	}
	if resp["expires_at"] == nil {
		t.Error("expected expires_at")
	}
}

func TestDeviceToken_pending(t *testing.T) {
	h := newDeviceTokenHandler(t,
		http.StatusBadRequest,
		map[string]any{"error": "authorization_pending"},
		nil,
	)
	body := `{"device_code":"dev-abc"}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.DeviceToken(c)

	if w.Code != http.StatusAccepted {
		t.Errorf("status: got %d, want 202", w.Code)
	}
}

func TestDeviceToken_slowDown(t *testing.T) {
	h := newDeviceTokenHandler(t,
		http.StatusBadRequest,
		map[string]any{"error": "slow_down"},
		nil,
	)
	body := `{"device_code":"dev-abc"}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.DeviceToken(c)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status: got %d, want 429", w.Code)
	}
}

func TestDeviceToken_accessDenied(t *testing.T) {
	h := newDeviceTokenHandler(t,
		http.StatusUnauthorized,
		map[string]any{"error": "access_denied"},
		nil,
	)
	body := `{"device_code":"dev-abc"}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.DeviceToken(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "access_denied" {
		t.Errorf("error: got %v", resp["error"])
	}
}

func TestDeviceToken_expired(t *testing.T) {
	h := newDeviceTokenHandler(t,
		http.StatusUnauthorized,
		map[string]any{"error": "expired_token"},
		nil,
	)
	body := `{"device_code":"dev-abc"}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.DeviceToken(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "authorization_expired" {
		t.Errorf("error: got %v, want authorization_expired", resp["error"])
	}
}

func TestDeviceToken_missingDeviceCode(t *testing.T) {
	h := &KeycloakHandler{
		config:        &oauth2.Config{},
		cliClientID:   "test-cli",
		sessionSecret: "sec",
	}
	body := `{}`
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/auth/keycloak/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.DeviceToken(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}
