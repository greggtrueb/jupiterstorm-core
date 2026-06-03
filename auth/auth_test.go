package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// --- signSession / verifySession -------------------------------------------

func TestSignAndVerifySession(t *testing.T) {
	secret := "test-secret"
	email := "user@example.com"
	name := "Test User"
	role := "manager"

	cookie, err := signSession(email, name, role, secret)
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	gotEmail, gotName, gotRole, err := verifySession(cookie, secret)
	if err != nil {
		t.Fatalf("verifySession: %v", err)
	}
	if gotEmail != email {
		t.Errorf("email: got %q, want %q", gotEmail, email)
	}
	if gotName != name {
		t.Errorf("name: got %q, want %q", gotName, name)
	}
	if gotRole != role {
		t.Errorf("role: got %q, want %q", gotRole, role)
	}
}

func TestVerifySession_WrongSecret(t *testing.T) {
	cookie, err := signSession("user@example.com", "Name", "staff", "secret-a")
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}
	_, _, _, err = verifySession(cookie, "secret-b")
	if err == nil {
		t.Fatal("expected error with wrong secret, got nil")
	}
}

func TestVerifySession_TamperedPayload(t *testing.T) {
	cookie, err := signSession("user@example.com", "Name", "staff", "secret")
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	// Decode, alter email, re-encode without updating HMAC
	raw, _ := base64.StdEncoding.DecodeString(cookie)
	tampered := strings.Replace(string(raw), "user@example.com", "evil@example.com", 1)
	tamperedCookie := base64.StdEncoding.EncodeToString([]byte(tampered))

	_, _, _, err = verifySession(tamperedCookie, "secret")
	if err == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
}

func TestVerifySession_TamperedRole(t *testing.T) {
	cookie, err := signSession("user@example.com", "Name", "staff", "secret")
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	// Promote staff → admin by tampering the cookie without re-signing
	raw, _ := base64.StdEncoding.DecodeString(cookie)
	tampered := strings.Replace(string(raw), "|staff|", "|admin|", 1)
	tamperedCookie := base64.StdEncoding.EncodeToString([]byte(tampered))

	_, _, _, err = verifySession(tamperedCookie, "secret")
	if err == nil {
		t.Fatal("expected error for tampered role, got nil")
	}
}

func TestVerifySession_InvalidBase64(t *testing.T) {
	_, _, _, err := verifySession("not-valid-base64!!!", "secret")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestVerifySession_MalformedTooFewParts(t *testing.T) {
	// Valid base64 but wrong structure
	cookie := base64.StdEncoding.EncodeToString([]byte("onlytwoparts|here"))
	_, _, _, err := verifySession(cookie, "secret")
	if err == nil {
		t.Fatal("expected error for malformed session, got nil")
	}
}

// signSessionAt builds a valid cookie value with a caller-supplied Unix timestamp.
// Used to test expiry and future-timestamp rejection without time.Sleep.
func signSessionAt(email, name, role, secret string, ts int64) string {
	payload := fmt.Sprintf("%s|%s|%s|%d", email, name, role, ts)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(payload + "|" + sig))
}

func TestVerifySession_Expired(t *testing.T) {
	secret := "secret"
	old := time.Now().Add(-25 * time.Hour).Unix() // older than sessionMaxAge (24h)
	cookie := signSessionAt("user@example.com", "Name", "staff", secret, old)
	_, _, _, err := verifySession(cookie, secret)
	if err == nil {
		t.Fatal("expected error for expired session, got nil")
	}
}

func TestVerifySession_FutureTimestamp(t *testing.T) {
	secret := "secret"
	future := time.Now().Add(1 * time.Hour).Unix() // 1 hour in the future
	cookie := signSessionAt("user@example.com", "Name", "staff", secret, future)
	_, _, _, err := verifySession(cookie, secret)
	if err == nil {
		t.Fatal("expected error for future session timestamp, got nil")
	}
}

// --- generateState ----------------------------------------------------------

func TestGenerateState(t *testing.T) {
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if s1 == "" {
		t.Fatal("generateState returned empty string")
	}

	s2, err := generateState()
	if err != nil {
		t.Fatalf("generateState second call: %v", err)
	}
	if s1 == s2 {
		t.Error("generateState returned identical values on consecutive calls")
	}
}

// --- RequireSession middleware -----------------------------------------------

func newTestContext(method, path string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(method, path, nil)
	return c, w
}

func TestRequireSession_NoCookie(t *testing.T) {
	c, w := newTestContext(http.MethodGet, "/")
	RequireSession("secret", false)(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !c.IsAborted() {
		t.Error("context should be aborted")
	}
}

func TestRequireSession_InvalidCookie(t *testing.T) {
	c, w := newTestContext(http.MethodGet, "/")
	c.Request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "garbage"})
	RequireSession("secret", false)(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !c.IsAborted() {
		t.Error("context should be aborted")
	}
}

func TestRequireSession_ValidCookie(t *testing.T) {
	secret := "test-secret"
	cookie, err := signSession("user@example.com", "Test User", "manager", secret)
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	c, w := newTestContext(http.MethodGet, "/")
	c.Request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})

	RequireSession(secret, false)(c)

	if w.Code == http.StatusUnauthorized {
		t.Errorf("should not be unauthorized with valid cookie")
	}
	if c.IsAborted() {
		t.Error("context should not be aborted")
	}

	email, exists := c.Get("userEmail")
	if !exists {
		t.Fatal("userEmail not set in context")
	}
	if email != "user@example.com" {
		t.Errorf("userEmail: got %q, want %q", email, "user@example.com")
	}

	name, exists := c.Get("userName")
	if !exists {
		t.Fatal("userName not set in context")
	}
	if name != "Test User" {
		t.Errorf("userName: got %q, want %q", name, "Test User")
	}

	role, exists := c.Get("userRole")
	if !exists {
		t.Fatal("userRole not set in context")
	}
	if role != "manager" {
		t.Errorf("userRole: got %q, want %q", role, "manager")
	}
}

func TestRequireSession_ValidBearerToken(t *testing.T) {
	secret := "test-secret"
	token, err := signSession("api@example.com", "API User", "admin", secret)
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	c, w := newTestContext(http.MethodGet, "/")
	c.Request.Header.Set("Authorization", "Bearer "+token)

	RequireSession(secret, false)(c)

	if w.Code == http.StatusUnauthorized {
		t.Errorf("should not be unauthorized with valid bearer token")
	}
	role, _ := c.Get("userRole")
	if role != "admin" {
		t.Errorf("userRole: got %q, want %q", role, "admin")
	}
}

func TestRequireSession_AuthDisabled(t *testing.T) {
	c, _ := newTestContext(http.MethodGet, "/")
	RequireSession("secret", true)(c)

	if c.IsAborted() {
		t.Error("context should not be aborted when auth is disabled")
	}
	role, exists := c.Get("userRole")
	if !exists {
		t.Fatal("userRole not set in context when auth is disabled")
	}
	if role != "admin" {
		t.Errorf("auth disabled should grant admin role, got %q", role)
	}
}

// --- RequireRole middleware --------------------------------------------------

func contextWithRole(role string) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	c.Set("userRole", role)
	return c
}

func TestRequireRole_Allowed(t *testing.T) {
	c := contextWithRole("manager")
	RequireRole("admin", "manager")(c)
	if c.IsAborted() {
		t.Error("manager should be allowed; context should not be aborted")
	}
}

func TestRequireRole_Denied(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	c.Set("userRole", "staff")
	RequireRole("admin", "manager")(c)
	if !c.IsAborted() {
		t.Error("staff should be denied; context should be aborted")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRequireRole_Admin(t *testing.T) {
	c := contextWithRole("admin")
	RequireRole("admin", "manager")(c)
	if c.IsAborted() {
		t.Error("admin should be allowed")
	}
}

// --- NewHandler -------------------------------------------------------------

func TestNewHandler_RedirectURL(t *testing.T) {
	h := NewHandler("cid", "csec", "https://example.com", "example.com", "secret")
	want := "https://example.com/auth/callback"
	if h.config.RedirectURL != want {
		t.Errorf("RedirectURL: got %q, want %q", h.config.RedirectURL, want)
	}
	if h.allowedDomain != "example.com" {
		t.Errorf("allowedDomain: got %q, want %q", h.allowedDomain, "example.com")
	}
}
