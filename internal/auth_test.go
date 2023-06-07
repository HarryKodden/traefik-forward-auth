package tfa

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

/**
 * Tests
 */

func TestAuthValidateCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	c := &http.Cookie{}

	// Should require 3 parts
	c.Value = ""
	_, err := ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}
	c.Value = "1|2"
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}
	c.Value = "1|2|3|4"
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}

	// Should catch invalid mac
	c.Value = "MQ==|2|3"
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie mac", err.Error())
	}

	// Should catch expired
	config.Lifetime = time.Second * time.Duration(-1)
	c = MakeCookie(r, "test@test.com")
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Cookie has expired", err.Error())
	}

	// Should accept valid cookie
	config.Lifetime = time.Second * time.Duration(10)
	c = MakeCookie(r, "test@test.com")
	email, err := ValidateCookie(r, c)
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("test@test.com", email, "valid request should return user email")
}

func TestRedirectUri(t *testing.T) {
	assert := assert.New(t)

	r := httptest.NewRequest("GET", "http://app.example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "http")

	//
	// No Auth Host
	//
	config, _ = NewConfig([]string{})

	uri, err := url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("app.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With Auth URL but no matching cookie domain
	// - will not use auth host
	//
	config.AuthHost = "auth.example.com"

	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("app.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With correct Auth URL + cookie domain
	//
	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}

	// Check url
	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("auth.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With Auth URL + cookie domain, but from different domain
	// - will not use auth host
	//
	r = httptest.NewRequest("GET", "https://another.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "https")

	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}

	// Check url
	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("another.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)
}

func TestAuthMakeCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	c := MakeCookie(r, "test@example.com")
	assert.Equal("_forward_auth", c.Name)
	parts := strings.Split(c.Value, "|")
	assert.Len(parts, 3, "cookie should be 3 parts")
	_, err := ValidateCookie(r, c)
	assert.Nil(err, "should generate valid cookie")
	assert.Equal("/", c.Path)
	assert.Equal("app.example.com", c.Domain)
	assert.True(c.Secure)

	expires := time.Now().Local().Add(config.Lifetime)
	assert.WithinDuration(expires, c.Expires, 10*time.Second)

	config.CookieName = "testname"
	config.InsecureCookie = true
	c = MakeCookie(r, "test@example.com")
	assert.Equal("testname", c.Name)
	assert.False(c.Secure)
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	// No cookie domain or auth url
	c := MakeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("_forward_auth_csrf_123456", c.Name)
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain but no auth url
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}
	c = MakeCSRFCookie(r, "12222278901234567890123456789012")
	assert.Equal("_forward_auth_csrf_122222", c.Name)
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain and auth url
	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}
	c = MakeCSRFCookie(r, "12333378901234567890123456789012")
	assert.Equal("_forward_auth_csrf_123333", c.Name)
	assert.Equal("example.com", c.Domain)
}

func TestAuthClearCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	c := ClearCSRFCookie(r, &http.Cookie{Name: "someCsrfCookie"})
	assert.Equal("someCsrfCookie", c.Name)
	if c.Value != "" {
		t.Error("ClearCSRFCookie should create cookie with empty value")
	}
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	c := &http.Cookie{}
	state := ""

	// Should require 32 char string
	state = ""
	c.Value = ""
	valid, _, _, err := ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, _, err = ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}

	// Should require provider
	state = "12345678901234567890123456789012:99"
	c.Value = "12345678901234567890123456789012"
	valid, _, _, err = ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state format", err.Error())
	}

	// Should allow valid state
	state = "12345678901234567890123456789012:p99:url123"
	c.Value = "12345678901234567890123456789012"
	valid, provider, redirect, err := ValidateCSRFCookie(c, state)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("p99", provider, "valid request should return correct provider")
	assert.Equal("url123", redirect, "valid request should return correct redirect")
}

func TestValidateState(t *testing.T) {
	assert := assert.New(t)

	// Should require valid state
	state := "12345678901234567890123456789012:"
	err := ValidateState(state)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state value", err.Error())
	}
	// Should pass this state
	state = "12345678901234567890123456789012:p99:url123"
	err = ValidateState(state)
	assert.Nil(err, "valid request should not return an error")
}

func TestMakeState(t *testing.T) {
	assert := assert.New(t)

	r := httptest.NewRequest("GET", "http://example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "http")

	// Test with google
	p := provider.Google{}
	state := MakeState(r, &p, "nonce")
	assert.Equal("nonce:google:http://example.com/hello", state)

	// Test with OIDC
	p2 := provider.OIDC{}
	state = MakeState(r, &p2, "nonce")
	assert.Equal("nonce:oidc:http://example.com/hello", state)

	// Test with Generic OAuth
	p3 := provider.GenericOAuth{}
	state = MakeState(r, &p3, "nonce")
	assert.Equal("nonce:generic-oauth:http://example.com/hello", state)
}

func TestAuthNonce(t *testing.T) {
	assert := assert.New(t)
	err, nonce1 := Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce1, 32, "length should be 32 chars")

	err, nonce2 := Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce2, 32, "length should be 32 chars")

	assert.NotEqual(nonce1, nonce2, "nonce should not be equal")
}

func TestAuthCookieDomainMatch(t *testing.T) {
	assert := assert.New(t)
	cd := NewCookieDomain("example.com")

	// Exact should match
	assert.True(cd.Match("example.com"), "exact domain should match")

	// Subdomain should match
	assert.True(cd.Match("test.example.com"), "subdomain should match")
	assert.True(cd.Match("twolevels.test.example.com"), "subdomain should match")
	assert.True(cd.Match("many.many.levels.test.example.com"), "subdomain should match")

	// Derived domain should not match
	assert.False(cd.Match("testexample.com"), "derived domain should not match")

	// Other domain should not match
	assert.False(cd.Match("test.com"), "other domain should not match")
}

func TestAuthCookieDomains(t *testing.T) {
	assert := assert.New(t)
	cds := CookieDomains{}

	err := cds.UnmarshalFlag("one.com,two.org")
	assert.Nil(err)
	expected := CookieDomains{
		CookieDomain{
			Domain:       "one.com",
			DomainLen:    7,
			SubDomain:    ".one.com",
			SubDomainLen: 8,
		},
		CookieDomain{
			Domain:       "two.org",
			DomainLen:    7,
			SubDomain:    ".two.org",
			SubDomainLen: 8,
		},
	}
	assert.Equal(expected, cds)

	marshal, err := cds.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one.com,two.org", marshal)
}
