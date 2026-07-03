// Package cas implements a client for the CAS (Central Authentication Service)
// single sign-on protocol.
//
// With no ?ticket in the request it redirects the user agent to the CAS login
// page (casBaseURL/login?service=<service>). When CAS redirects back with a
// ?ticket, the strategy validates it against casBaseURL/serviceValidate and,
// on success, reports the authenticated username.
//
// SIMPLIFIED: this implements the CAS 2.0 serviceValidate XML flow and parses
// the <cas:user> element from a success response. It does not implement proxy
// tickets, attribute release beyond a flat map, or SAML validation.
package cas

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/malcolmston/passport"
)

// Config configures the CAS strategy.
type Config struct {
	// BaseURL is the CAS server base, e.g. "https://cas.example.com/cas".
	BaseURL string
	// Service is this application's service URL registered with CAS; CAS
	// redirects back here with a ticket.
	Service string
	// HTTPClient is used for ticket validation. When nil, http.DefaultClient
	// is used. Injectable for tests.
	HTTPClient *http.Client
}

// VerifyFunc maps a validated CAS username (and any released attributes) to an
// application user. When nil, the username string is used as the user.
type VerifyFunc func(username string, attributes map[string]string) (user any, err error)

// Strategy authenticates against a CAS server.
type Strategy struct {
	cfg    Config
	verify VerifyFunc
}

// New creates a CAS Strategy. verify may be nil.
func New(cfg Config, verify VerifyFunc) *Strategy {
	return &Strategy{cfg: cfg, verify: verify}
}

// Name returns "cas".
func (s *Strategy) Name() string { return "cas" }

func (s *Strategy) httpClient() *http.Client {
	if s.cfg.HTTPClient != nil {
		return s.cfg.HTTPClient
	}
	return http.DefaultClient
}

// LoginURL is the CAS login redirect target.
func (s *Strategy) LoginURL() string {
	v := url.Values{}
	v.Set("service", s.cfg.Service)
	return strings.TrimRight(s.cfg.BaseURL, "/") + "/login?" + v.Encode()
}

// serviceResponse models the CAS 2.0 serviceValidate XML reply.
type serviceResponse struct {
	XMLName               xml.Name `xml:"serviceResponse"`
	AuthenticationSuccess *struct {
		User       string `xml:"user"`
		Attributes struct {
			Inner []byte `xml:",innerxml"`
		} `xml:"attributes"`
	} `xml:"authenticationSuccess"`
	AuthenticationFailure *struct {
		Code string `xml:"code,attr"`
		Text string `xml:",chardata"`
	} `xml:"authenticationFailure"`
}

// Validate calls serviceValidate and returns the authenticated username and any
// released attributes.
func (s *Strategy) Validate(ctx context.Context, ticket string) (string, map[string]string, error) {
	v := url.Values{}
	v.Set("service", s.cfg.Service)
	v.Set("ticket", ticket)
	endpoint := strings.TrimRight(s.cfg.BaseURL, "/") + "/serviceValidate?" + v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("cas: serviceValidate returned %d", resp.StatusCode)
	}

	var sr serviceResponse
	if err := xml.Unmarshal(body, &sr); err != nil {
		return "", nil, fmt.Errorf("cas: parsing serviceValidate response: %w", err)
	}
	if sr.AuthenticationSuccess == nil || sr.AuthenticationSuccess.User == "" {
		reason := "ticket validation failed"
		if sr.AuthenticationFailure != nil {
			reason = strings.TrimSpace(sr.AuthenticationFailure.Text)
		}
		return "", nil, fmt.Errorf("cas: %s", reason)
	}
	attrs := parseAttributes(sr.AuthenticationSuccess.Attributes.Inner)
	return sr.AuthenticationSuccess.User, attrs, nil
}

// parseAttributes extracts the flat child elements of <cas:attributes> into a
// map of tag local-name to text.
func parseAttributes(inner []byte) map[string]string {
	attrs := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(string(inner)))
	var cur string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			cur = t.Name.Local
		case xml.CharData:
			if cur != "" {
				text := strings.TrimSpace(string(t))
				if text != "" {
					attrs[cur] = text
				}
			}
		case xml.EndElement:
			cur = ""
		}
	}
	return attrs
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		c.Redirect(s.LoginURL(), http.StatusFound)
		return
	}

	username, attrs, err := s.Validate(r.Context(), ticket)
	if err != nil {
		c.Fail("invalid_ticket", http.StatusUnauthorized)
		return
	}

	if s.verify != nil {
		user, err := s.verify(username, attrs)
		if err != nil {
			c.Error(err)
			return
		}
		if user == nil {
			c.Fail("", http.StatusUnauthorized)
			return
		}
		c.Success(user)
		return
	}
	c.Success(username)
}
