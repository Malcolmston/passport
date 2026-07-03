package clientcert

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(cert *x509.Certificate) (any, error) {
	if cert.Subject.CommonName == "alice" {
		return cert.Subject.CommonName, nil
	}
	return nil, ErrRejected
}

func requestWithCert(cn string) *passport.Context {
	r := httptest.NewRequest("GET", "/", nil)
	if cn != "" {
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: cn}},
			},
		}
	}
	c := &passport.Context{}
	New(Options{Verify: verify}).Authenticate(c, r)
	return c
}

func TestValidCert(t *testing.T) {
	c := requestWithCert("alice")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestRejectedCert(t *testing.T) {
	c := requestWithCert("bob")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestNoTLS(t *testing.T) {
	c := requestWithCert("")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestNoPeerCerts(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	c := &passport.Context{}
	New(Options{Verify: verify}).Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Verify: verify}).Name() != "client-cert" {
		t.Fatal("name")
	}
}
