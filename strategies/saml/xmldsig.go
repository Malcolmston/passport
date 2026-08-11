package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Errors reported by signature validation. They are deliberately coarse at the
// package boundary — the strategy never reveals which check failed to the
// remote peer — but are distinguishable by callers using errors.Is.
var (
	// ErrNoCertificates is returned when no IdP certificate is configured.
	// Without one, no response can be trusted, so every response is rejected.
	ErrNoCertificates = errors.New("saml: no IdP certificate configured (Options.IdPCertificates)")
	// ErrNoSignature is returned when the response carries no XML signature.
	ErrNoSignature = errors.New("saml: response is not signed")
	// ErrSignatureInvalid is returned when a signature or digest does not
	// verify against the configured certificates.
	ErrSignatureInvalid = errors.New("saml: XML signature validation failed")
	// ErrWeakAlgorithm is returned when the response uses SHA-1 or MD5 and
	// Options.AllowSHA1 has not been set.
	ErrWeakAlgorithm = errors.New("saml: signature uses a rejected digest algorithm")
	// ErrUntrustedCertificate is returned when the response embeds an X.509
	// certificate that does not match any configured certificate.
	ErrUntrustedCertificate = errors.New("saml: embedded X509Certificate does not match a configured IdP certificate")
)

type sigKind uint8

const (
	sigRSAPKCS1 sigKind = iota
	sigRSAPSS
	sigECDSA
)

type sigAlgorithm struct {
	hash crypto.Hash
	kind sigKind
	weak bool
}

// signatureAlgorithms maps xmldsig SignatureMethod URIs to Go primitives.
// MD5 (and the RIPEMD/other legacy URIs) are absent on purpose: an unknown URI
// is rejected, so omission is the strongest possible form of "not allowed".
var signatureAlgorithms = map[string]sigAlgorithm{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":      {crypto.SHA256, sigRSAPKCS1, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":      {crypto.SHA384, sigRSAPKCS1, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":      {crypto.SHA512, sigRSAPKCS1, false},
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":             {crypto.SHA1, sigRSAPKCS1, true},
	"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": {crypto.SHA256, sigRSAPSS, false},
	"http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": {crypto.SHA384, sigRSAPSS, false},
	"http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": {crypto.SHA512, sigRSAPSS, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":    {crypto.SHA256, sigECDSA, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":    {crypto.SHA384, sigECDSA, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":    {crypto.SHA512, sigECDSA, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":      {crypto.SHA1, sigECDSA, true},
}

// digestAlgorithms maps xmldsig DigestMethod URIs to hashes.
var digestAlgorithms = map[string]sigAlgorithm{
	"http://www.w3.org/2001/04/xmlenc#sha256":       {hash: crypto.SHA256},
	"http://www.w3.org/2001/04/xmldsig-more#sha384": {hash: crypto.SHA384},
	"http://www.w3.org/2001/04/xmlenc#sha512":       {hash: crypto.SHA512},
	"http://www.w3.org/2000/09/xmldsig#sha1":        {hash: crypto.SHA1, weak: true},
}

func newHash(h crypto.Hash) (hashFunc func([]byte) []byte, err error) {
	switch h {
	case crypto.SHA1:
		return func(b []byte) []byte { s := sha1.Sum(b); return s[:] }, nil
	case crypto.SHA256:
		return func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }, nil
	case crypto.SHA384:
		return func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }, nil
	case crypto.SHA512:
		return func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }, nil
	}
	return nil, fmt.Errorf("saml: unsupported hash %v", h)
}

// signedElement is the result of a successful signature verification: the one
// element the signature actually covers. Everything the caller subsequently
// trusts must be read from inside this subtree and nowhere else.
type signedElement struct {
	element   *xnode
	signature *xnode
}

// verifySignature validates the ds:Signature element sig, which must be a child
// of the element its single ds:Reference points at, and returns that element.
//
// The critical property is that this function *finds* the signed element rather
// than being told which one it is. Callers may only read identity data out of
// the returned node's subtree, which is what makes XML Signature Wrapping
// structurally impossible: an attacker-supplied element is never the node this
// returns.
func verifySignature(root, sig *xnode, certs []*x509.Certificate, allowSHA1 bool) (*signedElement, error) {
	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}
	signedInfo, err := sig.onlyChild(nsDSig, "SignedInfo")
	if err != nil {
		return nil, err
	}

	// --- SignedInfo/CanonicalizationMethod -------------------------------
	cm, err := signedInfo.onlyChild(nsDSig, "CanonicalizationMethod")
	if err != nil {
		return nil, err
	}
	cmAlg, _ := cm.attrValue("", "Algorithm")
	siOpts, err := c14nModeFor(cmAlg)
	if err != nil {
		return nil, err
	}
	if siOpts.inclusivePrefixes, err = inclusivePrefixList(cm); err != nil {
		return nil, err
	}

	// --- SignedInfo/SignatureMethod --------------------------------------
	sm, err := signedInfo.onlyChild(nsDSig, "SignatureMethod")
	if err != nil {
		return nil, err
	}
	smAlg, _ := sm.attrValue("", "Algorithm")
	sigAlg, ok := signatureAlgorithms[smAlg]
	if !ok {
		return nil, fmt.Errorf("saml: unsupported signature algorithm %q", smAlg)
	}
	if sigAlg.weak && !allowSHA1 {
		return nil, fmt.Errorf("%w: %s", ErrWeakAlgorithm, smAlg)
	}

	// --- SignedInfo/Reference --------------------------------------------
	refs := signedInfo.childElements(nsDSig, "Reference")
	if len(refs) != 1 {
		return nil, fmt.Errorf("saml: SignedInfo has %d References, expected exactly 1", len(refs))
	}
	ref := refs[0]
	uri, ok := ref.attrValue("", "URI")
	if !ok {
		return nil, errors.New("saml: ds:Reference has no URI attribute")
	}
	if !strings.HasPrefix(uri, "#") || len(uri) < 2 {
		return nil, fmt.Errorf("saml: ds:Reference URI %q is not a same-document ID reference", uri)
	}
	target, err := resolveIDRef(root, uri[1:])
	if err != nil {
		return nil, err
	}
	// The signature must be enveloped in the element it covers. Without this
	// the signature could sit anywhere in the document while pointing at an
	// element the attacker chose to keep intact.
	if sig.parent != target {
		return nil, errors.New("saml: ds:Signature is not a child of the element it references")
	}

	// --- Reference/Transforms --------------------------------------------
	refOpts, err := referenceTransforms(ref)
	if err != nil {
		return nil, err
	}
	refOpts.omit = sig

	// --- Reference digest -------------------------------------------------
	dm, err := ref.onlyChild(nsDSig, "DigestMethod")
	if err != nil {
		return nil, err
	}
	dmAlg, _ := dm.attrValue("", "Algorithm")
	digAlg, ok := digestAlgorithms[dmAlg]
	if !ok {
		return nil, fmt.Errorf("saml: unsupported digest algorithm %q", dmAlg)
	}
	if digAlg.weak && !allowSHA1 {
		return nil, fmt.Errorf("%w: %s", ErrWeakAlgorithm, dmAlg)
	}
	dvNode, err := ref.onlyChild(nsDSig, "DigestValue")
	if err != nil {
		return nil, err
	}
	want, err := decodeXMLBase64(dvNode.textContent())
	if err != nil {
		return nil, fmt.Errorf("saml: malformed DigestValue: %w", err)
	}
	canonical, err := canonicalize(target, refOpts)
	if err != nil {
		return nil, err
	}
	digestFn, err := newHash(digAlg.hash)
	if err != nil {
		return nil, err
	}
	if got := digestFn(canonical); subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, fmt.Errorf("%w: reference digest mismatch", ErrSignatureInvalid)
	}

	// --- SignatureValue over SignedInfo -----------------------------------
	svNode, err := sig.onlyChild(nsDSig, "SignatureValue")
	if err != nil {
		return nil, err
	}
	signature, err := decodeXMLBase64(svNode.textContent())
	if err != nil {
		return nil, fmt.Errorf("saml: malformed SignatureValue: %w", err)
	}
	canonicalSI, err := canonicalize(signedInfo, siOpts)
	if err != nil {
		return nil, err
	}
	hashFn, err := newHash(sigAlg.hash)
	if err != nil {
		return nil, err
	}
	digest := hashFn(canonicalSI)

	keys, err := trustedKeys(sig, certs)
	if err != nil {
		return nil, err
	}
	verified := false
	for _, key := range keys {
		if verifyRaw(key, sigAlg, digest, signature) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrSignatureInvalid
	}
	return &signedElement{element: target, signature: sig}, nil
}

// inclusivePrefixList reads an exc-c14n InclusiveNamespaces PrefixList from a
// CanonicalizationMethod or Transform element.
func inclusivePrefixList(n *xnode) ([]string, error) {
	in, err := n.optionalChild(nsExcC14N, "InclusiveNamespaces")
	if err != nil || in == nil {
		return nil, err
	}
	list, _ := in.attrValue("", "PrefixList")
	return strings.Fields(list), nil
}

// referenceTransforms validates the transform chain of a ds:Reference.
//
// Only the enveloped-signature transform and a canonicalization transform are
// accepted. XPath and XSLT transforms in particular are refused: they are a
// remote code-execution and denial-of-service surface, and no SAML identity
// provider needs them.
func referenceTransforms(ref *xnode) (c14nOptions, error) {
	transforms, err := ref.optionalChild(nsDSig, "Transforms")
	if err != nil {
		return c14nOptions{}, err
	}
	// With no explicit canonicalization transform the xmldsig default,
	// Canonical XML 1.0, applies.
	opts := c14nOptions{}
	if transforms == nil {
		return c14nOptions{}, errors.New("saml: ds:Reference has no enveloped-signature transform")
	}
	enveloped := false
	sawC14N := false
	list := transforms.childElements(nsDSig, "Transform")
	if len(list) == 0 {
		return c14nOptions{}, errors.New("saml: ds:Transforms is empty")
	}
	for _, t := range list {
		alg, _ := t.attrValue("", "Algorithm")
		switch alg {
		case AlgEnvelopedSignature:
			if enveloped {
				return c14nOptions{}, errors.New("saml: duplicate enveloped-signature transform")
			}
			enveloped = true
		case AlgC14N, AlgC14N11, AlgC14NExclusive:
			if sawC14N {
				return c14nOptions{}, errors.New("saml: more than one canonicalization transform")
			}
			sawC14N = true
			if opts, err = c14nModeFor(alg); err != nil {
				return c14nOptions{}, err
			}
			if opts.inclusivePrefixes, err = inclusivePrefixList(t); err != nil {
				return c14nOptions{}, err
			}
		default:
			return c14nOptions{}, fmt.Errorf("saml: transform %q is not allowed", alg)
		}
	}
	if !enveloped {
		return c14nOptions{}, errors.New("saml: ds:Reference has no enveloped-signature transform")
	}
	return opts, nil
}

// resolveIDRef finds the single element in the document whose ID attribute
// equals id. Zero matches, or more than one, is an error: a duplicated ID is
// the oldest signature-wrapping trick there is.
func resolveIDRef(root *xnode, id string) (*xnode, error) {
	var found []*xnode
	root.walk(func(n *xnode) {
		for _, name := range [...]string{"ID", "Id", "id"} {
			if v, ok := n.attrValue("", name); ok && v == id {
				found = append(found, n)
				return
			}
		}
	})
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("saml: ds:Reference URI #%s does not resolve to any element", id)
	default:
		return nil, fmt.Errorf("saml: ds:Reference URI #%s resolves to %d elements", id, len(found))
	}
}

// trustedKeys returns the public keys the signature may be verified against.
//
// An embedded ds:X509Certificate is never trusted on its own — trusting it is
// the entire attack. It is only used to select which *configured* certificate
// to verify against, and must match one byte for byte.
func trustedKeys(sig *xnode, certs []*x509.Certificate) ([]crypto.PublicKey, error) {
	embedded := findEmbeddedCerts(sig)
	if len(embedded) == 0 {
		keys := make([]crypto.PublicKey, 0, len(certs))
		for _, c := range certs {
			keys = append(keys, c.PublicKey)
		}
		return keys, nil
	}
	var keys []crypto.PublicKey
	for _, der := range embedded {
		for _, c := range certs {
			if subtle.ConstantTimeCompare(der, c.Raw) == 1 {
				keys = append(keys, c.PublicKey)
			}
		}
	}
	if len(keys) == 0 {
		return nil, ErrUntrustedCertificate
	}
	return keys, nil
}

// findEmbeddedCerts collects the DER bytes of every ds:X509Certificate inside
// the signature's KeyInfo.
func findEmbeddedCerts(sig *xnode) [][]byte {
	var out [][]byte
	for _, ki := range sig.childElements(nsDSig, "KeyInfo") {
		ki.walk(func(n *xnode) {
			if !n.is(nsDSig, "X509Certificate") {
				return
			}
			if der, err := decodeXMLBase64(n.textContent()); err == nil && len(der) > 0 {
				out = append(out, der)
			}
		})
	}
	return out
}

// verifyRaw checks a signature value against a pre-computed digest.
func verifyRaw(key crypto.PublicKey, alg sigAlgorithm, digest, signature []byte) error {
	switch alg.kind {
	case sigRSAPKCS1:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrSignatureInvalid
		}
		return rsa.VerifyPKCS1v15(pub, alg.hash, digest, signature)
	case sigRSAPSS:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrSignatureInvalid
		}
		return rsa.VerifyPSS(pub, alg.hash, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       alg.hash,
		})
	case sigECDSA:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrSignatureInvalid
		}
		// XMLDSig encodes ECDSA signatures as the fixed-width concatenation
		// r || s, not as the ASN.1 sequence crypto/ecdsa produces.
		if len(signature) == 0 || len(signature)%2 != 0 {
			return ErrSignatureInvalid
		}
		half := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:half])
		s := new(big.Int).SetBytes(signature[half:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return ErrSignatureInvalid
		}
		return nil
	}
	return ErrSignatureInvalid
}

// decodeXMLBase64 decodes base64 text taken from an XML element, ignoring the
// whitespace identity providers routinely wrap it in.
func decodeXMLBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
	if s == "" {
		return nil, errors.New("saml: empty base64 value")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
