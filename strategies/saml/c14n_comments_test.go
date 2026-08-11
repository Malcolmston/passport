package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This file exercises the "#WithComments" canonicalization algorithms end to
// end, through verifySignature rather than through canonicalize alone.
//
// The property under test is the one that makes these algorithms different in
// kind rather than in detail: with a comments-retaining canonicalization, a
// comment is signed material, so editing one invalidates the signature. That is
// correct and intended. With a comments-omitting canonicalization the same edit
// must remain invisible — the two must not contaminate each other.

// commentDoc is the document the round trip signs. The ds:Signature replaces
// %s, and it sits inside the element its reference names, as verifySignature
// requires. Both comments are load-bearing: signedInfoComment is covered by the
// SignatureValue via the CanonicalizationMethod, and referenceComment is
// covered by the DigestValue via the reference transform chain.
const (
	signedInfoComment = "<!-- signed info comment -->"
	referenceComment  = "<!-- reference comment -->"
	commentDocFmt     = `<r xmlns="urn:t" ID="R1">` + referenceComment + `payload%s</r>`
)

// signCommentDoc builds a signed commentDoc whose ds:CanonicalizationMethod is
// c14nAlg and whose reference transform chain is refAlg.
func signCommentDoc(t *testing.T, idp *testIdP, c14nAlg, refAlg string) string {
	t.Helper()

	refOpts, err := c14nModeFor(refAlg)
	if err != nil {
		t.Fatalf("c14nModeFor(%q): %v", refAlg, err)
	}
	// The signature is not in the tree yet, which is exactly the node set the
	// enveloped-signature transform produces once it is.
	unsigned := mustParse(t, fmt.Sprintf(commentDocFmt, ""))
	target, err := resolveIDRef(unsigned, "R1")
	if err != nil {
		t.Fatalf("resolveIDRef: %v", err)
	}
	canon, err := canonicalize(target, refOpts)
	if err != nil {
		t.Fatalf("canonicalizing reference: %v", err)
	}
	digest := sha256.Sum256(canon)

	sigXML := `<ds:Signature xmlns:ds="` + nsDSig + `">` +
		`<ds:SignedInfo>` + signedInfoComment +
		`<ds:CanonicalizationMethod Algorithm="` + c14nAlg + `"/>` +
		`<ds:SignatureMethod Algorithm="` + algRSASHA256 + `"/>` +
		`<ds:Reference URI="#R1">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="` + AlgEnvelopedSignature + `"/>` +
		`<ds:Transform Algorithm="` + refAlg + `"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algDigestSHA256 + `"/>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue>` +
		`</ds:Reference>` +
		`</ds:SignedInfo>` +
		`<ds:SignatureValue></ds:SignatureValue>` +
		`</ds:Signature>`

	doc := fmt.Sprintf(commentDocFmt, sigXML)

	siOpts, err := c14nModeFor(c14nAlg)
	if err != nil {
		t.Fatalf("c14nModeFor(%q): %v", c14nAlg, err)
	}
	signedInfo := findFirst(t, mustParse(t, doc), "SignedInfo")
	canonSI, err := canonicalize(signedInfo, siOpts)
	if err != nil {
		t.Fatalf("canonicalizing SignedInfo: %v", err)
	}
	h := sha256.Sum256(canonSI)
	key, ok := idp.key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("test IdP key is %T, want *rsa.PrivateKey", idp.key)
	}
	value, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return strings.Replace(doc,
		"<ds:SignatureValue></ds:SignatureValue>",
		"<ds:SignatureValue>"+base64.StdEncoding.EncodeToString(value)+"</ds:SignatureValue>", 1)
}

// verifyCommentDoc runs a finished document through verifySignature.
func verifyCommentDoc(t *testing.T, idp *testIdP, doc string) error {
	t.Helper()
	root := mustParse(t, doc)
	sig := findFirst(t, root, "Signature")
	_, err := verifySignature(root, sig, []*x509.Certificate{idp.cert}, false)
	return err
}

// TestVerifySignatureWithCommentsCanonicalization signs and verifies a document
// under each canonicalization algorithm, then edits a comment inside
// ds:SignedInfo and re-verifies.
//
// The comment sits inside the material the SignatureValue covers, so a
// "#WithComments" CanonicalizationMethod must notice the edit and every
// comments-omitting one must not.
func TestVerifySignatureWithCommentsCanonicalization(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	tests := []struct {
		alg               string
		commentsAreSigned bool
	}{
		{AlgC14N, false},
		{AlgC14N11, false},
		{AlgC14NExclusive, false},
		{AlgC14NWithComments, true},
		{AlgC14N11WithComments, true},
		{AlgC14NExclusiveWithComments, true},
	}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			// The reference transform chain stays on exclusive c14n: it is
			// the CanonicalizationMethod that is under test here.
			doc := signCommentDoc(t, idp, tc.alg, AlgC14NExclusive)
			if err := verifyCommentDoc(t, idp, doc); err != nil {
				t.Fatalf("verifySignature: %v", err)
			}

			tampered := strings.Replace(doc, signedInfoComment, "<!-- edited -->", 1)
			if tampered == doc {
				t.Fatal("the SignedInfo comment was not in the document")
			}
			err := verifyCommentDoc(t, idp, tampered)
			switch {
			case tc.commentsAreSigned && err == nil:
				t.Error("editing a comment left a #WithComments signature valid")
			case tc.commentsAreSigned && !errors.Is(err, ErrSignatureInvalid):
				t.Errorf("err = %v, want ErrSignatureInvalid", err)
			case !tc.commentsAreSigned && err != nil:
				t.Errorf("editing a comment broke a comment-free signature: %v", err)
			}
		})
	}
}

// TestVerifySignatureCommentsInReferenceNodeSet is the same experiment one
// level down, on the DigestValue rather than the SignatureValue.
//
// The reference transform chain is what selects the canonicalization for the
// signed element, so a comment inside that element is covered only when the
// chain names a "#WithComments" algorithm.
func TestVerifySignatureCommentsInReferenceNodeSet(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	// referenceTransforms in xmldsig.go allow-lists only the comment-free
	// canonicalization URIs, so a "#WithComments" reference transform is
	// rejected before any digest is computed. Both halves are asserted: the
	// comment-free chain round-trips and ignores comment edits, and the
	// with-comments chain is refused rather than silently downgraded.
	doc := signCommentDoc(t, idp, AlgC14NExclusive, AlgC14NExclusive)
	if err := verifyCommentDoc(t, idp, doc); err != nil {
		t.Fatalf("verifySignature: %v", err)
	}
	tampered := strings.Replace(doc, referenceComment, "<!-- edited -->", 1)
	if tampered == doc {
		t.Fatal("the reference comment was not in the document")
	}
	if err := verifyCommentDoc(t, idp, tampered); err != nil {
		t.Errorf("editing a comment broke a comment-free reference digest: %v", err)
	}

	withComments := signCommentDoc(t, idp, AlgC14NExclusive, AlgC14NExclusiveWithComments)
	err := verifyCommentDoc(t, idp, withComments)
	if err == nil {
		t.Fatal("a #WithComments reference transform was accepted; if that is now intended, this test should assert the round trip instead")
	}
	if !strings.Contains(err.Error(), "is not allowed") {
		t.Errorf("err = %v, want the transform allow-list rejection", err)
	}
}
