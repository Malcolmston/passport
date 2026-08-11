package saml

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// StatusSuccess is the only samlp:StatusCode value that is accepted.
const StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// Errors reported by response validation.
var (
	// ErrStatus is returned when the response carries a StatusCode other
	// than Success.
	ErrStatus = errors.New("saml: response status is not Success")
	// ErrConditions is returned when the assertion is outside its validity
	// window or fails an audience, recipient or destination check.
	ErrConditions = errors.New("saml: assertion conditions not met")
	// ErrEncrypted is the umbrella error for encrypted content that could
	// not be processed. Every decryption error in this package wraps it, so
	// errors.Is(err, ErrEncrypted) answers "the response carried encrypted
	// content this strategy would not accept". Encrypted content is always
	// an explicit rejection, never a silent skip.
	ErrEncrypted = errors.New("saml: encrypted content could not be processed")
	// ErrAmbiguousAssertion is returned when a multi-assertion response
	// yields more than one distinct NameID and Options.SelectAssertion is
	// not configured. Guessing which subject logged in is not an option.
	ErrAmbiguousAssertion = errors.New("saml: response contains several assertions with different NameIDs and Options.SelectAssertion is not set")
)

// Assertion is the subject information extracted from a SAML assertion whose
// signature has been verified. Every field is read from inside the signed
// subtree, with the sole exception of Destination, which is an attribute of the
// samlp:Response element and is therefore only covered when the response itself
// is signed (see ResponseSigned).
type Assertion struct {
	// ID is the assertion's ID attribute, used for replay detection.
	ID string
	// Issuer is the text of the assertion's saml:Issuer element.
	Issuer string
	// NameID is the authenticated subject.
	NameID string
	// NameIDFormat is the Format attribute of the NameID, if present.
	NameIDFormat string
	// SessionIndex is the AuthnStatement's SessionIndex, if present. It is
	// what a SAML single-logout request has to quote.
	SessionIndex string
	// Attributes holds the saml:AttributeStatement values, keyed by the
	// attribute Name.
	Attributes map[string][]string
	// NotBefore and NotOnOrAfter are the assertion's Conditions bounds. They
	// are zero when the assertion does not state them.
	NotBefore, NotOnOrAfter time.Time
	// InResponseTo is the SubjectConfirmationData's InResponseTo, empty for
	// IdP-initiated sign-on.
	InResponseTo string
	// ResponseSigned reports whether the verified signature covered the whole
	// samlp:Response rather than just the assertion.
	ResponseSigned bool
	// Encrypted reports that this assertion arrived inside a
	// saml:EncryptedAssertion and was decrypted with an SP key. It says
	// nothing about authenticity — the signature checks do that — only about
	// confidentiality in transit.
	Encrypted bool
	// EncryptedNameID reports that the subject arrived as a
	// saml:EncryptedID rather than a plaintext saml:NameID.
	EncryptedNameID bool
	// Assertions holds every validated assertion in the response, in
	// document order, when Options.AllowMultipleAssertions is set and the
	// response carried more than one. It is nil otherwise, and nil on the
	// entries of the slice. The assertion this field hangs off is itself one
	// of the entries: the one selected to carry the identity.
	Assertions []*Assertion
}

// validateXML runs the whole validation pipeline over a decoded SAMLResponse
// and returns the verified assertion.
func (s *Strategy) validateXML(raw []byte) (*Assertion, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	if len(s.certs) == 0 {
		return nil, ErrNoCertificates
	}
	root, err := parseXML(raw, s.maxDepth)
	if err != nil {
		return nil, err
	}
	if !root.is(nsSAMLProtocol, "Response") {
		return nil, fmt.Errorf("saml: root element is <%s>, expected samlp:Response", root.local)
	}

	// Structural hardening, applied before anything is verified.
	//
	// Every assertion in the document — plaintext or encrypted — must be a
	// direct child of the response, and there must be exactly one unless the
	// caller opted into more. This single rule eliminates the whole XML
	// Signature Wrapping family: an attacker cannot smuggle an extra
	// assertion in anywhere — before or after the real one, nested inside
	// it, or parked in a ds:Object or samlp:Extensions element — and cannot
	// relocate the genuinely signed assertion out of the way.
	var assertions, encryptedAssertions []*xnode
	var structErr error
	fail := func(err error) {
		if structErr == nil {
			structErr = err
		}
	}
	root.walk(func(n *xnode) {
		switch {
		case n.is(nsSAMLAssertion, "Assertion"):
			if n.parent != root {
				fail(errors.New("saml: saml:Assertion is not a direct child of samlp:Response"))
			}
			assertions = append(assertions, n)
		case n.is(nsSAMLAssertion, "EncryptedAssertion"):
			if n.parent != root {
				fail(errors.New("saml: saml:EncryptedAssertion is not a direct child of samlp:Response"))
			}
			encryptedAssertions = append(encryptedAssertions, n)
		}
	})
	hasEncryptedID := checkEncryptedIDPlacement(root, fail)

	// Encrypted content with no key configured is rejected outright, before
	// anything else can turn it into a "no assertion found" that a caller
	// might mistake for a benign response.
	if (len(encryptedAssertions) > 0 || hasEncryptedID) && !s.hasDecryptionKey() {
		return nil, ErrNoDecryptionKey
	}
	if structErr != nil {
		return nil, structErr
	}
	total := len(assertions) + len(encryptedAssertions)
	if total != 1 && !s.allowMultiple {
		return nil, fmt.Errorf("saml: response contains %d assertions, expected exactly 1", total)
	}
	if total == 0 {
		return nil, errors.New("saml: response contains no assertion")
	}

	// Collect every signature in the outer document. Each one must sit at a
	// legal position and each one must verify: a signature that does not
	// verify is never simply ignored in favour of one that does.
	var signatures []*xnode
	root.walk(func(n *xnode) {
		if n.is(nsDSig, "Signature") {
			signatures = append(signatures, n)
		}
	})
	responseSigned := false
	signedAssertions := map[*xnode]bool{}
	for _, sig := range signatures {
		if sig.parent != root && !containsNode(assertions, sig.parent) {
			return nil, errors.New("saml: ds:Signature is not a child of the response or the assertion")
		}
		verified, err := verifySignature(root, sig, s.certs, s.allowSHA1)
		if err != nil {
			return nil, err
		}
		switch {
		case verified.element == root:
			responseSigned = true
		case containsNode(assertions, verified.element):
			signedAssertions[verified.element] = true
		default:
			// Unreachable given the parent check above, but a signature
			// covering anything else must never be treated as coverage.
			return nil, errors.New("saml: signature covers an unexpected element")
		}
	}

	// Status is only integrity-protected when the response itself is signed;
	// it is checked either way, because a non-Success status must never
	// produce a login.
	if err := checkStatus(root); err != nil {
		return nil, err
	}

	// Validate every assertion independently. Nothing short-circuits: a
	// single assertion that is unsigned or fails a condition rejects the
	// whole response, so a valid assertion is never picked out of a document
	// that also carries an invalid one.
	var results []*Assertion
	for _, node := range assertions {
		if !signedAssertions[node] && !responseSigned {
			return nil, ErrNoSignature
		}
		a, err := s.validateAssertion(root, node, responseSigned)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	for _, ea := range encryptedAssertions {
		a, err := s.validateEncryptedAssertion(root, ea, responseSigned)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}

	// The replay cache is only consumed once every assertion has passed, so
	// a response that is going to be rejected does not burn assertion IDs.
	for _, a := range results {
		if err := s.checkReplay(a); err != nil {
			return nil, err
		}
	}
	return s.selectAssertion(results)
}

// containsNode reports whether n is one of the nodes in list.
func containsNode(list []*xnode, n *xnode) bool {
	for _, e := range list {
		if e == n {
			return true
		}
	}
	return false
}

// checkEncryptedIDPlacement rejects a saml:EncryptedID anywhere other than as a
// direct child of a saml:Subject, and reports whether one was found at all.
//
// Pinning the position matters for the same reason the assertion position does:
// an EncryptedID parked somewhere the extraction code does not look is dead
// weight at best, and a decoy for a future reader at worst.
func checkEncryptedIDPlacement(root *xnode, fail func(error)) bool {
	found := false
	root.walk(func(n *xnode) {
		if !n.is(nsSAMLAssertion, "EncryptedID") {
			return
		}
		found = true
		if n.parent == nil || !n.parent.is(nsSAMLAssertion, "Subject") {
			fail(errors.New("saml: saml:EncryptedID is not a direct child of a saml:Subject"))
		}
	})
	return found
}

// validateAssertion extracts and condition-checks one plaintext assertion whose
// signature coverage has already been established.
func (s *Strategy) validateAssertion(root, node *xnode, responseSigned bool) (*Assertion, error) {
	a, err := s.extractAssertion(node)
	if err != nil {
		return nil, err
	}
	a.ResponseSigned = responseSigned
	if err := s.checkConditions(root, node, a, responseSigned); err != nil {
		return nil, err
	}
	return a, nil
}

// validateEncryptedAssertion decrypts a saml:EncryptedAssertion, establishes
// that the identity provider actually vouched for the plaintext, and then runs
// it through exactly the same checks a plaintext assertion gets.
//
// Decryption on its own authenticates nothing: the SP's encryption key is
// public, so any stranger can produce a well-formed EncryptedAssertion naming
// any subject. Exactly two things make a decrypted assertion trustworthy, and
// one of them must hold:
//
//  1. The samlp:Response carries a verified signature. That signature's digest
//     covers the EncryptedAssertion element, ciphertext included, so the
//     identity provider demonstrably chose these exact bytes. Substituting a
//     different ciphertext breaks the response digest.
//
//  2. The decrypted saml:Assertion carries its own ds:Signature, over itself,
//     that verifies against a configured IdP certificate. The plaintext is then
//     self-authenticating and the envelope it arrived in is irrelevant.
//
// With neither, the response is rejected with ErrNoSignature.
func (s *Strategy) validateEncryptedAssertion(root, ea *xnode, responseSigned bool) (*Assertion, error) {
	d, err := s.decryptElement(ea)
	if err != nil {
		return nil, err
	}
	inner, err := parseXML(d.plaintext, s.maxDepth)
	if err != nil {
		return nil, d.mask(err)
	}
	if !inner.is(nsSAMLAssertion, "Assertion") {
		return nil, d.mask(fmt.Errorf("saml: decrypted EncryptedAssertion is <%s>, expected saml:Assertion", inner.local))
	}
	// The plaintext is a document in its own right and gets the same
	// structural rules: no second assertion hiding inside it, no nested
	// encryption, no stray EncryptedID.
	var structErr error
	fail := func(err error) {
		if structErr == nil {
			structErr = err
		}
	}
	inner.walk(func(n *xnode) {
		switch {
		case n.is(nsSAMLAssertion, "Assertion") && n != inner:
			fail(errors.New("saml: decrypted assertion contains a nested saml:Assertion"))
		case n.is(nsSAMLAssertion, "EncryptedAssertion"):
			fail(errors.New("saml: decrypted assertion contains a nested saml:EncryptedAssertion"))
		}
	})
	checkEncryptedIDPlacement(inner, fail)
	if structErr != nil {
		return nil, d.mask(structErr)
	}

	// Every signature inside the plaintext must sit directly under the
	// assertion and must verify; one that does not is a rejection, never a
	// thing to skip past.
	innerSigned := false
	var innerErr error
	inner.walk(func(n *xnode) {
		if innerErr != nil || !n.is(nsDSig, "Signature") {
			return
		}
		if n.parent != inner {
			innerErr = errors.New("saml: ds:Signature inside a decrypted assertion is not a child of the assertion")
			return
		}
		verified, err := verifySignature(inner, n, s.certs, s.allowSHA1)
		if err != nil {
			innerErr = err
			return
		}
		if verified.element != inner {
			innerErr = errors.New("saml: signature inside a decrypted assertion covers an unexpected element")
			return
		}
		innerSigned = true
	})
	if innerErr != nil {
		return nil, d.mask(innerErr)
	}
	if !innerSigned && !responseSigned {
		return nil, d.mask(ErrNoSignature)
	}

	a, err := s.validateAssertion(root, inner, responseSigned)
	if err != nil {
		return nil, d.mask(err)
	}
	a.Encrypted = true
	return a, nil
}

// selectAssertion reduces the validated set to the one assertion that carries
// the identity.
//
// With a single assertion there is nothing to decide. With several, the choice
// has to be unambiguous: assertions that all name the same subject collapse to
// that subject, and anything else needs Options.SelectAssertion. Picking the
// first, or the newest, or the one with the most attributes would let an
// attacker who can get a second assertion into a response steer which subject
// the application sees.
func (s *Strategy) selectAssertion(results []*Assertion) (*Assertion, error) {
	if len(results) == 1 {
		return results[0], nil
	}
	if s.selectFn != nil {
		picked, err := s.selectFn(results)
		if err != nil {
			return nil, err
		}
		if picked == nil {
			return nil, errors.New("saml: Options.SelectAssertion returned no assertion")
		}
		if !containsAssertion(results, picked) {
			return nil, errors.New("saml: Options.SelectAssertion returned an assertion that is not part of the response")
		}
		picked.Assertions = results
		return picked, nil
	}
	for _, a := range results[1:] {
		if a.NameID != results[0].NameID {
			return nil, ErrAmbiguousAssertion
		}
	}
	results[0].Assertions = results
	return results[0], nil
}

func containsAssertion(list []*Assertion, a *Assertion) bool {
	for _, e := range list {
		if e == a {
			return true
		}
	}
	return false
}

func checkStatus(root *xnode) error {
	status, err := root.onlyChild(nsSAMLProtocol, "Status")
	if err != nil {
		return err
	}
	code, err := status.onlyChild(nsSAMLProtocol, "StatusCode")
	if err != nil {
		return err
	}
	value, _ := code.attrValue("", "Value")
	if value != StatusSuccess {
		msg := value
		if m, _ := status.optionalChild(nsSAMLProtocol, "StatusMessage"); m != nil {
			msg += ": " + strings.TrimSpace(m.textContent())
		}
		return fmt.Errorf("%w (%s)", ErrStatus, msg)
	}
	return nil
}

// extractAssertion reads the subject and attributes out of the verified
// assertion. Every lookup below is a *direct child* lookup within the verified
// subtree, so an element planted deeper in the document can never be picked up.
func (s *Strategy) extractAssertion(assertion *xnode) (*Assertion, error) {
	a := &Assertion{}
	var ok bool
	if a.ID, ok = assertion.attrValue("", "ID"); !ok || a.ID == "" {
		return nil, errors.New("saml: assertion has no ID attribute")
	}
	if issuer, err := assertion.optionalChild(nsSAMLAssertion, "Issuer"); err != nil {
		return nil, err
	} else if issuer != nil {
		a.Issuer = strings.TrimSpace(issuer.textContent())
	}

	subject, err := assertion.onlyChild(nsSAMLAssertion, "Subject")
	if err != nil {
		return nil, err
	}
	nameID, encrypted, err := s.subjectNameID(subject)
	if err != nil {
		return nil, err
	}
	a.EncryptedNameID = encrypted
	a.NameID = strings.TrimSpace(nameID.textContent())
	if a.NameID == "" {
		return nil, ErrNoNameID
	}
	a.NameIDFormat, _ = nameID.attrValue("", "Format")

	if scd := subjectConfirmationData(subject); scd != nil {
		a.InResponseTo, _ = scd.attrValue("", "InResponseTo")
	}
	for _, st := range assertion.childElements(nsSAMLAssertion, "AuthnStatement") {
		if v, ok := st.attrValue("", "SessionIndex"); ok {
			a.SessionIndex = v
			break
		}
	}
	if attrs := s.extractAttributes(assertion); len(attrs) > 0 {
		a.Attributes = attrs
	}
	return a, nil
}

// subjectNameID returns the saml:NameID element of a subject, decrypting a
// saml:EncryptedID first when that is how it arrived.
//
// Either form is acceptable but not both, and not two of either: an ambiguous
// subject is a rejected subject. Decrypting here is safe precisely because
// extractAssertion is only ever called on an assertion whose signature has
// already been verified, so the EncryptedID's ciphertext is covered by that
// signature and cannot have been substituted.
func (s *Strategy) subjectNameID(subject *xnode) (nameID *xnode, encrypted bool, err error) {
	plain := subject.childElements(nsSAMLAssertion, "NameID")
	enc := subject.childElements(nsSAMLAssertion, "EncryptedID")
	switch {
	case len(plain)+len(enc) == 0:
		return nil, false, fmt.Errorf("saml: missing <NameID> in <%s>", subject.local)
	case len(plain)+len(enc) > 1:
		return nil, false, fmt.Errorf("saml: %d subject identifiers in <%s>, expected exactly 1", len(plain)+len(enc), subject.local)
	case len(plain) == 1:
		return plain[0], false, nil
	}

	d, err := s.decryptElement(enc[0])
	if err != nil {
		return nil, true, err
	}
	inner, err := parseXML(d.plaintext, s.maxDepth)
	if err != nil {
		return nil, true, d.mask(err)
	}
	if !inner.is(nsSAMLAssertion, "NameID") {
		return nil, true, d.mask(fmt.Errorf("saml: decrypted EncryptedID is <%s>, expected saml:NameID", inner.local))
	}
	return inner, true, nil
}

// extractAttributes gathers saml:Attribute values from the assertion's direct
// AttributeStatement children.
func (s *Strategy) extractAttributes(assertion *xnode) map[string][]string {
	out := map[string][]string{}
	for _, st := range assertion.childElements(nsSAMLAssertion, "AttributeStatement") {
		for _, at := range st.childElements(nsSAMLAssertion, "Attribute") {
			name, ok := at.attrValue("", "Name")
			if !ok || name == "" {
				continue
			}
			for _, v := range at.childElements(nsSAMLAssertion, "AttributeValue") {
				out[name] = append(out[name], strings.TrimSpace(v.textContent()))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// subjectConfirmationData returns the SubjectConfirmationData of the first
// bearer SubjectConfirmation, or nil.
func subjectConfirmationData(subject *xnode) *xnode {
	for _, sc := range subject.childElements(nsSAMLAssertion, "SubjectConfirmation") {
		for _, scd := range sc.childElements(nsSAMLAssertion, "SubjectConfirmationData") {
			return scd
		}
	}
	return nil
}

// checkConditions enforces the validity window, audience, recipient and
// destination restrictions.
func (s *Strategy) checkConditions(root, assertion *xnode, a *Assertion, responseSigned bool) error {
	now := s.now()

	conditions, err := assertion.optionalChild(nsSAMLAssertion, "Conditions")
	if err != nil {
		return err
	}
	if conditions == nil {
		return fmt.Errorf("%w: assertion has no saml:Conditions", ErrConditions)
	}
	if a.NotBefore, a.NotOnOrAfter, err = timeBounds(conditions); err != nil {
		return err
	}
	if err := s.checkWindow("assertion", a.NotBefore, a.NotOnOrAfter, now); err != nil {
		return err
	}

	// Audience.
	restrictions := conditions.childElements(nsSAMLAssertion, "AudienceRestriction")
	if len(restrictions) == 0 {
		return fmt.Errorf("%w: assertion has no AudienceRestriction", ErrConditions)
	}
	if s.audience == "" {
		return errors.New("saml: Options.Audience is not configured, cannot check the assertion audience")
	}
	matched := false
	var offered []string
	for _, r := range restrictions {
		for _, aud := range r.childElements(nsSAMLAssertion, "Audience") {
			v := strings.TrimSpace(aud.textContent())
			offered = append(offered, v)
			if v == s.audience {
				matched = true
			}
		}
	}
	if !matched {
		sort.Strings(offered)
		return fmt.Errorf("%w: audience %q not among %v", ErrConditions, s.audience, offered)
	}

	// Subject confirmation: recipient, its own window, and InResponseTo.
	subject, err := assertion.onlyChild(nsSAMLAssertion, "Subject")
	if err != nil {
		return err
	}
	if scd := subjectConfirmationData(subject); scd != nil {
		nb, noa, err := timeBounds(scd)
		if err != nil {
			return err
		}
		if err := s.checkWindow("subject confirmation", nb, noa, now); err != nil {
			return err
		}
		if recipient, ok := scd.attrValue("", "Recipient"); ok && recipient != "" {
			if err := s.checkACS("Recipient", recipient); err != nil {
				return err
			}
		}
	}

	// Destination is an attribute of the response element.
	if dest, ok := root.attrValue("", "Destination"); ok && dest != "" {
		if err := s.checkACS("Destination", dest); err != nil {
			return err
		}
	}

	if s.validateInResponseTo != nil && !s.validateInResponseTo(a.InResponseTo) {
		return fmt.Errorf("%w: InResponseTo %q was rejected", ErrConditions, a.InResponseTo)
	}
	return nil
}

// checkACS compares a Recipient or Destination against the configured ACS URL.
// When no ACS URL is configured the value cannot be checked at all, which is
// treated as a failure rather than as permission to skip it.
func (s *Strategy) checkACS(what, got string) error {
	if s.acsURL == "" {
		return fmt.Errorf("saml: assertion carries a %s but Options.AssertionConsumerServiceURL is not configured", what)
	}
	if got != s.acsURL {
		return fmt.Errorf("%w: %s %q does not match %q", ErrConditions, what, got, s.acsURL)
	}
	return nil
}

func (s *Strategy) checkWindow(what string, notBefore, notOnOrAfter, now time.Time) error {
	if !notBefore.IsZero() && now.Before(notBefore.Add(-s.skew)) {
		return fmt.Errorf("%w: %s is not valid before %s (now %s)", ErrConditions, what,
			notBefore.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !notOnOrAfter.IsZero() && !now.Before(notOnOrAfter.Add(s.skew)) {
		return fmt.Errorf("%w: %s expired at %s (now %s)", ErrConditions, what,
			notOnOrAfter.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}

// timeBounds parses the NotBefore/NotOnOrAfter attributes of an element.
func timeBounds(n *xnode) (notBefore, notOnOrAfter time.Time, err error) {
	if v, ok := n.attrValue("", "NotBefore"); ok {
		if notBefore, err = parseSAMLTime(v); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if v, ok := n.attrValue("", "NotOnOrAfter"); ok {
		if notOnOrAfter, err = parseSAMLTime(v); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	return notBefore, notOnOrAfter, nil
}

// parseSAMLTime parses an xsd:dateTime as SAML requires it: UTC, RFC 3339.
func parseSAMLTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, fmt.Errorf("saml: malformed timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// checkReplay consumes the assertion ID, rejecting a second use.
func (s *Strategy) checkReplay(a *Assertion) error {
	expires := a.NotOnOrAfter
	if expires.IsZero() {
		expires = s.now().Add(defaultReplayTTL)
	}
	expires = expires.Add(s.skew)
	fresh, err := s.replay.Store(a.ID, expires)
	if err != nil {
		return err
	}
	if !fresh {
		return fmt.Errorf("%w: assertion ID %q", ErrReplay, a.ID)
	}
	return nil
}
