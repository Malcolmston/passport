package saml

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Canonicalization algorithm identifiers understood by this package.
const (
	// AlgC14N is Canonical XML 1.0 (omitting comments).
	AlgC14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	// AlgC14NWithComments is Canonical XML 1.0 retaining comments.
	AlgC14NWithComments = AlgC14N + "#WithComments"
	// AlgC14N11 is Canonical XML 1.1 (omitting comments).
	AlgC14N11 = "http://www.w3.org/2006/12/xml-c14n11"
	// AlgC14N11WithComments is Canonical XML 1.1 retaining comments.
	AlgC14N11WithComments = AlgC14N11 + "#WithComments"
	// AlgC14NExclusive is Exclusive XML Canonicalization 1.0 (omitting
	// comments). This is what virtually every SAML identity provider uses.
	AlgC14NExclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"
	// AlgC14NExclusiveWithComments is Exclusive XML Canonicalization 1.0
	// retaining comments.
	AlgC14NExclusiveWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	// AlgEnvelopedSignature is the enveloped-signature transform.
	AlgEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// c14nOptions describes one canonicalization run.
type c14nOptions struct {
	// exclusive selects exclusive canonicalization instead of C14N 1.0/1.1.
	exclusive bool
	// v11 selects Canonical XML 1.1 instead of 1.0. It is meaningless when
	// exclusive is set. The two versions differ only in how an apex element
	// of a document subset inherits attributes in the xml namespace: 1.0
	// inherits every one of them verbatim, while 1.1 inherits only the
	// "simple inheritable" ones (xml:lang and xml:space), leaves xml:id
	// alone entirely, and computes xml:base by resolving the values on the
	// omitted ancestors against one another.
	v11 bool
	// withComments selects a "#WithComments" variant, in which comment nodes
	// are part of the canonical form — and therefore part of what a
	// signature covers.
	withComments bool
	// inclusivePrefixes is the exc-c14n InclusiveNamespaces PrefixList.
	inclusivePrefixes []string
	// omit, when non-nil, is a subtree removed from the node set. It carries
	// the enveloped-signature transform.
	omit *xnode
}

// c14nModeFor maps a canonicalization algorithm URI onto c14nOptions. An
// algorithm this package does not implement is rejected rather than
// approximated: canonicalizing under the wrong rules would either fail to
// interoperate or, far worse, let two different documents canonicalize to the
// same bytes.
func c14nModeFor(alg string) (c14nOptions, error) {
	switch alg {
	case AlgC14NExclusive:
		return c14nOptions{exclusive: true}, nil
	case AlgC14NExclusiveWithComments:
		return c14nOptions{exclusive: true, withComments: true}, nil
	case AlgC14N:
		return c14nOptions{}, nil
	case AlgC14NWithComments:
		return c14nOptions{withComments: true}, nil
	case AlgC14N11:
		return c14nOptions{v11: true}, nil
	case AlgC14N11WithComments:
		return c14nOptions{v11: true, withComments: true}, nil
	default:
		return c14nOptions{}, fmt.Errorf("saml: unsupported canonicalization algorithm %q", alg)
	}
}

// canonicalize serializes the subtree rooted at apex according to o. The result
// is the exact byte sequence that the digest or signature is computed over.
func canonicalize(apex *xnode, o c14nOptions) ([]byte, error) {
	return canonicalizeNodes([]*xnode{apex}, o)
}

// canonicalizeNodes serializes a node set whose top level is the ordered slice
// nodes: exactly one element — the document element of the node set — possibly
// surrounded by comment and processing-instruction siblings.
//
// The sibling case exists to implement one rule that canonicalize's single-node
// entry point can never reach. C14N 1.0 §2.3 and C14N 1.1 §2.3 both say of a
// comment (and, identically, of a PI):
//
//	a trailing #xA is rendered after the closing comment symbol for comment
//	children of the root node with a lesser document order than the document
//	element, and a leading #xA is rendered before the opening comment symbol
//	of comment children of the root node with a greater document order than
//	the document element
//
// so a prolog comment is followed by a newline and an epilog comment is
// preceded by one. A comment dropped because the algorithm omits comments
// contributes no newline either, because it contributes nothing at all.
//
// This package's own verification path never takes that branch: every
// ds:Reference it accepts is a bare-name "#ID" XPointer, whose node set is one
// element's subtree, and ds:SignedInfo is likewise a single element. The
// parser correspondingly discards markup outside the document element.
func canonicalizeNodes(nodes []*xnode, o c14nOptions) ([]byte, error) {
	c := &c14ner{opts: o, inclusive: map[string]bool{}}
	for _, p := range o.inclusivePrefixes {
		if p == "#default" {
			c.inclusive[""] = true
		} else {
			c.inclusive[p] = true
		}
	}

	docElem := -1
	for i, n := range nodes {
		if n.kind == nodeElement {
			if docElem >= 0 {
				return nil, errors.New("saml: node set has more than one document element")
			}
			docElem = i
		}
	}
	if docElem < 0 {
		return nil, errors.New("saml: node set has no document element")
	}

	// The initial "rendered" context binds the xml prefix, which every element
	// carries implicitly. Both algorithms suppress a binding the nearest
	// output ancestor already rendered, so seeding it here is what keeps
	// xmlns:xml out of the canonical form — the behaviour every C14N
	// implementation has. Without the seed, exclusive c14n renders one on the
	// first element whose only use of the prefix is an attribute such as
	// xml:lang or xml:base. A document that rebound the prefix to some other
	// URI — which XML 1.0 forbids — would still have that rendered, which is
	// the safe direction.
	root := map[string]string{"xml": nsXML}
	for i, n := range nodes {
		if i == docElem {
			if err := c.element(n, root, true); err != nil {
				return nil, err
			}
			continue
		}
		switch n.kind {
		case nodeComment:
			if !o.withComments {
				continue
			}
		case nodePI:
		default:
			return nil, errors.New("saml: only comments and processing instructions may sit outside the document element")
		}
		if i > docElem {
			c.buf.WriteByte('\n')
		}
		if err := c.node(n, root); err != nil {
			return nil, err
		}
		if i < docElem {
			c.buf.WriteByte('\n')
		}
	}
	return c.buf.Bytes(), nil
}

type c14ner struct {
	buf       bytes.Buffer
	opts      c14nOptions
	inclusive map[string]bool
}

func qname(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

func (c *c14ner) node(n *xnode, rendered map[string]string) error {
	switch n.kind {
	case nodeElement:
		return c.element(n, rendered, false)
	case nodeText:
		c.buf.WriteString(escapeText(n.text))
	case nodePI:
		c.buf.WriteString("<?")
		c.buf.WriteString(n.piTarget)
		if n.text != "" {
			c.buf.WriteByte(' ')
			c.buf.WriteString(n.text)
		}
		c.buf.WriteString("?>")
	case nodeComment:
		// Comments are part of the canonical form only for the
		// "#WithComments" algorithms, which makes them signed material:
		// editing a comment then invalidates the signature.
		if c.opts.withComments {
			c.buf.WriteString("<!--")
			c.buf.WriteString(n.text)
			c.buf.WriteString("-->")
		}
	}
	return nil
}

func (c *c14ner) element(n *xnode, rendered map[string]string, apex bool) error {
	name := qname(n.prefix, n.local)

	decls, err := c.namespaceDecls(n, rendered, apex)
	if err != nil {
		return err
	}
	next := rendered
	if len(decls) > 0 {
		next = make(map[string]string, len(rendered)+len(decls))
		for k, v := range rendered {
			next[k] = v
		}
		for _, d := range decls {
			next[d.prefix] = d.uri
		}
	}
	sort.SliceStable(decls, func(i, j int) bool { return decls[i].prefix < decls[j].prefix })

	attrs := append([]xattr(nil), n.attrs...)
	if apex && !c.opts.exclusive {
		// Inclusive c14n document-subset rule: an apex element carries the
		// xml-namespace attributes of its omitted ancestors. Exclusive c14n
		// deliberately does not do this, which is why the branch is skipped.
		var err error
		if attrs, err = apexXMLAttrs(n, c.opts.v11); err != nil {
			return err
		}
	}
	sort.SliceStable(attrs, func(i, j int) bool {
		if attrs[i].uri != attrs[j].uri {
			return attrs[i].uri < attrs[j].uri
		}
		return attrs[i].local < attrs[j].local
	})

	c.buf.WriteByte('<')
	c.buf.WriteString(name)
	for _, d := range decls {
		if d.prefix == "" {
			c.buf.WriteString(` xmlns="`)
		} else {
			c.buf.WriteString(" xmlns:")
			c.buf.WriteString(d.prefix)
			c.buf.WriteString(`="`)
		}
		c.buf.WriteString(escapeAttr(d.uri))
		c.buf.WriteByte('"')
	}
	for _, a := range attrs {
		c.buf.WriteByte(' ')
		c.buf.WriteString(qname(a.prefix, a.local))
		c.buf.WriteString(`="`)
		c.buf.WriteString(escapeAttr(a.value))
		c.buf.WriteByte('"')
	}
	c.buf.WriteByte('>')
	for _, ch := range n.children {
		if ch == c.opts.omit {
			continue // enveloped-signature transform
		}
		if err := c.node(ch, next); err != nil {
			return err
		}
	}
	c.buf.WriteString("</")
	c.buf.WriteString(name)
	c.buf.WriteByte('>')
	return nil
}

// namespaceDecls computes the namespace declarations rendered on n.
//
// Both algorithms share the same emit rule — render a binding unless the
// nearest output ancestor already rendered the identical binding, and never
// render an undeclaration for a prefix that was never rendered — and differ
// only in which bindings are candidates. C14N 1.0 offers every in-scope
// binding at the apex and each element's own declarations below it; exclusive
// c14n offers only the bindings the element visibly utilizes, plus any listed
// in InclusiveNamespaces.
func (c *c14ner) namespaceDecls(n *xnode, rendered map[string]string, apex bool) ([]xns, error) {
	var candidates []xns
	if c.opts.exclusive {
		used := map[string]bool{n.prefix: true}
		for _, a := range n.attrs {
			if a.prefix != "" {
				used[a.prefix] = true
			}
		}
		for p := range c.inclusive {
			used[p] = true
		}
		prefixes := make([]string, 0, len(used))
		for p := range used {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		for _, p := range prefixes {
			uri, ok := lookupNS(n, p)
			if !ok {
				continue // an InclusiveNamespaces prefix that is not in scope
			}
			candidates = append(candidates, xns{prefix: p, uri: uri})
		}
	} else if apex {
		candidates = inScopeNS(n)
	} else {
		candidates = n.ns
	}

	var out []xns
	for _, d := range candidates {
		prev, ok := rendered[d.prefix]
		if ok && prev == d.uri {
			continue
		}
		if !ok && d.uri == "" {
			continue // xmlns="" with no default namespace to undeclare
		}
		out = append(out, d)
	}
	return out, nil
}

// apexXMLAttrs returns the attribute list of the apex element n of a document
// subset under inclusive canonicalization: n's own attributes, adjusted for the
// xml-namespace attributes of the ancestors that the node set omits.
//
// C14N 1.0 §2.3 states the rule once for the whole xml namespace — the apex is
// output "as if" it carried the nearest in-scope occurrence of every xml:*
// attribute, xml:lang and xml:space being only the examples the text gives. So
// xml:base is inherited verbatim there, with no URI arithmetic whatsoever.
//
// C14N 1.1 §2.4 splits that rule three ways. Only the "simple inheritable"
// attributes — xml:lang and xml:space — are still inherited verbatim; xml:id is
// explicitly left alone ("no processing of these attributes is performed"),
// because copying an ID onto the apex would duplicate it; and xml:base is
// recomputed by joinXMLBase below.
func apexXMLAttrs(n *xnode, v11 bool) ([]xattr, error) {
	out := make([]xattr, 0, len(n.attrs)+2)
	have := map[string]bool{}
	for _, a := range n.attrs {
		if a.uri == nsXML {
			if v11 && a.local == "base" {
				// Held back: joinXMLBase decides whether the fixed-up
				// value replaces it or it survives unchanged.
				have[a.local] = true
				continue
			}
			have[a.local] = true
		}
		out = append(out, a)
	}

	inheritable := func(local string) bool {
		if !v11 {
			return true
		}
		return local == "lang" || local == "space"
	}
	for e := n.parent; e != nil; e = e.parent {
		if e.kind != nodeElement {
			continue
		}
		for _, a := range e.attrs {
			if a.uri != nsXML || have[a.local] || !inheritable(a.local) {
				continue
			}
			have[a.local] = true
			out = append(out, a)
		}
	}

	if v11 {
		base, ok, err := joinXMLBase(n)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, base)
		}
	}
	return out, nil
}

// xmlAttr returns the value of an attribute in the xml namespace.
func xmlAttr(n *xnode, local string) (string, bool) {
	for _, a := range n.attrs {
		if a.uri == nsXML && a.local == local {
			return a.value, true
		}
	}
	return "", false
}

// joinXMLBase performs the Canonical XML 1.1 xml:base fix-up for the apex
// element n of a document subset, reporting whether an xml:base attribute is
// rendered at all.
//
// C14N 1.1 §2.4 defines it as follows. E is the apex; E1...En are its omitted
// ancestor elements in document order; "the fix-up is only performed if at
// least one of E1...En had an xml:base attribute", in which case X1...Xm are
// the xml:base values found on E1...En+1 (E itself being En+1), outermost
// first. The values are then reduced to one by repeatedly applying the
// specification's join-URI-References function, and "the result may also be
// null or empty [...] in which case xml:base MUST NOT be rendered".
//
// When no omitted ancestor carries xml:base there is no fix-up and E's own
// xml:base — if it has one — is an ordinary attribute that has already been
// copied through by apexXMLAttrs.
func joinXMLBase(n *xnode) (xattr, bool, error) {
	var ancestors []string
	for e := n.parent; e != nil; e = e.parent {
		if e.kind != nodeElement {
			continue
		}
		if v, ok := xmlAttr(e, "base"); ok {
			ancestors = append(ancestors, v)
		}
	}
	own, hasOwn := xmlAttr(n, "base")
	if len(ancestors) == 0 {
		if !hasOwn {
			return xattr{}, false, nil
		}
		return xattr{prefix: "xml", local: "base", uri: nsXML, value: own}, true, nil
	}

	// ancestors was collected innermost-first; X1...Xm is outermost-first.
	values := make([]string, 0, len(ancestors)+1)
	for i := len(ancestors) - 1; i >= 0; i-- {
		values = append(values, ancestors[i])
	}
	if hasOwn {
		values = append(values, own)
	}

	joined := values[0]
	for _, ref := range values[1:] {
		var err error
		if joined, err = joinURIRef(joined, ref); err != nil {
			return xattr{}, false, err
		}
	}
	if joined == "" {
		return xattr{}, false, nil
	}
	return xattr{prefix: "xml", local: "base", uri: nsXML, value: joined}, true, nil
}

// joinURIRef resolves the URI reference ref against the base URI base.
//
// C14N 1.1 §2.4 defines join-URI-References as RFC 3986 §5.2 with two changes:
// the reference's fragment is discarded before resolution ("after parsing R set
// R.fragment = null"), and the base is permitted to be a relative reference, in
// which case §5.2.1 and §5.2.4 are amended so that leading "../" segments
// survive and the joined result is itself relative.
//
// The first change is applied here. The second is refused: resolving a relative
// reference against a relative base is not RFC 3986 reference resolution, so
// net/url cannot do it and the amended algorithm the specification sketches is
// stated only by example. Guessing at it would risk canonicalizing two
// different documents to identical bytes, so this case is an explicit error.
//
// A reference that carries a scheme of its own never reaches that restriction:
// RFC 3986 §5.2.2 discards the base entirely for such a reference.
func joinURIRef(base, ref string) (string, error) {
	r, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("saml: xml:base value %q is not a valid URI reference: %w", ref, err)
	}
	r.Fragment, r.RawFragment = "", ""
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("saml: xml:base value %q is not a valid URI reference: %w", base, err)
	}
	if !b.IsAbs() && !r.IsAbs() && r.Host == "" {
		return "", fmt.Errorf("saml: Canonical XML 1.1 xml:base fix-up joining %q onto the relative base %q needs the modified RFC 3986 resolution that this package does not implement", ref, base)
	}
	return b.ResolveReference(r).String(), nil
}

// escapeText applies the canonical-form escaping for character data.
func escapeText(s string) string {
	if !strings.ContainsAny(s, "&<>\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// escapeAttr applies the canonical-form escaping for attribute values.
func escapeAttr(s string) string {
	if !strings.ContainsAny(s, "&<\"\t\n\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
