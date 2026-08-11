package saml

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file contains a small, deliberately strict XML parser.
//
// Go's encoding/xml cannot be used for XML Digital Signature processing: it
// discards attribute order, rewrites namespace prefixes, drops namespace
// declarations that it considers redundant and does not preserve the exact
// character data of a node. Canonicalizing a tree that came out of
// encoding/xml therefore produces bytes that differ from what the identity
// provider signed. The parser below keeps everything canonicalization needs —
// prefixes, declaration order, attribute order, raw text — and refuses to
// parse anything it does not fully understand, so an unsupported construct is
// always a rejection rather than a silent misinterpretation.

// XML namespace URIs used throughout the package.
const (
	nsXML           = "http://www.w3.org/XML/1998/namespace"
	nsDSig          = "http://www.w3.org/2000/09/xmldsig#"
	nsExcC14N       = "http://www.w3.org/2001/10/xml-exc-c14n#"
	nsSAMLAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsSAMLProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// Parser limits. Both are configurable through Options.
const (
	defaultMaxResponseBytes = 5 << 20 // 5 MiB of decoded XML
	defaultMaxDepth         = 100     // element nesting levels
)

// ErrDoctype is returned when the document contains a DOCTYPE or any other
// markup declaration. Rejecting these outright is what makes the package immune
// to XXE and entity-expansion ("billion laughs") attacks.
var ErrDoctype = errors.New("saml: XML DOCTYPE and entity declarations are not allowed")

type nodeKind uint8

const (
	nodeElement nodeKind = iota
	nodeText
	nodePI
	nodeComment
)

// xns is a namespace declaration appearing on an element. A prefix of "" is the
// default namespace; a uri of "" is an undeclaration (xmlns="").
type xns struct {
	prefix string
	uri    string
}

// xattr is a non-namespace attribute, retaining its original prefix so that
// canonicalization can reproduce the exact QName the signer saw.
type xattr struct {
	prefix string
	local  string
	uri    string // resolved namespace URI, "" for unprefixed attributes
	value  string // entity-expanded, whitespace-normalized value
}

// xnode is a node in the parsed document.
type xnode struct {
	kind     nodeKind
	parent   *xnode
	children []*xnode

	// Element fields.
	prefix string
	local  string
	uri    string
	ns     []xns
	attrs  []xattr

	// Text/comment content, or processing-instruction data.
	text     string
	piTarget string
}

// attrValue returns the value of the attribute with the given namespace URI and
// local name. Use uri == "" for an unprefixed attribute.
func (n *xnode) attrValue(uri, local string) (string, bool) {
	for _, a := range n.attrs {
		if a.uri == uri && a.local == local {
			return a.value, true
		}
	}
	return "", false
}

// is reports whether n is an element with the given namespace and local name.
func (n *xnode) is(uri, local string) bool {
	return n.kind == nodeElement && n.uri == uri && n.local == local
}

// childElements returns the direct child elements matching uri/local.
func (n *xnode) childElements(uri, local string) []*xnode {
	var out []*xnode
	for _, c := range n.children {
		if c.is(uri, local) {
			out = append(out, c)
		}
	}
	return out
}

// onlyChild returns the single direct child element matching uri/local. It
// reports an error when there is none or more than one: ambiguity in a security
// decision is always resolved by rejecting the document.
func (n *xnode) onlyChild(uri, local string) (*xnode, error) {
	m := n.childElements(uri, local)
	switch len(m) {
	case 1:
		return m[0], nil
	case 0:
		return nil, fmt.Errorf("saml: missing <%s> in <%s>", local, n.local)
	default:
		return nil, fmt.Errorf("saml: %d <%s> elements in <%s>, expected exactly 1", len(m), local, n.local)
	}
}

// optionalChild behaves like onlyChild but returns (nil, nil) when absent.
func (n *xnode) optionalChild(uri, local string) (*xnode, error) {
	m := n.childElements(uri, local)
	switch len(m) {
	case 0:
		return nil, nil
	case 1:
		return m[0], nil
	default:
		return nil, fmt.Errorf("saml: %d <%s> elements in <%s>, expected at most 1", len(m), local, n.local)
	}
}

// textContent concatenates the character data of the node's descendants.
func (n *xnode) textContent() string {
	var b strings.Builder
	var walk func(*xnode)
	walk = func(e *xnode) {
		if e.kind == nodeText {
			b.WriteString(e.text)
			return
		}
		for _, c := range e.children {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// walk calls fn for every element in the subtree rooted at n, n included.
func (n *xnode) walk(fn func(*xnode)) {
	if n.kind == nodeElement {
		fn(n)
	}
	for _, c := range n.children {
		c.walk(fn)
	}
}

// lookupNS resolves a prefix against the in-scope namespace declarations of n
// and its ancestors.
func lookupNS(n *xnode, prefix string) (string, bool) {
	for e := n; e != nil; e = e.parent {
		if e.kind != nodeElement {
			continue
		}
		for _, d := range e.ns {
			if d.prefix == prefix {
				return d.uri, true
			}
		}
	}
	switch prefix {
	case "xml":
		return nsXML, true
	case "":
		return "", true
	}
	return "", false
}

// inScopeNS returns every namespace binding visible at n, nearest declaration
// winning, in no particular order.
func inScopeNS(n *xnode) []xns {
	seen := map[string]bool{}
	var out []xns
	for e := n; e != nil; e = e.parent {
		if e.kind != nodeElement {
			continue
		}
		for _, d := range e.ns {
			if !seen[d.prefix] {
				seen[d.prefix] = true
				out = append(out, d)
			}
		}
	}
	return out
}

type xparser struct {
	src      []byte
	pos      int
	maxDepth int
}

// parseXML parses src into a tree. It rejects DOCTYPE declarations, unknown
// entity references and documents nested deeper than maxDepth.
func parseXML(src []byte, maxDepth int) (*xnode, error) {
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	if !utf8.Valid(src) {
		return nil, errors.New("saml: response is not valid UTF-8")
	}
	p := &xparser{src: normalizeLineEndings(src), maxDepth: maxDepth}

	var root *xnode
	for {
		p.skipSpace()
		if p.pos >= len(p.src) {
			break
		}
		if p.src[p.pos] != '<' {
			return nil, p.errf("unexpected character %q outside the root element", p.src[p.pos])
		}
		switch {
		case p.hasPrefix("<?"):
			if _, _, err := p.parsePI(); err != nil {
				return nil, err
			}
		case p.hasPrefix("<!--"):
			if _, err := p.parseComment(); err != nil {
				return nil, err
			}
		case p.hasPrefix("<!"):
			return nil, ErrDoctype
		case p.hasPrefix("</"):
			return nil, p.errf("unexpected end tag")
		default:
			if root != nil {
				return nil, p.errf("document has more than one root element")
			}
			n, err := p.parseElement(nil, 1)
			if err != nil {
				return nil, err
			}
			root = n
		}
	}
	if root == nil {
		return nil, errors.New("saml: XML document has no root element")
	}
	return root, nil
}

// normalizeLineEndings applies the XML 1.0 line-end normalization (CRLF and a
// lone CR both become LF) that the infoset — and therefore canonicalization —
// assumes has already happened.
func normalizeLineEndings(b []byte) []byte {
	if !bytes.ContainsRune(b, '\r') {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' {
			if i+1 < len(b) && b[i+1] == '\n' {
				continue
			}
			out = append(out, '\n')
			continue
		}
		out = append(out, b[i])
	}
	return out
}

func (p *xparser) errf(format string, a ...any) error {
	return fmt.Errorf("saml: malformed XML at byte %d: %s", p.pos, fmt.Sprintf(format, a...))
}

func (p *xparser) hasPrefix(s string) bool {
	return bytes.HasPrefix(p.src[p.pos:], []byte(s))
}

func (p *xparser) skipSpace() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n':
			p.pos++
		default:
			return
		}
	}
}

func isNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_' || c == '-' || c == '.' || c == ':' || c >= 0x80:
		return true
	}
	return false
}

func (p *xparser) scanName() (string, error) {
	start := p.pos
	for p.pos < len(p.src) && isNameByte(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", p.errf("expected a name")
	}
	return string(p.src[start:p.pos]), nil
}

func splitQName(name string) (prefix, local string, err error) {
	i := strings.IndexByte(name, ':')
	if i < 0 {
		if name == "" {
			return "", "", errors.New("saml: empty XML name")
		}
		return "", name, nil
	}
	prefix, local = name[:i], name[i+1:]
	if prefix == "" || local == "" || strings.Contains(local, ":") {
		return "", "", fmt.Errorf("saml: malformed qualified name %q", name)
	}
	return prefix, local, nil
}

// parseComment consumes a comment and returns its content.
func (p *xparser) parseComment() (string, error) {
	p.pos += 4 // "<!--"
	end := bytes.Index(p.src[p.pos:], []byte("-->"))
	if end < 0 {
		return "", p.errf("unterminated comment")
	}
	text := string(p.src[p.pos : p.pos+end])
	p.pos += end + 3
	return text, nil
}

// parsePI consumes a processing instruction and returns its target and data.
func (p *xparser) parsePI() (target, data string, err error) {
	p.pos += 2 // "<?"
	target, err = p.scanName()
	if err != nil {
		return "", "", err
	}
	end := bytes.Index(p.src[p.pos:], []byte("?>"))
	if end < 0 {
		return "", "", p.errf("unterminated processing instruction")
	}
	data = strings.TrimLeft(string(p.src[p.pos:p.pos+end]), " \t\n")
	p.pos += end + 2
	return target, data, nil
}

// parseElement parses the element starting at p.pos, which must be '<'.
func (p *xparser) parseElement(parent *xnode, depth int) (*xnode, error) {
	if depth > p.maxDepth {
		return nil, fmt.Errorf("saml: XML nesting deeper than %d elements", p.maxDepth)
	}
	p.pos++ // '<'
	name, err := p.scanName()
	if err != nil {
		return nil, err
	}
	n := &xnode{kind: nodeElement, parent: parent}
	if n.prefix, n.local, err = splitQName(name); err != nil {
		return nil, err
	}

	selfClosing := false
	seen := map[string]bool{}
	for {
		wasSpace := p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t' || p.src[p.pos] == '\n')
		p.skipSpace()
		if p.pos >= len(p.src) {
			return nil, p.errf("unterminated start tag <%s>", name)
		}
		if p.hasPrefix("/>") {
			p.pos += 2
			selfClosing = true
			break
		}
		if p.src[p.pos] == '>' {
			p.pos++
			break
		}
		if !wasSpace {
			return nil, p.errf("missing whitespace before attribute in <%s>", name)
		}
		aname, err := p.scanName()
		if err != nil {
			return nil, err
		}
		if seen[aname] {
			return nil, p.errf("duplicate attribute %q on <%s>", aname, name)
		}
		seen[aname] = true
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != '=' {
			return nil, p.errf("expected '=' after attribute %q", aname)
		}
		p.pos++
		p.skipSpace()
		value, err := p.scanAttrValue()
		if err != nil {
			return nil, err
		}
		switch {
		case aname == "xmlns":
			n.ns = append(n.ns, xns{prefix: "", uri: value})
		case strings.HasPrefix(aname, "xmlns:"):
			prefix := aname[len("xmlns:"):]
			if prefix == "" || strings.Contains(prefix, ":") {
				return nil, p.errf("malformed namespace declaration %q", aname)
			}
			if prefix == "xmlns" {
				return nil, p.errf("the %q prefix may not be redeclared", prefix)
			}
			if value == "" {
				return nil, p.errf("prefixed namespace %q may not be undeclared", aname)
			}
			n.ns = append(n.ns, xns{prefix: prefix, uri: value})
		default:
			prefix, local, err := splitQName(aname)
			if err != nil {
				return nil, err
			}
			n.attrs = append(n.attrs, xattr{prefix: prefix, local: local, value: value})
		}
	}

	// Resolve namespaces now that every declaration on this element is known.
	var ok bool
	if n.uri, ok = lookupNS(n, n.prefix); !ok {
		return nil, p.errf("undeclared namespace prefix %q on <%s>", n.prefix, name)
	}
	for i := range n.attrs {
		a := &n.attrs[i]
		if a.prefix == "" {
			continue // unprefixed attributes are never in the default namespace
		}
		if a.uri, ok = lookupNS(n, a.prefix); !ok {
			return nil, p.errf("undeclared namespace prefix %q on attribute %q", a.prefix, a.local)
		}
	}
	for i := range n.attrs {
		for j := i + 1; j < len(n.attrs); j++ {
			if n.attrs[i].uri == n.attrs[j].uri && n.attrs[i].local == n.attrs[j].local {
				return nil, p.errf("duplicate attribute {%s}%s on <%s>", n.attrs[i].uri, n.attrs[i].local, name)
			}
		}
	}
	if selfClosing {
		return n, nil
	}

	for {
		if p.pos >= len(p.src) {
			return nil, p.errf("unclosed element <%s>", name)
		}
		if p.src[p.pos] != '<' {
			text, err := p.scanText()
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, &xnode{kind: nodeText, parent: n, text: text})
			continue
		}
		switch {
		case p.hasPrefix("</"):
			p.pos += 2
			cname, err := p.scanName()
			if err != nil {
				return nil, err
			}
			if cname != name {
				return nil, p.errf("end tag </%s> does not match <%s>", cname, name)
			}
			p.skipSpace()
			if p.pos >= len(p.src) || p.src[p.pos] != '>' {
				return nil, p.errf("unterminated end tag </%s>", cname)
			}
			p.pos++
			return n, nil
		case p.hasPrefix("<![CDATA["):
			p.pos += len("<![CDATA[")
			end := bytes.Index(p.src[p.pos:], []byte("]]>"))
			if end < 0 {
				return nil, p.errf("unterminated CDATA section")
			}
			n.children = append(n.children, &xnode{kind: nodeText, parent: n, text: string(p.src[p.pos : p.pos+end])})
			p.pos += end + 3
		case p.hasPrefix("<!--"):
			text, err := p.parseComment()
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, &xnode{kind: nodeComment, parent: n, text: text})
		case p.hasPrefix("<!"):
			return nil, ErrDoctype
		case p.hasPrefix("<?"):
			target, data, err := p.parsePI()
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, &xnode{kind: nodePI, parent: n, piTarget: target, text: data})
		default:
			child, err := p.parseElement(n, depth+1)
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, child)
		}
	}
}

// scanAttrValue reads a quoted attribute value, expanding the five predefined
// entities and character references and applying attribute-value normalization
// (literal tab/newline become a space; the same characters written as character
// references survive, which is why they are tracked separately).
func (p *xparser) scanAttrValue() (string, error) {
	if p.pos >= len(p.src) {
		return "", p.errf("expected an attribute value")
	}
	quote := p.src[p.pos]
	if quote != '"' && quote != '\'' {
		return "", p.errf("attribute value must be quoted")
	}
	p.pos++
	var b strings.Builder
	for {
		if p.pos >= len(p.src) {
			return "", p.errf("unterminated attribute value")
		}
		c := p.src[p.pos]
		switch {
		case c == quote:
			p.pos++
			return b.String(), nil
		case c == '<':
			return "", p.errf("'<' is not allowed in an attribute value")
		case c == '&':
			r, err := p.scanReference()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
		case c == '\t' || c == '\n':
			b.WriteByte(' ')
			p.pos++
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

// scanText reads character data up to the next '<'.
func (p *xparser) scanText() (string, error) {
	var b strings.Builder
	for p.pos < len(p.src) && p.src[p.pos] != '<' {
		if p.src[p.pos] == '&' {
			r, err := p.scanReference()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
			continue
		}
		b.WriteByte(p.src[p.pos])
		p.pos++
	}
	return b.String(), nil
}

// scanReference expands one entity or character reference. Only the five
// predefined entities and numeric character references are accepted; anything
// else would require a DTD, which this parser refuses to process.
func (p *xparser) scanReference() (rune, error) {
	end := bytes.IndexByte(p.src[p.pos:], ';')
	if end < 0 || end > 12 {
		return 0, p.errf("unterminated entity reference")
	}
	ref := string(p.src[p.pos+1 : p.pos+end])
	p.pos += end + 1
	switch ref {
	case "amp":
		return '&', nil
	case "lt":
		return '<', nil
	case "gt":
		return '>', nil
	case "quot":
		return '"', nil
	case "apos":
		return '\'', nil
	}
	if strings.HasPrefix(ref, "#") {
		var (
			v   uint64
			err error
		)
		if strings.HasPrefix(ref, "#x") || strings.HasPrefix(ref, "#X") {
			v, err = strconv.ParseUint(ref[2:], 16, 32)
		} else {
			v, err = strconv.ParseUint(ref[1:], 10, 32)
		}
		if err != nil {
			return 0, p.errf("malformed character reference &%s;", ref)
		}
		r := rune(v)
		if !isXMLChar(r) {
			return 0, p.errf("character reference &%s; is not a legal XML character", ref)
		}
		return r, nil
	}
	return 0, fmt.Errorf("%w (found &%s;)", ErrDoctype, ref)
}

func isXMLChar(r rune) bool {
	switch {
	case r == 0x9 || r == 0xA || r == 0xD:
		return true
	case r >= 0x20 && r <= 0xD7FF:
		return true
	case r >= 0xE000 && r <= 0xFFFD:
		return true
	case r >= 0x10000 && r <= 0x10FFFF:
		return true
	}
	return false
}
