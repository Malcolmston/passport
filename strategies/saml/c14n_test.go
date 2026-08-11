package saml

import (
	"strings"
	"testing"
)

// findFirst returns the first element in doc with the given local name.
func findFirst(t *testing.T, doc *xnode, local string) *xnode {
	t.Helper()
	var found *xnode
	doc.walk(func(n *xnode) {
		if found == nil && n.local == local {
			found = n
		}
	})
	if found == nil {
		t.Fatalf("no <%s> element in document", local)
	}
	return found
}

func mustParse(t *testing.T, s string) *xnode {
	t.Helper()
	doc, err := parseXML([]byte(s), defaultMaxDepth)
	if err != nil {
		t.Fatalf("parseXML(%q): %v", s, err)
	}
	return doc
}

// TestCanonicalizeKnownAnswers pins the canonical form of hand-picked inputs.
//
// Every expected value below is derived directly from the rules in the C14N 1.0
// and exc-c14n 1.0 recommendations, not from running this implementation:
//
//   - namespace declarations are emitted before attributes, sorted by prefix
//     with the default namespace first;
//   - attributes are sorted by namespace URI then local name, so unprefixed
//     attributes (empty URI) come first;
//   - empty elements are written with an explicit end tag;
//   - comments are dropped, processing instructions are kept;
//   - character data escapes &, < and > and writes CR as &#xD;;
//   - attribute values escape &, < and " and write TAB, LF and CR as &#x9;,
//     &#xA; and &#xD;, while a *literal* tab or newline has already become a
//     space through attribute-value normalization;
//   - a binding is only re-declared when the nearest output ancestor rendered a
//     different value for that prefix, and xmlns="" is never emitted when no
//     default namespace was in force.
//
// The xml-namespace and comment cases add three more rules, taken from C14N 1.0
// §2.3, C14N 1.1 §2.4 and the "Comment Nodes" bullet of both processing models:
//
//   - under inclusive c14n the apex of a document subset is output as if it
//     carried the nearest in-scope occurrence of the omitted ancestors'
//     xml-namespace attributes — every one of them in 1.0, only the "simple
//     inheritable" xml:lang and xml:space in 1.1, with xml:id explicitly left
//     alone and xml:base recomputed by join-URI-References;
//   - exclusive c14n inherits nothing onto the apex at all;
//   - comments are output as <!--...--> only for a "#WithComments" algorithm.
func TestCanonicalizeKnownAnswers(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		apex         string // local name of the apex element; "" means the root
		exclusive    bool
		v11          bool
		withComments bool
		prefixes     []string
		want         string
	}{
		{
			name:  "inclusive root sorts namespaces and attributes",
			input: `<doc xmlns:b="urn:b" xmlns:a="urn:a" xmlns:c="urn:c"><e a:x="1" z="2" b:y="3" attr="v">text &amp; &lt;more&gt;</e></doc>`,
			want:  `<doc xmlns:a="urn:a" xmlns:b="urn:b" xmlns:c="urn:c"><e attr="v" z="2" a:x="1" b:y="3">text &amp; &lt;more&gt;</e></doc>`,
		},
		{
			// The apex of an inclusive canonicalization inherits every
			// in-scope binding, including urn:c which nothing uses.
			name:  "inclusive subset inherits unused namespaces",
			input: `<doc xmlns:b="urn:b" xmlns:a="urn:a" xmlns:c="urn:c"><e a:x="1" z="2" b:y="3" attr="v">t</e></doc>`,
			apex:  "e",
			want:  `<e xmlns:a="urn:a" xmlns:b="urn:b" xmlns:c="urn:c" attr="v" z="2" a:x="1" b:y="3">t</e>`,
		},
		{
			// Exclusive canonicalization emits only visibly utilized
			// prefixes, so urn:c disappears. This difference is exactly why
			// the algorithm has to be taken from the document rather than
			// assumed.
			name:      "exclusive subset drops unused namespaces",
			input:     `<doc xmlns:b="urn:b" xmlns:a="urn:a" xmlns:c="urn:c"><e a:x="1" z="2" b:y="3" attr="v">t</e></doc>`,
			apex:      "e",
			exclusive: true,
			want:      `<e xmlns:a="urn:a" xmlns:b="urn:b" attr="v" z="2" a:x="1" b:y="3">t</e>`,
		},
		{
			name:      "exclusive InclusiveNamespaces pulls a prefix back in",
			input:     `<doc xmlns:b="urn:b" xmlns:a="urn:a" xmlns:c="urn:c"><e a:x="1">t</e></doc>`,
			apex:      "e",
			exclusive: true,
			prefixes:  []string{"c"},
			want:      `<e xmlns:a="urn:a" xmlns:c="urn:c" a:x="1">t</e>`,
		},
		{
			name:      "exclusive default namespace undeclaration",
			input:     `<a xmlns="urn:d"><b xmlns=""><c/></b></a>`,
			exclusive: true,
			want:      `<a xmlns="urn:d"><b xmlns=""><c></c></b></a>`,
		},
		{
			name:  "inclusive default namespace undeclaration",
			input: `<a xmlns="urn:d"><b xmlns=""><c/></b></a>`,
			want:  `<a xmlns="urn:d"><b xmlns=""><c></c></b></a>`,
		},
		{
			// xmlns="" on the apex has nothing to undeclare and must not be
			// emitted.
			name:  "no spurious default namespace undeclaration",
			input: `<a xmlns=""><b/></a>`,
			want:  `<a><b></b></a>`,
		},
		{
			name:  "attribute value escaping",
			input: `<e a="x&#x9;y&#xA;z&quot;w&amp;v&#xD;u"/>`,
			want:  `<e a="x&#x9;y&#xA;z&quot;w&amp;v&#xD;u"></e>`,
		},
		{
			// A literal tab and a literal newline in the source are
			// normalized to spaces before canonicalization sees them.
			name:  "attribute value whitespace normalization",
			input: "<e a=\"x\ty\nz\"/>",
			want:  `<e a="x y z"></e>`,
		},
		{
			name:  "carriage return in text",
			input: `<e>a&#xD;b</e>`,
			want:  `<e>a&#xD;b</e>`,
		},
		{
			name:  "comments dropped, processing instructions kept",
			input: `<e><!--gone--><?target data?>t</e>`,
			want:  `<e><?target data?>t</e>`,
		},
		{
			name:  "CDATA becomes escaped text",
			input: `<e><![CDATA[a < b & c]]></e>`,
			want:  `<e>a &lt; b &amp; c</e>`,
		},
		{
			// The nearest output ancestor already rendered p=urn:p, so the
			// redundant redeclaration on <c> is suppressed.
			name:  "redundant redeclaration suppressed",
			input: `<p:a xmlns:p="urn:p"><p:b><p:c xmlns:p="urn:p"/></p:b></p:a>`,
			want:  `<p:a xmlns:p="urn:p"><p:b><p:c></p:c></p:b></p:a>`,
		},
		{
			// Exclusive c14n renders a prefix on the first element that
			// visibly utilizes it, so <q:b> — which does not use p — carries
			// no xmlns:p. <p:c> does use p, but the exc-c14n ns_rendered set
			// accumulates down the output ancestor chain and <p:a> already
			// rendered the identical binding, so it is not repeated.
			name:      "exclusive renders per element",
			input:     `<p:a xmlns:p="urn:p" xmlns:q="urn:q"><q:b><p:c/></q:b></p:a>`,
			exclusive: true,
			want:      `<p:a xmlns:p="urn:p"><q:b xmlns:q="urn:q"><p:c></p:c></q:b></p:a>`,
		},

		// --- #WithComments -------------------------------------------------
		{
			// "For canonical XML with comments, generate the opening comment
			// symbol (<!--), the string value of the node, and the closing
			// comment symbol (-->)." The string value is the raw comment
			// content: a comment cannot contain "--", so nothing is escaped.
			name:         "comments retained with comments",
			input:        `<e><!-- keep me --><?target data?>t</e>`,
			withComments: true,
			want:         `<e><!-- keep me --><?target data?>t</e>`,
		},
		{
			// The same document under exclusive #WithComments. Comment
			// handling is orthogonal to the namespace rules.
			name:         "comments retained under exclusive with comments",
			input:        `<p:e xmlns:p="urn:p" xmlns:unused="urn:u">a<!--x-->b</p:e>`,
			exclusive:    true,
			withComments: true,
			want:         `<p:e xmlns:p="urn:p">a<!--x-->b</p:e>`,
		},
		{
			// ... and the identical input with the comment-free algorithm, so
			// the two expectations sit side by side.
			name:      "comments dropped under exclusive without comments",
			input:     `<p:e xmlns:p="urn:p" xmlns:unused="urn:u">a<!--x-->b</p:e>`,
			exclusive: true,
			want:      `<p:e xmlns:p="urn:p">ab</p:e>`,
		},
		{
			// A comment nested well below the apex is retained too; the rule
			// is per node, not per document.
			name:         "nested comment retained",
			input:        `<a><b><c><!--deep--></c></b></a>`,
			withComments: true,
			want:         `<a><b><c><!--deep--></c></b></a>`,
		},

		// --- xml-namespace attributes, Canonical XML 1.0 -------------------
		{
			// C14N 1.0 §2.3 inherits the *nearest* occurrence of each
			// xml-namespace attribute, so <m>'s xml:base wins over <r>'s and
			// no URI resolution happens. Attributes sort by namespace URI then
			// local name, so both land after the unprefixed ones and "base"
			// precedes "lang".
			name:  "C14N 1.0 inherits xml:base verbatim",
			input: `<r xml:base="http://example.org/a/b/c" xml:lang="en"><m xml:base="d/e"><e z="1">t</e></m></r>`,
			apex:  "e",
			want:  `<e z="1" xml:base="d/e" xml:lang="en">t</e>`,
		},
		{
			// An attribute the apex already carries is never replaced by an
			// inherited one.
			name:  "C14N 1.0 apex xml:base wins over ancestors",
			input: `<r xml:base="http://example.org/a/"><e xml:base="y/">t</e></r>`,
			apex:  "e",
			want:  `<e xml:base="y/">t</e>`,
		},
		{
			// C14N 1.0 draws no distinction between xml-namespace attributes,
			// so xml:id is inherited like any other. C14N 1.1 was published
			// specifically because that is wrong; see the 1.1 case below.
			name:  "C14N 1.0 inherits xml:id",
			input: `<r xml:id="q"><e>t</e></r>`,
			apex:  "e",
			want:  `<e xml:id="q">t</e>`,
		},

		// --- xml-namespace attributes, Canonical XML 1.1 -------------------
		{
			// "The xml:id attribute is not a simple inheritable attribute and
			// no processing of these attributes is performed."
			name:  "C14N 1.1 does not inherit xml:id",
			input: `<r xml:id="q"><e>t</e></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e>t</e>`,
		},
		{
			// xml:lang and xml:space are the simple inheritable attributes and
			// keep the 1.0 behaviour.
			name:  "C14N 1.1 still inherits xml:lang and xml:space",
			input: `<r xml:lang="en" xml:space="preserve"><e>t</e></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:lang="en" xml:space="preserve">t</e>`,
		},
		{
			// Only one omitted ancestor carries xml:base, so X1...Xm is a
			// single value and there is nothing to join: it is emitted as it
			// stands, relative form included.
			name:  "C14N 1.1 single ancestor xml:base is used verbatim",
			input: `<r xml:base="b/c"><e>t</e></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="b/c">t</e>`,
		},
		{
			// "The fix-up is only performed if at least one of E1...En had an
			// xml:base attribute." None did, so the apex's own xml:base is an
			// ordinary attribute and is left alone.
			name:  "C14N 1.1 apex xml:base with no omitted ancestor is untouched",
			input: `<r><e xml:base="b/c">t</e></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="b/c">t</e>`,
		},
		{
			// RFC 3986 §5.2.2 with B = http://example.org/a/b/c and the
			// relative reference R = d/e: R.path does not start with "/", so
			// T.path = merge(B.path, R.path) = "/a/b/" + "d/e" = "/a/b/d/e",
			// which remove_dot_segments leaves alone, and scheme and authority
			// come from B.
			name:  "C14N 1.1 xml:base merges a relative reference",
			input: `<r xml:base="http://example.org/a/b/c"><m xml:base="d/e"><e>t</e></m></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="http://example.org/a/b/d/e">t</e>`,
		},
		{
			// merge("/a/b/c/", "../d") = "/a/b/c/../d"; remove_dot_segments
			// walks it to "/a/b" and then appends "/d", giving "/a/b/d".
			name:  "C14N 1.1 xml:base removes dot segments",
			input: `<r xml:base="http://example.org/a/b/c/"><m xml:base="../d"><e>t</e></m></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="http://example.org/a/b/d">t</e>`,
		},
		{
			// RFC 3986 §5.2.2: "if defined(R.scheme) then T = R" — a reference
			// with its own scheme ignores the base entirely, so everything the
			// ancestors contributed is discarded.
			name:  "C14N 1.1 absolute xml:base discards its ancestors",
			input: `<r xml:base="http://example.org/a/"><m xml:base="http://other.example/x/y"><e>t</e></m></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="http://other.example/x/y">t</e>`,
		},
		{
			// C14N 1.1 §2.4 amends §5.2.2 with "after parsing R set
			// R.fragment = null", so "d#frag" resolves exactly as "d" would
			// and the result carries no fragment.
			name:  "C14N 1.1 xml:base discards the reference fragment",
			input: `<r xml:base="http://example.org/a/"><m xml:base="d#frag"><e>t</e></m></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="http://example.org/a/d">t</e>`,
		},
		{
			// X1...Xm runs over E1...En+1, so the apex's own xml:base is the
			// innermost value and is resolved against the ancestors rather
			// than emitted as it stands:
			// merge("/a/", "b/c") = "/a/b/c".
			name:  "C14N 1.1 xml:base includes the apex's own value",
			input: `<r xml:base="http://example.org/a/"><e xml:base="b/c">t</e></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e xml:base="http://example.org/a/b/c">t</e>`,
		},
		{
			// Three levels fold left to right; the fixed-up xml:base sorts
			// with the other xml-namespace attributes, after the unprefixed z
			// and before xml:lang.
			name:  "C14N 1.1 xml:base folds a whole ancestor chain",
			input: `<r xml:base="http://example.org/a/b" xml:lang="en"><m xml:base="c/"><n xml:base="d"><e z="1">t</e></n></m></r>`,
			apex:  "e",
			v11:   true,
			want:  `<e z="1" xml:base="http://example.org/a/c/d" xml:lang="en">t</e>`,
		},

		// --- xml-namespace attributes, exclusive c14n ----------------------
		{
			// Exclusive c14n has no document-subset inheritance rule at all:
			// nothing from the omitted ancestors reaches the apex.
			name:      "exclusive does not propagate xml:base",
			input:     `<r xml:base="http://example.org/a/" xml:lang="en"><e>t</e></r>`,
			apex:      "e",
			exclusive: true,
			want:      `<e>t</e>`,
		},
		{
			// The xml prefix is bound implicitly on every element, so it is
			// never "visibly utilized" in the sense that would require a
			// declaration: no canonical form contains xmlns:xml. Exclusive
			// c14n used to render one here, because it treats any prefix an
			// attribute uses as a candidate and the xml binding resolves
			// without any declaration to point at.
			name:      "no xmlns:xml declaration for the implicit binding",
			input:     `<r><e xml:lang="en" xml:space="preserve">t</e></r>`,
			apex:      "e",
			exclusive: true,
			want:      `<e xml:lang="en" xml:space="preserve">t</e>`,
		},
		{
			// An xml:base the apex carries itself is simply one of its own
			// attributes and survives untouched.
			name:      "exclusive keeps an element's own xml:base",
			input:     `<r xml:base="http://example.org/a/"><e xml:base="b/c">t</e></r>`,
			apex:      "e",
			exclusive: true,
			want:      `<e xml:base="b/c">t</e>`,
		},
		{
			// Below the apex, xml:base is an ordinary attribute under every
			// algorithm.
			name:  "xml:base below the apex is an ordinary attribute",
			input: `<r><e xml:base="http://example.org/a/">t</e></r>`,
			want:  `<r><e xml:base="http://example.org/a/">t</e></r>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustParse(t, tc.input)
			apex := doc
			if tc.apex != "" {
				apex = findFirst(t, doc, tc.apex)
			}
			got, err := canonicalize(apex, c14nOptions{
				exclusive:         tc.exclusive,
				v11:               tc.v11,
				withComments:      tc.withComments,
				inclusivePrefixes: tc.prefixes,
			})
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("canonicalize:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestCanonicalizeOmit checks that the enveloped-signature transform removes
// the signature subtree wherever it sits.
func TestCanonicalizeOmit(t *testing.T) {
	doc := mustParse(t, `<a xmlns:ds="http://www.w3.org/2000/09/xmldsig#">x<ds:Signature><ds:X/></ds:Signature>y</a>`)
	sig := findFirst(t, doc, "Signature")
	got, err := canonicalize(doc, c14nOptions{omit: sig})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `<a xmlns:ds="http://www.w3.org/2000/09/xmldsig#">xy</a>`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestC14NModeForRejectsUnsupported(t *testing.T) {
	for _, alg := range []string{
		"http://www.w3.org/2010/xml-c14n2",
		"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#withcomments", // wrong case
		"http://www.w3.org/2006/12/xml-c14n11#WithComments ",           // trailing space
		"http://example.com/made-up",
		"",
	} {
		if _, err := c14nModeFor(alg); err == nil {
			t.Errorf("c14nModeFor(%q) = nil error, want rejection", alg)
		}
	}
}

// TestC14NModeForSupported pins the URI-to-mode mapping. The six URIs are the
// two comment settings of each of the three algorithms, and the "#WithComments"
// spelling is defined by the specifications as the base URI with that fragment
// appended.
func TestC14NModeForSupported(t *testing.T) {
	tests := []struct {
		alg  string
		want c14nOptions
	}{
		{"http://www.w3.org/TR/2001/REC-xml-c14n-20010315", c14nOptions{}},
		{"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", c14nOptions{withComments: true}},
		{"http://www.w3.org/2006/12/xml-c14n11", c14nOptions{v11: true}},
		{"http://www.w3.org/2006/12/xml-c14n11#WithComments", c14nOptions{v11: true, withComments: true}},
		{"http://www.w3.org/2001/10/xml-exc-c14n#", c14nOptions{exclusive: true}},
		{"http://www.w3.org/2001/10/xml-exc-c14n#WithComments", c14nOptions{exclusive: true, withComments: true}},
	}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			got, err := c14nModeFor(tc.alg)
			if err != nil {
				t.Fatalf("c14nModeFor(%q): %v", tc.alg, err)
			}
			if got.exclusive != tc.want.exclusive || got.v11 != tc.want.v11 || got.withComments != tc.want.withComments {
				t.Errorf("c14nModeFor(%q) = %+v, want %+v", tc.alg, got, tc.want)
			}
		})
	}
	// The exported constants must spell exactly those URIs.
	for _, p := range [][2]string{
		{AlgC14N, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
		{AlgC14NWithComments, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"},
		{AlgC14N11, "http://www.w3.org/2006/12/xml-c14n11"},
		{AlgC14N11WithComments, "http://www.w3.org/2006/12/xml-c14n11#WithComments"},
		{AlgC14NExclusive, "http://www.w3.org/2001/10/xml-exc-c14n#"},
		{AlgC14NExclusiveWithComments, "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"},
	} {
		if p[0] != p[1] {
			t.Errorf("constant is %q, want %q", p[0], p[1])
		}
	}
}

// TestCanonicalizeOutsideDocumentElement pins the one rule that only applies to
// nodes that are siblings of the document element.
//
// C14N 1.0 and 1.1 both say, of comments and identically of processing
// instructions: "a trailing #xA is rendered after the closing comment symbol
// for comment children of the root node with a lesser document order than the
// document element, and a leading #xA is rendered before the opening comment
// symbol of comment children of the root node with a greater document order
// than the document element."
//
// So a node before the document element is followed by a newline, a node after
// it is preceded by one, and nothing separates the document element from
// character data it does not have. A comment omitted by a comment-free
// algorithm emits neither the comment nor its newline.
func TestCanonicalizeOutsideDocumentElement(t *testing.T) {
	// Comments outside the document element cannot come from parseXML, which
	// discards the prolog and epilog, so the node set is assembled here.
	nodes := func() []*xnode {
		return []*xnode{
			{kind: nodePI, piTarget: "before", text: "1"},
			{kind: nodeComment, text: " lesser "},
			mustParse(t, `<e>t</e>`),
			{kind: nodeComment, text: " greater "},
			{kind: nodePI, piTarget: "after", text: "2"},
		}
	}

	tests := []struct {
		name string
		opts c14nOptions
		want string
	}{
		{
			name: "with comments",
			opts: c14nOptions{withComments: true},
			want: "<?before 1?>\n<!-- lesser -->\n<e>t</e>\n<!-- greater -->\n<?after 2?>",
		},
		{
			// The PIs keep their newlines; the comments and the newlines that
			// belong to them disappear together.
			name: "without comments",
			opts: c14nOptions{},
			want: "<?before 1?>\n<e>t</e>\n<?after 2?>",
		},
		{
			name: "exclusive with comments",
			opts: c14nOptions{exclusive: true, withComments: true},
			want: "<?before 1?>\n<!-- lesser -->\n<e>t</e>\n<!-- greater -->\n<?after 2?>",
		},
		{
			name: "C14N 1.1 with comments",
			opts: c14nOptions{v11: true, withComments: true},
			want: "<?before 1?>\n<!-- lesser -->\n<e>t</e>\n<!-- greater -->\n<?after 2?>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeNodes(nodes(), tc.opts)
			if err != nil {
				t.Fatalf("canonicalizeNodes: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("canonicalizeNodes:\n got %q\nwant %q", got, tc.want)
			}
		})
	}

	// A node set with no document element, or with two, is not a document.
	if _, err := canonicalizeNodes([]*xnode{{kind: nodeComment, text: "x"}}, c14nOptions{}); err == nil {
		t.Error("canonicalizeNodes with no document element succeeded, want rejection")
	}
	if _, err := canonicalizeNodes([]*xnode{mustParse(t, `<a/>`), mustParse(t, `<b/>`)}, c14nOptions{}); err == nil {
		t.Error("canonicalizeNodes with two document elements succeeded, want rejection")
	}
	if _, err := canonicalizeNodes([]*xnode{{kind: nodeText, text: "x"}, mustParse(t, `<a/>`)}, c14nOptions{}); err == nil {
		t.Error("canonicalizeNodes with top-level character data succeeded, want rejection")
	}
}

// TestCanonicalizeCommentsNoCrossContamination checks that turning comments on
// is strictly opt-in per algorithm: the comment-free algorithms produce byte
// for byte what they produced when this package had no comment support at all.
func TestCanonicalizeCommentsNoCrossContamination(t *testing.T) {
	const input = `<a xmlns:p="urn:p"><!--one--><p:b>t<!--two--></p:b></a>`

	// The apex of an inclusive canonicalization renders every in-scope binding,
	// so <a> carries xmlns:p; exclusive c14n renders p on <p:b>, the first
	// element that visibly utilizes it. Neither form contains a comment.
	for _, tc := range []struct{ alg, want string }{
		{AlgC14N, `<a xmlns:p="urn:p"><p:b>t</p:b></a>`},
		{AlgC14N11, `<a xmlns:p="urn:p"><p:b>t</p:b></a>`},
		{AlgC14NExclusive, `<a><p:b xmlns:p="urn:p">t</p:b></a>`},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			opts, err := c14nModeFor(tc.alg)
			if err != nil {
				t.Fatalf("c14nModeFor: %v", err)
			}
			got, err := canonicalize(mustParse(t, input), opts)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("%s:\n got %s\nwant %s", tc.alg, got, tc.want)
			}
		})
	}

	// The with-comments form of the same document must differ, or the flag
	// would be doing nothing.
	for _, pair := range [][2]string{
		{AlgC14N, AlgC14NWithComments},
		{AlgC14N11, AlgC14N11WithComments},
		{AlgC14NExclusive, AlgC14NExclusiveWithComments},
	} {
		plainOpts, _ := c14nModeFor(pair[0])
		commentOpts, _ := c14nModeFor(pair[1])
		plain, err := canonicalize(mustParse(t, input), plainOpts)
		if err != nil {
			t.Fatalf("canonicalize %s: %v", pair[0], err)
		}
		withC, err := canonicalize(mustParse(t, input), commentOpts)
		if err != nil {
			t.Fatalf("canonicalize %s: %v", pair[1], err)
		}
		if string(plain) == string(withC) {
			t.Errorf("%s and %s produced identical bytes %s", pair[0], pair[1], plain)
		}
	}
}

// TestXMLBaseRelativeBaseRejected records the one case of the Canonical XML 1.1
// fix-up this package refuses.
//
// The specification's own worked example is that joining "../" onto the base
// "abc/" yields the empty string, which requires its amended forms of RFC 3986
// §5.2.1 and §5.2.4 — relative bases, surviving leading "../" segments — that
// net/url does not provide and that the specification states only by example.
// Approximating it could make two different documents canonicalize alike, so it
// is an error instead.
func TestXMLBaseRelativeBaseRejected(t *testing.T) {
	doc := mustParse(t, `<r xml:base="abc/"><m xml:base="../"><e>t</e></m></r>`)
	_, err := canonicalize(findFirst(t, doc, "e"), c14nOptions{v11: true})
	if err == nil {
		t.Fatal("relative xml:base join succeeded, want an explicit rejection")
	}
	if !strings.Contains(err.Error(), "xml:base") {
		t.Errorf("error %q does not mention xml:base", err)
	}

	// The same chain under C14N 1.0 needs no resolution at all and is fine.
	got, err := canonicalize(findFirst(t, doc, "e"), c14nOptions{})
	if err != nil {
		t.Fatalf("C14N 1.0: %v", err)
	}
	if want := `<e xml:base="../">t</e>`; string(got) != want {
		t.Errorf("C14N 1.0: got %s, want %s", got, want)
	}
}

// TestParserRejects covers the hardening rules of the XML parser.
func TestParserRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"doctype", `<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>`},
		{"entity declaration only", `<!DOCTYPE r SYSTEM "http://evil/x.dtd"><r/>`},
		{"external entity reference", `<r>&xxe;</r>`},
		{"unclosed element", `<r><a></r>`},
		{"mismatched end tag", `<r></q>`},
		{"two roots", `<a/><b/>`},
		{"undeclared prefix", `<p:a/>`},
		{"undeclared attribute prefix", `<a p:x="1"/>`},
		{"duplicate attribute", `<a x="1" x="2"/>`},
		{"unquoted attribute", `<a x=1/>`},
		{"less-than in attribute", `<a x="<"/>`},
		{"no root", `  `},
		{"unterminated comment", `<a><!-- x</a>`},
		{"unterminated CDATA", `<a><![CDATA[x</a>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseXML([]byte(tc.input), defaultMaxDepth); err == nil {
				t.Fatalf("parseXML(%q) succeeded, want rejection", tc.input)
			}
		})
	}
}

func TestParserDepthLimit(t *testing.T) {
	deep := strings.Repeat("<a>", 50) + strings.Repeat("</a>", 50)
	if _, err := parseXML([]byte(deep), 50); err != nil {
		t.Fatalf("depth 50 with limit 50: %v", err)
	}
	if _, err := parseXML([]byte(deep), 49); err == nil {
		t.Fatal("depth 50 with limit 49 succeeded, want rejection")
	}
}

// TestResolveIDRefUnique is the property the whole anti-wrapping design rests
// on: an ID that matches more than one element resolves to none.
func TestResolveIDRefUnique(t *testing.T) {
	doc := mustParse(t, `<r ID="x"><a ID="y"/><b ID="y"/></r>`)
	if _, err := resolveIDRef(doc, "x"); err != nil {
		t.Fatalf("unique ID: %v", err)
	}
	if _, err := resolveIDRef(doc, "y"); err == nil {
		t.Fatal("duplicate ID resolved, want rejection")
	}
	if _, err := resolveIDRef(doc, "zzz"); err == nil {
		t.Fatal("missing ID resolved, want rejection")
	}
}
