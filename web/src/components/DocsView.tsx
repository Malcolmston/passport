import { CodeBlock, VersionBadge, hi, ghrepo } from 'go-ui';
import type { Lib } from '../data';

export interface DocsViewProps {
  lib: Lib;
}

// DocsView is the documentation tab: it links out to the generated API
// reference (served alongside this site at ./api/) and shows the install +
// usage snippets so the essentials are one click away.
export function DocsView({ lib }: DocsViewProps) {
  return (
    <section className="view active" id="view-docs">
      <div className="sec-h"><span className="bar" /><h2 style={{ margin: 0 }}>Documentation</h2></div>
      <p className="muted">The complete API reference is generated straight from the Go source with <code>go/doc</code> and published alongside this site, so the docs never drift from the code.</p>
      <div className="actions" style={{ margin: '1rem 0 1.6rem' }}>
        <a className="btn primary" href="./api/" target="_blank" rel="noopener"><i className="fa-solid fa-book" />&nbsp;Open the API reference →</a>
        <a className="pill b" href={lib.repo} target="_blank" rel="noopener"><i className="fa-brands fa-github" />&nbsp;Source</a>
        <VersionBadge repo={ghrepo(lib)} href={`${lib.repo}/releases`} />
      </div>

      <div className="sec-h" id="docs-install"><span className="bar" /><h3 style={{ margin: 0 }}>Install</h3></div>
      <CodeBlock lang="shell" html={`<span class="tok-c">$</span> go get ${lib.pkg}`} />

      <div className="sec-h" id="docs-usage"><span className="bar" /><h3 style={{ margin: 0 }}>Usage</h3></div>
      <CodeBlock lang="main.go" html={hi(lib.go_code)} />

      <div className="sec-h" id="docs-more"><span className="bar" /><h3 style={{ margin: 0 }}>Going further</h3></div>
      <CodeBlock lang="go" html={lib.integrate} />

      <div className="note">Full API reference &amp; runnable examples: <a href="./api/" target="_blank" rel="noopener">./api/</a></div>
    </section>
  );
}
