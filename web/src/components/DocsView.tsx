import { DocsApp, VersionBadge, ghrepo } from 'go-ui';
import type { Lib } from '../data';
import { Install } from './Install';
import { QuickStart } from './QuickStart';

export interface DocsViewProps {
  lib: Lib;
}

// DocsView is the "docs" tab. It renders the full, package-by-package Go API
// reference inline via the shared `DocsApp`, which fetches the generated
// `doc.json` (emitted by docs/gen) and shows a package sidebar + package view,
// hash-routable by import path. A secondary link points at the raw generated
// static HTML (`./api/`). Install + QuickStart snippets follow so a reader can
// get running without leaving the page.
//
// `doc.json` is served at `<base>/doc.json`. If it is missing, DocsApp degrades
// gracefully (it renders an inline error/loading state rather than crashing).
export function DocsView({ lib }: DocsViewProps) {
  return (
    <section className="view active" id="view-docs">
      <div className="sec-h"><span className="bar" /><h2 style={{ margin: 0 }}>API documentation</h2></div>
      <p className="muted">The complete package-by-package Go API reference, generated from source. It documents every exported type, function and method across the {lib.name} module and its 100+ strategy packages.</p>

      <div className="actions" style={{ marginBottom: '1.4rem' }}>
        <a className="pill b" href="./api/"><i className="fa-solid fa-file-code" />&nbsp;Raw generated HTML</a>
        <a className="pill b" href={lib.repo} target="_blank" rel="noopener"><i className="fa-brands fa-github" />&nbsp;Source on GitHub</a>
        <VersionBadge repo={ghrepo(lib)} href={`${lib.repo}/releases`} />
      </div>

      <DocsApp url={`${import.meta.env.BASE_URL}doc.json`} />

      <Install lib={lib} />
      <QuickStart lib={lib} />
    </section>
  );
}
