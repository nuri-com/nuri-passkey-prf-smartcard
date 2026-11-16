import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const walk = dir => readdirSync(dir, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? walk(resolve(dir, e.name)) : [resolve(dir, e.name)]);
const docs = [resolve(root, 'README.md'), ...walk(resolve(root, 'docs')).filter(p => p.endsWith('.md'))];
const repoFiles = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(p => p && existsSync(resolve(root, p)));
const repoRoots = '(?:card|dist|docs|extension|host|mobile|patches|scripts|src|test|third_party|tools|web|bin)';
const repoPath = new RegExp(`^(?:\\.\\./|\\./)*(?:${repoRoots}/|[A-Z][A-Z_]*(?:\\.md)?$|package(?:-lock)?\\.json$|requirements[^/]*\\.txt$)`);

function candidates(from, target) {
  return [resolve(dirname(from), target), resolve(root, target), ...(!target.includes('/') ? repoFiles.filter(p => p.endsWith('/' + target)).map(p => resolve(root, p)) : [])];
}
function checkReference(from, target, kind, failures) {
  if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(target)) return;
  const [path, fragment] = target.split('#');
  target = decodeURIComponent(path.split('?')[0]);
  const options = kind === 'inline repo path' ? candidates(from, target) : [target ? resolve(dirname(from), target) : from];
  const found = options.find(existsSync);
  if (!found) { failures.push(`${relative(root, from)}: ${kind}: ${target}`); return; }
  if (fragment && found.endsWith('.md') && !/^L\d+(?:-L?\d+)?$/.test(fragment)) {
    const text = readFileSync(found, 'utf8').replace(/^\s*```[^\n]*\n[\s\S]*?^\s*```\s*$/gm, '');
    const slugs = [...text.matchAll(/^#{1,6}\s+(.+)$/gm)].map(m => m[1].toLowerCase()
      .replace(/<[^>]*>/g, '').replace(/[^\p{L}\p{N}_ -]/gu, '').replace(/ /g, '-'));
    if (!slugs.includes(decodeURIComponent(fragment))) failures.push(`${relative(root, from)}: missing heading: ${target}#${fragment}`);
  }
}

test('README and all docs: relative links and backticked repository paths exist', () => {
  const failures = [];
  const index = readFileSync(resolve(root, 'docs/README.md'), 'utf8');
  for (const artifact of walk(resolve(root, 'docs'))) {
    if (artifact.endsWith('/README.md')) continue;
    assert.ok(index.includes(`](${relative(resolve(root, 'docs'), artifact)})`), `docs index omits ${artifact}`);
  }
  for (const from of docs) {
    const text = readFileSync(from, 'utf8');
    assert.match(text, /```mermaid\n/, `${relative(root, from)} needs a Mermaid diagram`);
    // Inline links/images, including optional titles and angle-bracket paths.
    for (const match of text.matchAll(/!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\s*\)/g)) {
      checkReference(from, match[1] || match[2], 'link', failures);
    }
    // Reference-style Markdown links.
    for (const match of text.matchAll(/^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?/gm)) {
      checkReference(from, match[1], 'reference link', failures);
    }
    const prose = text.replace(/^\s*```[^\n]*\n[\s\S]*?^\s*```\s*$/gm, '');
    for (const match of prose.matchAll(/(?<!`)`([^`\n]+)`(?!`)/g)) {
      const token = match[1].replace(/:\d+(?:[-–]\d+)?(?:,\d+(?:[-–]\d+)?)*$/, '').replace(/#.*$/, '');
      // Runtime/output paths (~, /absolute, .build, environment variables) are
      // deliberately not repository paths. Commands and protocol strings aren't either.
      if (!(repoPath.test(token) || /^[\w.-]+\.(?:md|sh|py|java|js|mjs)$/.test(token)) || /[\s|{}*<>]/.test(token)) continue;
      // Bare upper-case constants are not filenames.
      if (!token.includes('/') && !token.includes('.')) continue;
      checkReference(from, token, 'inline repo path', failures);
    }
  }
  assert.deepEqual(failures, []);
  console.log(`DOC_LINKS_OK ${docs.length} Markdown files`);
});

test('link checker rejects missing links and missing inline repository paths', () => {
  const failures = [];
  checkReference(docs[0], 'docs/__missing__.md', 'link', failures);
  checkReference(docs[0], 'scripts/__missing__.py', 'inline repo path', failures);
  assert.equal(failures.length, 2);
});
