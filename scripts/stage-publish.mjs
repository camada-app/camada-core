// Stage a @camada package for `npm publish` without touching its checkout.
//
// The checkouts depend on their siblings through `file:../camada-*` links so tests can read
// fixtures through the symlink; a published manifest needs caret ranges instead. This copies
// the publishable files into a temp dir, rewrites those links to `^<version>` (from the sibling
// checkout when it is there, else from the npm registry), fills in repository/homepage/bugs,
// drops scripts and devDependencies, and publishes from the copy. Every adapter's publish.yml
// runs it from a camada-core checkout, so there is one copy of this file.
//
// usage: node stage-publish.mjs <repo-dir> [--publish]
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const repo = resolve(process.argv[2] ?? '.');
const publish = process.argv.includes('--publish');
const pkg = JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8'));

function siblingVersion(name, dir) {
  const manifest = join(repo, '..', dir, 'package.json');
  if (existsSync(manifest)) {
    const sib = JSON.parse(readFileSync(manifest, 'utf8'));
    if (sib.name !== name) throw new Error(`${name} points at ${dir}, which is ${sib.name}`);
    return sib.version;
  }
  return execFileSync('npm', ['view', name, 'version'], { encoding: 'utf8' }).trim();
}

for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
  for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
    const m = /^file:\.\.\/(camada-[a-z]+)$/.exec(spec);
    if (m) pkg[field][name] = `^${siblingVersion(name, m[1])}`;
  }
}
delete pkg.devDependencies;
delete pkg.scripts;
const slug = basename(repo);
pkg.repository ??= { type: 'git', url: `git+https://github.com/camada-app/${slug}.git` };
pkg.homepage ??= `https://github.com/camada-app/${slug}#readme`;
pkg.bugs ??= { url: `https://github.com/camada-app/${slug}/issues` };

const stage = mkdtempSync(join(tmpdir(), `${slug}-stage-`));
for (const f of pkg.files ?? ['dist']) {
  const src = join(repo, f);
  if (existsSync(src)) cpSync(src, join(stage, f), { recursive: true });
}
writeFileSync(join(stage, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);

console.log(`${pkg.name}@${pkg.version}`, JSON.stringify(pkg.dependencies ?? {}));
const args = ['publish', '--access', 'public'];
if (process.env.GITHUB_ACTIONS) args.push('--provenance'); // signed against the workflow (OIDC)
if (!publish) args.push('--dry-run');
try {
  execFileSync('npm', args, { cwd: stage, stdio: 'inherit' });
} finally {
  rmSync(stage, { recursive: true, force: true });
}
