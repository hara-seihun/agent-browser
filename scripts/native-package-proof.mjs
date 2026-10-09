import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [packagePath, binaryPath, source, tag, ...extra] = process.argv.slice(2);
if (!packagePath || !binaryPath || !/^[a-f0-9]{40}$/.test(source ?? '') || !tag || extra.length) {
  throw new Error('usage: native-package-proof.mjs PACKAGE BINARY SOURCE_SHA RELEASE_TAG');
}
const symbols = execFileSync('objdump', ['-T', binaryPath], { encoding: 'utf8' });
const versions = [...symbols.matchAll(/\bGLIBC_(\d+)\.(\d+)\b/g)].map(match => [Number(match[1]), Number(match[2])]);
if (!versions.length) throw new Error('Executable has no measurable GLIBC requirement');
versions.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
const maximum = versions.at(-1);
if (maximum[0] > 2 || (maximum[0] === 2 && maximum[1] > 35)) {
  throw new Error(`Executable requires GLIBC_${maximum.join('.')} above fleet floor 2.35`);
}
const bytes = readFileSync(packagePath), binary = readFileSync(binaryPath);
const hash = (algorithm, value, encoding) => createHash(algorithm).update(value).digest(encoding);
console.log(JSON.stringify({
  repository: 'hara-seihun/agent-browser', source, tag,
  url: `https://github.com/hara-seihun/agent-browser/releases/download/${tag}/agent-browser-0.37.1.tgz`,
  sha256: hash('sha256', bytes, 'hex'), integrity: `sha512-${hash('sha512', bytes, 'base64')}`,
  binarySha256: hash('sha256', binary, 'hex'), platform: 'linux-x64', glibcRequirement: maximum.join('.'),
}, null, 2));
