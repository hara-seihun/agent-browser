#!/usr/bin/env python3
"""Local Chromium credential regression. Only synthetic credentials are used."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid

binary = sys.argv[1]
chrome = shutil.which('chromium') or shutil.which('google-chrome')
assert chrome, 'Chrome must be installed'
session = 'bu-secret-' + uuid.uuid4().hex[:10]
secret = 'bu_' + 'Synthetic_UrlSafe-FakeKey0123456789abcdefghijk'[:43]
assert len(secret) == 46
selector = "[role=dialog] :has(> button[aria-label='Copy API key']) + *"

def run(*args, success=True):
    result = subprocess.run([binary, '--session', session, '--executable-path', chrome,
                             '--json', *args], capture_output=True, text=True, timeout=45)
    assert secret not in result.stdout + result.stderr, 'Synthetic credential leaked in command output'
    payload = json.loads(result.stdout)
    assert payload.get('success') == success, (args[0], payload)
    return payload

with tempfile.TemporaryDirectory(prefix='bu-secret-') as temp:
    root = pathlib.Path(temp)
    root.chmod(0o700)
    fixture = root / 'dialog.html'
    fixture.write_text('''<!doctype html><html><body>
        <div role="dialog"><h2>API Key Created</h2>
        <div><button aria-label="Copy API key">Copy API key</button></div>
        <div id="credential">''' + secret + '''</div></div>
        <p>Public dashboard help</p><p>pk_test_public_key_is_readable</p>
        </body></html>''')
    try:
        run('open', fixture.as_uri())
        for args in [('snapshot', '-i'), ('snapshot',), ('get', 'text', '#credential'),
                     ('get', 'html', 'body'), ('get', 'text', 'body')]:
            payload = run(*args)
            if args == ('snapshot',):
                assert '[redacted: credential]' in json.dumps(payload), payload
        print('PASS: dialog StaticText, interactive/full snapshots and getters never expose the key')
        refusal = run('eval', 'document.body.innerText', success=False)
        assert 'SENSITIVE_OUTPUT_UNSUPPORTED' in json.dumps(refusal), refusal
        print('PASS: evaluation refuses the sensitive dialog')
        shot = run('screenshot', str(root / 'masked.png'))
        assert (root / 'masked.png').is_file(), shot
        # The screenshot is accompanied by native sensitive mask metadata.
        assert shot['data']['guard']['maskedControls'] > 0, shot
        print('PASS: screenshot reports sensitive masking')
        output = root / 'private-key'
        run('auth', 'export', '--selector', selector, '--output', str(output))
        assert output.read_text() == secret, 'Private export changed selected bytes'
        assert output.stat().st_mode & 0o777 == 0o600
        print('PASS: the original Copy API key sibling selector still exports exact bytes to a private file')
        assert run('get', 'text', 'body')['data'], 'Public page content should remain available'
        for label, html, expected in [
            ('unlabelled', '<div id="credential">' + secret + '</div><p>Public dashboard help</p>', secret),
            ('attribute', '<div id="credential" data-key="' + secret + '">Key material</div><p>Public dashboard help</p>', secret),

        ]:
            fixture = root / (label.replace(' ', '-') + '.html')
            fixture.write_text('<!doctype html><html><body>' + html + '</body></html>')
            run('open', fixture.as_uri())
            snapshot = run('snapshot')
            assert expected not in json.dumps(snapshot), label + ' snapshot leaked'
            assert 'Public dashboard help' in json.dumps(snapshot), label + ' hid public content'
            getter = run('get', 'html', 'body')
            assert expected not in json.dumps(getter), label + ' getter leaked'
            run('eval', 'document.body.innerText', success=False)
            shot = run('screenshot', str(root / (label.replace(' ', '-') + '.png')))
            assert shot['data']['guard']['maskedControls'] > 0, label
            print('PASS: ' + label + ' tokens are protected across snapshot, getter, eval and screenshot')
    finally:
        run('close')
