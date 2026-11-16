#!/usr/bin/env python3
"""Local native fill fixture; no external navigation, profiles or transactions."""
import json
import shutil
import subprocess
import sys
import uuid

binary = sys.argv[1]
session = 'amount-fixture-' + uuid.uuid4().hex[:10]
chrome = shutil.which('chromium') or shutil.which('google-chrome')

def run(*args, success=True):
    result = subprocess.run([binary, '--session', session, '--executable-path', chrome,
                             '--json', *args], text=True, capture_output=True, timeout=30)
    payload = json.loads(result.stdout)
    assert payload.get('success') is success, (args, payload, result.stderr)
    return payload

def evaluate(script):
    return run('eval', script)['data']['result']

try:
    run('open', 'about:blank')
    evaluate('document.body.innerHTML=\'<input id="amount" aria-label="Amount"><input id="other">\'; true')
    # Deliberately no inputmode. Synchronous masking mimics a controlled amount input.
    evaluate('amount.addEventListener("input", () => { amount.value = window.rendered; }); true')
    for rendered in ['10,053.74', '$10,053.74', '10,053.74 €', '10053.74', '10,053.740',
                     '10,053.75', '1,005.374', '10.053,74', '10,53.74', 'CAD10,053.74',
                     '$10,053.74€', '', '1005374', '+10,053.74', ' 10,053.74']:
        accepted = rendered in ['10,053.74', '$10,053.74', '10,053.74 €', '10053.74']
        evaluate('window.rendered=' + json.dumps(rendered) + '; true')
        response = run('fill', '#amount', '10053.74', success=accepted)
        assert evaluate('amount.value') == rendered
        assert evaluate('other.value') == ''
        if accepted and rendered != '10053.74':
            assert response['data']['retainedValue'] == rendered, response
            assert response['data']['formatting'] == 'numeric-formatting', response
        elif not accepted:
            assert response['code'] == 'fill_value_not_retained', response
    # Same operation through semantic find and snapshot refs.
    evaluate('window.rendered="10,053.74"; true')
    response = run('find', 'label', 'Amount', 'fill', '10053.74')
    assert response['data']['retainedValue'] == '10,053.74', response
    snapshot = run('snapshot', '-i')
    import re
    ref = re.search(r'textbox "Amount" \[ref=(e\d+)\]', snapshot['data']['snapshot']).group(1)
    response = run('fill', '@' + ref, '10053.74')
    assert response['data']['retainedValue'] == '10,053.74', response
    # Passwords and arbitrary text do not get numeric equivalence.
    evaluate('amount.type="password"; true')
    run('fill', '#amount', '10053.74', success=False)
    print('PASS: 15 amount renderings, selector/find/ref observations, unchanged sibling and password rejection')
finally:
    run('close')
