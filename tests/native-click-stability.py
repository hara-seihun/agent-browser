#!/usr/bin/env python3
"""Deterministic local Chromium regression for native click stabilization.
Usage: python3 tests/native-click-stability.py /absolute/path/to/agent-browser
No profiles, external navigation, dependencies, or sleep-based retries.
"""
import json
import subprocess
import shutil
import sys
import uuid

binary = sys.argv[1]
chrome = shutil.which('chromium') or shutil.which('google-chrome')
if not chrome:
    raise SystemExit('Chromium or Google Chrome must be on PATH')
session = 'click-regression-' + uuid.uuid4().hex[:10]

def run(*args, success=True):
    result = subprocess.run([binary, '--session', session, '--executable-path', chrome, '--json', *args], text=True, capture_output=True, timeout=30)
    payload = json.loads(result.stdout)
    assert bool(payload.get('success')) == success, (args, result.stdout, result.stderr)
    return payload

def evaluate(script):
    return run('eval', script)['data']['result']

def page(html):
    run('open', 'about:blank')
    evaluate('document.body.innerHTML=' + json.dumps(html) + '; window.hits=0; window.misses=0; document.onpointerdown=e=>{if(!e.target.closest("button,input,label"))window.misses++}; true')

try:
    run('set', 'viewport', '1000', '650')
    page('''<style>@keyframes enter{from{transform:translateX(1600px)}to{transform:translateX(0)}}button{position:fixed;left:200px;top:120px;width:200px;height:60px}</style><button id="target" onclick="window.hits++">View source</button>''')
    evaluate("document.querySelector('button').style.animation='enter 1200ms linear both';true")
    run('click', '#target')
    assert evaluate('({hits:window.hits,misses:window.misses})') == {'hits': 1, 'misses': 0}
    print('PASS: moving target produces exactly one correct pointer gesture')

    page('<div id="host" style="position:fixed;left:150px;top:80px;width:200px;height:80px"></div>')
    evaluate("const h=document.querySelector('#host');h.attachShadow({mode:'open'}).innerHTML='<button style=\"width:100%;height:100%\">Shadow child</button>';h.onclick=()=>window.hits++;true")
    run('click', '#host')
    assert evaluate('window.hits') == 1
    print('PASS: shadow descendant hit remains supported')

    page('''<label style="position:fixed;left:150px;top:80px;width:200px;height:80px"><input id="check" type="checkbox" style="position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0"><span style="position:absolute;inset:0">Styled label</span></label>''')
    run('click', '#check')
    assert evaluate("document.querySelector('#check').checked") is True
    print('PASS: styled associated label remains supported')

    page('''<iframe id="frame" style="position:fixed;left:230px;top:160px;width:500px;height:300px" srcdoc="<button id='target' style='position:absolute;left:80px;top:60px;width:140px;height:50px' onclick='window.hits=1'>Frame target</button>"></iframe>''')
    run('frame', '#frame')
    run('click', '#target')
    run('frame', 'main')
    assert evaluate("document.querySelector('#frame').contentWindow.hits") == 1
    print('PASS: translated same-process iframe uses its own local geometry')

    page('''<style>@keyframes move{from{transform:translateX(0)}to{transform:translateX(200px)}}button{position:fixed;left:100px;top:100px;width:200px;height:60px;animation:move 500ms linear infinite alternate}</style><button id="target" onclick="window.hits++">Never stable</button>''')
    refusal = run('click', '#target', success=False)
    assert refusal['code'] == 'click_target_unstable', refusal
    assert refusal['data']['effectDispatched'] is False, refusal
    assert evaluate('({hits:window.hits,misses:window.misses})') == {'hits': 0, 'misses': 0}
    print('PASS: unending animation refuses without dispatch')
    page('<style>html,body{overflow:hidden}</style><button id="target" style="position:fixed;left:1500px;top:100px;width:200px;height:60px" onclick="window.hits++">Offscreen</button>')
    refusal = run('click', '#target', success=False)
    assert refusal['code'] == 'click_not_hittable', refusal
    assert refusal['data']['effectDispatched'] is False, refusal
    assert evaluate('({hits:window.hits,misses:window.misses})') == {'hits': 0, 'misses': 0}
    print('PASS: stable offscreen target refuses without dispatch')
finally:
    run('close')
