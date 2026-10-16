#!/usr/bin/env python3
"""Disposable CLI/MCP vault lifetime proof; never reads the account vault."""
import argparse, hashlib, json, os, pathlib, subprocess, tempfile, time

p = argparse.ArgumentParser()
p.add_argument('binary')
p.add_argument('output')
p.add_argument('--baseline', action='store_true')
a = p.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix='vault7-', dir='/home/kenan/work'))
home = root / 'home'
home.mkdir()
sockets = root / 'ipc'
config = root / 'empty.json'
config.write_text('{}')
env = {k: v for k, v in os.environ.items() if not k.startswith(('AGENT_BROWSER_', 'XDG_'))}
env.update(HOME=str(home), AGENT_BROWSER_SOCKET_DIR=str(sockets), NO_COLOR='1')
base = [str(pathlib.Path(a.binary).resolve()), '--config', str(config), '--json', '--session', 'fixture']
rows = []
def files():
    return sorted(str(x.relative_to(root)) for x in sockets.rglob('*') if x.is_file() or x.is_socket()) if sockets.exists() else []
def run(args, expected, stdin=None):
    t = time.monotonic()
    result = subprocess.run(base + args, input=stdin, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    body = json.loads(result.stdout)
    rows.append({'args':args, 'exit':result.returncode, 'success':body.get('success'), 'elapsedMs':(time.monotonic()-t)*1000, 'ipc':files()})
    assert body.get('success') == expected, (args, result.returncode, result.stderr)
    if not a.baseline:
        assert not files(), ('metadata spawned daemon', files())
    return body
try:
    run(['auth', 'list'], True)
    if a.baseline:
        assert files(), 'baseline must reproduce retained daemon'
    else:
        run(['auth', 'save', 'fixture', '--url', 'https://invalid.example', '--username', 'synthetic', '--password-stdin'], True, 'synthetic-not-a-secret\n')
        run(['auth', 'show', 'fixture'], True)
        run(['auth', 'list'], True)
        run(['auth', 'show', '../invalid'], False)
        deny = root / 'deny.json'
        deny.write_text(json.dumps({'deny':['auth_delete']}))
        run(['--action-policy', str(deny), 'auth', 'delete', 'fixture'], False)
        run(['auth', 'show', 'fixture'], True)
        run(['auth', 'delete', 'fixture'], True)
        run(['auth', 'show', 'fixture'], False)
        # Browser configuration cannot make metadata attach to or launch a browser.
        run(['--executable-path', '/missing-vault-fixture-chrome', '--headed', 'auth', 'list'], True)
        # MCP invokes this same canonical CLI; exercise its actual stdio transport.
        requests = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'vault-fixture','version':'1'}}},
                    {'jsonrpc':'2.0','method':'notifications/initialized'},
                    {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'agent_browser_auth_list','arguments':{'session':'fixture','extraArgs':['--config',str(config)]}}}]
        mcp = subprocess.run([base[0], '--config', str(config), 'mcp', '--tools', 'all'], input=''.join(json.dumps(v)+'\n' for v in requests), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        responses = [json.loads(line) for line in mcp.stdout.splitlines() if line.strip()]
        response = next(v for v in responses if v.get('id') == 2)
        assert 'error' not in response and not response['result'].get('isError', False), response
        assert not files(), files()
        rows.append({'case':'actual-mcp-auth-list', 'exit':mcp.returncode, 'ipc':files(), 'success':True})
finally:
    if a.baseline:
        closed = subprocess.run(base+['close'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        assert closed.returncode == 0
report = {'ok':True,'baseline':a.baseline,'binary':base[0], 'binarySha256':hashlib.sha256(pathlib.Path(base[0]).read_bytes()).hexdigest(), 'rows':rows,'ownedHome':str(home),'finalIpc':files()}
pathlib.Path(a.output).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'ok':True,'baseline':a.baseline,'cases':len(rows)}))
