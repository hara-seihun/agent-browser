#!/usr/bin/env python3
import argparse,functools,hashlib,http.server,json,os,pathlib,re,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--native',required=True);p.add_argument('--output',required=True);p.add_argument('--expect',choices=['refusal','pass'],required=True);a=p.parse_args()
n=pathlib.Path(a.native).resolve(strict=True);out=pathlib.Path(a.output);assert out.is_absolute() and not out.exists()
r=pathlib.Path(tempfile.mkdtemp(prefix='ifp-'));(r/'home').mkdir();(r/'s').mkdir();(r/'web').mkdir();(r/'empty.json').write_text('{}\n')
env=os.environ.copy()
for k in list(env):
 if k.startswith('AGENT_BROWSER_'):env.pop(k)
env.update(HOME=str(r/'home'),AGENT_BROWSER_SOCKET_DIR=str(r/'s'),AGENT_BROWSER_PLUGINS='[]')
pre=[str(n),'--config',str(r/'empty.json'),'--engine','chrome','--executable-path','/srv/pi-stack-next/toolchains/chrome-154.0.8037.92/chrome','--namespace','proof','--session','proof','--json']
secret='SYNTHETIC-LOGIN-SECRET-921704'
(r/'web/index.html').write_text('<!doctype html><title>Authenticated dashboard</title><input type=password id=login value="'+secret+'" hidden><button id=detach onclick="document.querySelector(\'iframe\').remove()">Detach inspector</button><iframe id=inspector src="http://localhost:PORT/inspector.html"></iframe><input aria-label="XPath" id=decoy value=unchanged>')
(r/'web/inspector.html').write_text('<!doctype html><title>Appium Inspector fixture</title><label for=search>XPath</label><input id=search placeholder="Search for element"><input type=password id=frame-secret value="FRAME-SYNTHETIC-SECRET">')
class Q(http.server.SimpleHTTPRequestHandler):
 def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Q,directory=str(r/'web')))
f=r/'web/index.html';f.write_text(f.read_text().replace('PORT',str(server.server_port)))
threading.Thread(target=server.serve_forever,daemon=True).start()
report={'native':str(n),'sha256':hashlib.sha256(n.read_bytes()).hexdigest(),'scope':'owned synthetic login-state/cross-origin inspector iframe only; no provider/account/phone action','runtimeRoot':str(r),'startedAt':time.time(),'steps':[]}
def save():out.write_text(json.dumps(report,indent=2)+'\n')
def cli(args):
 cp=subprocess.run(pre+args,env=env,capture_output=True,text=True,timeout=15)
 try:b=json.loads(cp.stdout)
 except ValueError:b={'stdout':cp.stdout,'stderr':cp.stderr}
 step={'argv':args,'exit':cp.returncode,'body':b};report['steps'].append(step);save();return step
def ok(args):
 d=cli(args);assert d['exit']==0,d;return d
try:
 ok(['open',f'http://127.0.0.1:{server.server_port}/index.html'])
 s=ok(['snapshot','-i']);assert secret not in json.dumps(s)
 ok(['frame','#inspector']);s=ok(['snapshot','-i'])
 text=json.dumps(s['body']);match=re.search(r'XPath[^\n]*?ref=(e\d+)',text)
 if not match:match=re.search(r'textbox[^\n]*?ref=(e\d+)',text)
 assert match,text
 ref='@'+match.group(1);report['targetRef']=ref;save()
 d=cli(['fill',ref,"//*[@text='Start admitted top-level panel' or @content-desc='Start admitted top-level panel']"])
 if a.expect=='refusal':
  assert d['exit']!=0 and 'SENSITIVE_OUTPUT_UNSUPPORTED' in json.dumps(d),d
 else:
  assert d['exit']==0,d
  value=ok(['get','value',ref]);assert 'Start admitted top-level panel' in json.dumps(value),value
  d=cli(['fill','#frame-secret','not-a-secret']);assert d['exit']!=0 and 'SENSITIVE_OUTPUT_UNSUPPORTED' in json.dumps(d),d
  d=cli(['eval','document.body.innerText']);assert d['exit']!=0 and 'SENSITIVE_OUTPUT_UNSUPPORTED' in json.dumps(d),d
  s=ok(['snapshot','-i']);assert 'FRAME-SYNTHETIC-SECRET' not in json.dumps(s)
  ok(['frame','main']);ok(['click','#detach'])
  d=cli(['fill',ref,'must-not-hit-decoy']);assert d['exit']!=0,d
  value=ok(['get','value','#decoy']);assert 'unchanged' in json.dumps(value) and 'must-not-hit-decoy' not in json.dumps(value),value
 report['accepted']=True
finally:
 try:report['close']=cli(['close'])
 finally:server.shutdown();server.server_close();report['endedAt']=time.time();save()
