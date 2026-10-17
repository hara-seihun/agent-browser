#!/usr/bin/env python3
import argparse,functools,hashlib,http.server,json,os,pathlib,re,subprocess,tempfile,threading,time,uuid
p=argparse.ArgumentParser();p.add_argument('--native',required=True);p.add_argument('--output',required=True);a=p.parse_args();n=pathlib.Path(a.native).resolve(strict=True);out=pathlib.Path(a.output);assert out.is_absolute() and not out.exists()
r=pathlib.Path(tempfile.mkdtemp(prefix='cjp-'));(r/'home').mkdir();(r/'s').mkdir();(r/'web').mkdir();(r/'empty.json').write_text('{}\n');(r/'web/index.html').write_text('<title>Owned cross-job state</title><input aria-label="Persistent value" id=value value=initial>')
env=os.environ.copy()
for key in list(env):
 if key.startswith('AGENT_BROWSER_'):env.pop(key)
env.update(HOME=str(r/'home'),AGENT_BROWSER_SOCKET_DIR=str(r/'s'),AGENT_BROWSER_PLUGINS='[]')
pre=[str(n),'--config',str(r/'empty.json'),'--engine','chrome','--executable-path','/srv/pi-stack-next/toolchains/chrome-154.0.8037.92/chrome','--namespace','proof','--session','proof','--json']
class Q(http.server.SimpleHTTPRequestHandler):
 def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Q,directory=str(r/'web')));threading.Thread(target=server.serve_forever,daemon=True).start()
report={'native':str(n),'sha256':hashlib.sha256(n.read_bytes()).hexdigest(),'runtimeRoot':str(r),'steps':[],'scope':'distinct bounded systemd job cgroups and synthetic local page only'}
def save():out.write_text(json.dumps(report,indent=2)+'\n')
def cli(args):
 unit='agent-browser-proof-job-'+uuid.uuid4().hex
 run=['systemd-run','--user','--quiet','--wait','--pipe','--collect','--service-type=exec','--property=KillMode=control-group','--property=RuntimeMaxSec=20s','--unit='+unit]
 for key in env:
  if key.startswith('AGENT_BROWSER_') or key in ['HOME','PATH','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS']:run.append('--setenv='+key)
 cp=subprocess.run(run+['--']+pre+args,env=env,capture_output=True,text=True,timeout=25)
 try:b=json.loads(cp.stdout)
 except ValueError:b={'stdout':cp.stdout,'stderr':cp.stderr}
 d={'argv':args,'jobUnit':unit,'exit':cp.returncode,'body':b};report['steps'].append(d);save();return d
def ok(args):
 d=cli(args);assert d['exit']==0,d;return d['body']['data']
try:
 opened=ok(['open',f'http://127.0.0.1:{server.server_port}/index.html'])
 s=ok(['snapshot','-i']);ref='@'+re.search(r'ref=(e\d+)',s['snapshot']).group(1)
 before=ok(['session','info']);report['before']=before
 assert before['daemonOwner']['kind']=='systemd-user-service',before
 pid=before['backgroundPid'];report['daemonCgroup']=pathlib.Path(f'/proc/{pid}/cgroup').read_text();assert before['daemonOwner']['unit'] in report['daemonCgroup']
 ok(['fill',ref,'retained-across-job-cgroups']);value=ok(['get','value',ref]);assert 'retained-across-job-cgroups' in json.dumps(value),value
 after=ok(['session','info']);assert after['backgroundPid']==pid and after['daemonOwner']==before['daemonOwner'],after
 ok(['close'])
 deadline=time.monotonic()+3
 while pathlib.Path(f'/proc/{pid}').exists() and time.monotonic()<deadline:time.sleep(.02)
 assert not pathlib.Path(f'/proc/{pid}').exists(),pid
 report['closedPidAbsent']=True;report['accepted']=True
finally:
 try:
  if not report.get('closedPidAbsent'):report['cleanup']=cli(['close'])
 finally:server.shutdown();server.server_close();save()
