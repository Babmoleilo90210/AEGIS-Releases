#!/usr/bin/python3
"""Local administration. No plaintext, decryption or correspondence-export command."""
import os,sys,stat,subprocess,socket,time,re,hmac,secrets,pathlib,sqlite3,pwd,grp,glob
P=pathlib.Path
CONF=P('/etc/aegis/relay.properties');MANAGED=P('/etc/tor/aegis-relay.conf');COOKIE=P('/var/lib/tor/aegis-control.authcookie')
def run(*args,check=True):return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=check,env={**os.environ,"LC_ALL":"C"})
def config():return dict(line.split('=',1) for line in CONF.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#') and '=' in line)
def command(stream,text):
 stream.write((text+'\r\n').encode());stream.flush();lines=[]
 for _ in range(64):
  line=stream.readline(4097)
  if len(line)>4096 or not line.startswith(b'250'):raise RuntimeError('Tor control rejected request')
  lines.append(line.decode('ascii').strip())
  if line.startswith(b'250 '):return lines
 raise RuntimeError('Tor control response too long')
def bootstrap_progress():
 cookie=COOKIE.read_bytes()
 if len(cookie)!=32:raise RuntimeError('Tor control cookie is not ready')
 with socket.create_connection(('127.0.0.1',19051),timeout=3) as sock:
  sock.settimeout(3)
  with sock.makefile('rwb',buffering=0) as stream:
   nonce=secrets.token_bytes(32);line=' '.join(command(stream,'AUTHCHALLENGE SAFECOOKIE '+nonce.hex()))
   server=bytes.fromhex(re.search(r'SERVERNONCE=([A-Fa-f0-9]{64})',line).group(1));given=bytes.fromhex(re.search(r'SERVERHASH=([A-Fa-f0-9]{64})',line).group(1));data=cookie+nonce+server
   expected=hmac.digest(b'Tor safe cookie authentication server-to-controller hash',data,'sha256')
   if not hmac.compare_digest(expected,given):raise RuntimeError('Tor authentication failed')
   answer=hmac.digest(b'Tor safe cookie authentication controller-to-server hash',data,'sha256');command(stream,'AUTHENTICATE '+answer.hex())
   reply=' '.join(command(stream,'GETINFO status/bootstrap-phase'));return int(re.search(r'PROGRESS=(\d+)',reply).group(1))
def bridges():
 lines=P('/opt/aegis/tor/snowflake-bridges.txt').read_text().splitlines()
 if not 1<=len(lines)<=8:raise RuntimeError('Snowflake bridge count invalid')
 for line in lines:
  if not line.startswith('snowflake ') or len(line)>4096 or re.search(r'(?:^| )front=\S*,\S*',line) or any(ord(c)<32 for c in line):raise RuntimeError('Snowflake bridge syntax invalid')
 return lines
def expanded_torrc(path,seen=None):
 seen=set() if seen is None else seen;path=P(path).resolve()
 if path in seen or len(seen)>=64:raise RuntimeError('Recursive or excessive Tor includes')
 seen.add(path);result=[]
 for line in path.read_text().splitlines():
  stripped=line.split('#',1)[0].strip()
  if stripped.startswith('%include '):
   pattern=stripped[9:].strip().strip('"')
   for name in sorted(glob.glob(pattern)):
    if P(name).resolve()!=MANAGED.resolve():result.extend(expanded_torrc(name,seen))
  else:result.append(stripped)
 return result
def tor_configuration():
 torrc=P('/etc/tor/torrc');original=torrc.read_text();include='%include /etc/tor/aegis-relay.conf'
 if MANAGED.exists():
  if include not in original:torrc.write_text(original.rstrip()+'\n'+include+'\n')
  return
 service=None;active=None
 for line in expanded_torrc(torrc):
  parts=line.split()
  if parts and parts[0]=='HiddenServiceDir':active=' '.join(parts[1:]).strip('"')
  if parts and parts[0]=='HiddenServicePort' and parts[1:]==['80','127.0.0.1:19110']:service=active
 existing=service is not None;service=service or '/var/lib/tor/aegis-relay'
 content='SocksPort 0\nControlPort 127.0.0.1:19051\nCookieAuthentication 1\nCookieAuthFile /var/lib/tor/aegis-control.authcookie\nSafeLogging 1\n'
 if not existing:content+='HiddenServiceDir '+service+'\nHiddenServiceVersion 3\nHiddenServicePort 80 127.0.0.1:19110\n'
 MANAGED.write_text(content);os.chmod(MANAGED,0o640);os.chown(MANAGED,0,grp.getgrnam('debian-tor').gr_gid)
 state=P('/etc/aegis/onion-directory');state.write_text(service+'\n');os.chmod(state,0o600)
 if include not in original:torrc.write_text(original.rstrip()+'\n\n# AEGIS\n'+include+'\n')
def snowflake():
 lines=bridges();old=MANAGED.read_text();base=old.split('# AEGIS SNOWFLAKE')[0]
 MANAGED.write_text(base+'# AEGIS SNOWFLAKE\nUseBridges 1\nClientTransportPlugin snowflake exec /opt/aegis/tor/lyrebird\n'+''.join('Bridge '+b+'\n' for b in lines))
 try:run('runuser','-u','debian-tor','--','/usr/bin/tor','--defaults-torrc','/usr/share/tor/tor-service-defaults-torrc','-f','/etc/tor/torrc','--verify-config')
 except Exception:MANAGED.write_text(old);raise RuntimeError('Snowflake configuration rejected; original restored')
 run('systemctl','restart','tor@default.service')
def wait_bootstrap(seconds):
 until=time.monotonic()+seconds;last=-1
 while time.monotonic()<until:
  try:
   progress=bootstrap_progress()
   if progress!=last:print('Tor bootstrap     '+str(progress)+'%',flush=True);last=progress
   if progress==100:return True
  except (OSError,RuntimeError,AttributeError):pass
  time.sleep(2)
 return False
def bootstrap():
 if wait_bootstrap(180):return
 print('Tor unavailable: enabling bundled Snowflake',flush=True);snowflake()
 if not wait_bootstrap(240):raise RuntimeError('Tor bootstrap incomplete. No direct connection is available. Run aegis-server doctor.')
def onion():
 value=(P(P('/etc/aegis/onion-directory').read_text().strip())/'hostname').read_text().strip()
 if not re.fullmatch('[a-z2-7]{56}\\.onion',value):raise RuntimeError('Onion service hostname not ready')
 return value
def doctor():
 errors=[]
 def check(name,fn):
  try:
   result=fn()
   if result is False:raise RuntimeError('проверка не пройдена')
   print(f'{name:<22} {result if isinstance(result,str) else "OK"}')
  except Exception as e:errors.append(name);print(f'{name:<22} ERROR: {e}')
 c=config()
 check('Java 21',lambda:'21.' in run('/opt/aegis/relay/runtime/bin/java','-version').stderr)
 check('AEGIS Relay',lambda:run('systemctl','is-active','--quiet','aegis-relay.service').returncode==0)
 check('Configuration',lambda:run('runuser','-u','aegis-relay','--','/opt/aegis/relay/bin/relay-server','version',str(CONF)).returncode==0)
 def rights():
  for path,owner,group,mode in [('/etc/aegis','root','aegis-relay',0o750),(str(CONF),'root','aegis-relay',0o640),('/var/lib/aegis-relay','aegis-relay','aegis-relay',0o700)]:
   s=P(path).stat()
   if (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(pwd.getpwnam(owner).pw_uid,grp.getgrnam(group).gr_gid,mode):raise RuntimeError(path+' has wrong owner or permissions')
  return True
 check('Permissions',rights)
 def database():
  with sqlite3.connect('file:'+c['databasePath']+'?mode=ro',uri=True) as db:
   if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('SQLite integrity check failed')
  return True
 check('Database',database)
 def listener():
  port=int(c.get('listenPort','19110'));addresses=[line.split()[3] for line in run('ss','-H','-ltn').stdout.splitlines() if line.split()[3].endswith(':'+str(port))]
  if addresses!=['127.0.0.1:'+str(port)]:raise RuntimeError('Expected loopback only; observed '+str(addresses))
  return True
 check('127.0.0.1:19110',listener)
 check('Tor instance',lambda:run('systemctl','is-active','--quiet','tor@default.service').returncode==0)
 def readiness():
  n=bootstrap_progress()
  if n!=100:raise RuntimeError('bootstrap '+str(n)+'%')
  return '100%'
 check('Tor bootstrap',readiness);check('Snowflake config',lambda:bool(bridges()));check('Onion service',lambda:bool(onion()))
 def firewall():
  data=run('ufw','status','verbose').stdout
  if 'Status: active' not in data or 'deny (incoming)' not in data:raise RuntimeError('UFW inactive or incoming policy not deny')
  if re.search(r'^19110(?:/tcp)?\s+ALLOW',data,re.M):raise RuntimeError('Remove public UFW allow rule for 19110')
  return True
 check('Firewall',firewall);check('Autostart',lambda:all(run('systemctl','is-enabled','--quiet',unit).returncode==0 for unit in ['aegis-relay.service','tor@default.service','aegis-tor-bootstrap.service']))
 if errors:raise RuntimeError('Failed: '+', '.join(errors))
def main():
 cmd=sys.argv[1] if len(sys.argv)>1 else 'doctor'
 if cmd in ['start','stop','restart','status']:subprocess.run(['systemctl',cmd,'aegis-relay.service'],check=True)
 elif cmd in ['stats','health','cleanup','version']:subprocess.run(['runuser','-u','aegis-relay','--','/opt/aegis/relay/bin/relay-server',cmd,str(CONF)],check=True)
 elif cmd=='doctor':doctor()
 elif cmd=='onion':print(onion())
 elif cmd=='bootstrap':bootstrap()
 elif cmd=='configure-tor':tor_configuration()
 elif cmd=='snowflake':snowflake()
 else:raise RuntimeError('Commands: doctor start stop restart status stats health cleanup version onion bootstrap snowflake')
if __name__=='__main__':
 try:main()
 except Exception as e:print('AEGIS: '+str(e),file=sys.stderr);sys.exit(1)
