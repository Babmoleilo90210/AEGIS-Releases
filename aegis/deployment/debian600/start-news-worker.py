#!/usr/bin/env python3
"""Fixed staging launcher; config includes public endpoint/pin and key file path, no secret value."""
import base64,json,os,pathlib,re
p=pathlib.Path("/etc/aegis600/news-worker.json")
if p.is_symlink() or not p.is_file():raise SystemExit("Рабочий узел не настроен: подготовьте отдельную служебную identity и разрешённый coordinator")
c=json.loads(p.read_text())
if set(c)!={"server","serverKeyBase64","torSocksPort","workerKeyFile"}:raise SystemExit("Неверные параметры рабочего узла")
if not re.fullmatch(r"http://[a-z2-7]{56}\.onion(?::[0-9]{1,5})?/api/v1",c["server"]):raise SystemExit("Координатор доступен только через onion")
if len(base64.b64decode(c["serverKeyBase64"],validate=True))!=44 or type(c["torSocksPort"]) is not int or not 1<=c["torSocksPort"]<=65535:raise SystemExit("Закреплённый ключ или SOCKS порт неверны")
if c["workerKeyFile"]!="/var/lib/aegis600/news-worker/state/worker.pk8":raise SystemExit("Неизменный отдельный каталог рабочего узла обязателен")
os.execve("/opt/aegis600/news-worker/bin/news-worker",["news-worker","--server",c["server"],"--server-key",c["serverKeyBase64"],"--worker-key",c["workerKeyFile"],"--tor-socks",str(c["torSocksPort"])],{"PATH":"/usr/bin:/usr/sbin","LANG":"C.UTF-8"})
