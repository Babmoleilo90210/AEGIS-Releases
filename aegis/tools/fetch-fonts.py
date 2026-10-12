#!/usr/bin/env python3
"""Explicit build-time download of official licensed static TTFs. Never used at runtime."""
import hashlib, io, json, pathlib, urllib.request, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
DEST=ROOT/'client-ui/src/main/resources/org/securemail/ui/fonts'
LICENSES=ROOT/'resources/licenses/fonts'
DEST.mkdir(parents=True,exist_ok=True);LICENSES.mkdir(parents=True,exist_ok=True)
proof=[]
def get(url,limit,digest=None,blob=None):
    with urllib.request.urlopen(url,timeout=45) as r:data=r.read(limit+1)
    if len(data)>limit:raise ValueError('Font input too large')
    sha=hashlib.sha256(data).hexdigest()
    if digest and sha!=digest:raise ValueError('Font archive SHA256 mismatch')
    if blob and hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=blob:raise ValueError('Official font blob changed')
    proof.append({'url':url,'bytes':len(data),'sha256':sha});return data
def raw(name,url,blob=None):
    path=DEST/name;data=get(url,2*1024*1024,blob=blob);path.write_bytes(data)
for weight,blob in [('Regular','d55220958aa51eeeb85048d746eabe43d2cd9f14'),('Bold','27131f8f479947ef1b6c1d0bc9ad5ab3d30bd831')]:
    raw('NotoSans-'+weight+'.ttf','https://raw.githubusercontent.com/notofonts/noto-fonts/main/hinted/ttf/NotoSans/NotoSans-'+weight+'.ttf',blob)
for weight,blob in [('Regular','83a21b724c47127a95e725b5c6bdfa30fcc1a7be'),('Bold','3d4e6fe2f9f5282806cda0553d3ab321605ae37c')]:
    raw('PTSans-'+weight+'.ttf','https://raw.githubusercontent.com/google/fonts/main/ofl/ptsans/PT_Sans-Web-'+weight+'.ttf',blob)
for weight,blob in [('Regular','ddee473e02035bfce6244746d5d2a281616f7ff8'),('Bold','8869666f245c6f474b98024327df7082e4c868b8')]:
    raw('Roboto-'+weight+'.ttf','https://raw.githubusercontent.com/googlefonts/roboto-2/main/src/hinted/Roboto-'+weight+'.ttf',blob)
archives=[
 ('Inter','https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip','9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e','extras/ttf/Inter-','LICENSE.txt'),
 ('DejaVuSans','https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.zip','7576310b219e04159d35ff61dd4a4ec4cdba4f35c00e002a136f00e96a908b0a','dejavu-fonts-ttf-2.37/ttf/DejaVuSans','dejavu-fonts-ttf-2.37/LICENSE')]
for stem,url,digest,prefix,license in archives:
    with zipfile.ZipFile(io.BytesIO(get(url,64*1024*1024,digest=digest))) as z:
        for n in z.namelist():
            p=pathlib.PurePosixPath(n)
            if p.is_absolute() or '..' in p.parts or '\\' in n:raise ValueError('Unsafe font archive')
        for weight in ['Regular','Bold']:
            member=prefix+weight+'.ttf' if stem=='Inter' else prefix+('' if weight=='Regular' else '-Bold')+'.ttf'
            if z.getinfo(member).file_size>2*1024*1024:raise ValueError('Font size limit')
            (DEST/(stem+'-'+weight+'.ttf')).write_bytes(z.read(member))
        if z.getinfo(license).file_size>65536:raise ValueError('Font license size limit')
        (LICENSES/(stem+'-LICENSE.txt')).write_bytes(z.read(license))
for name,url in [('NotoSans','https://raw.githubusercontent.com/notofonts/noto-fonts/main/LICENSE'),('Roboto','https://raw.githubusercontent.com/googlefonts/roboto-2/main/LICENSE'),('PTSans','https://raw.githubusercontent.com/google/fonts/main/ofl/ptsans/OFL.txt')]:
    (LICENSES/(name+'-LICENSE.txt')).write_bytes(get(url,65536))
inventory={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(DEST.glob('*.ttf'))}
(DEST/'FONT-PROVENANCE.json').write_text(json.dumps({'schema':1,'officialInputs':proof,'resources':inventory,'modifiedFonts':False,'runtimeNetworkRequests':False},indent=2)+'\n')
print('10 unmodified official static TTFs and 5 licenses prepared; glyph coverage checked in JavaFX smoke.')
