#!/usr/bin/env python3
"""Technical resizing of the supplied image; no redesign or generated artwork."""
from pathlib import Path
from PIL import Image
root=Path(__file__).resolve().parents[1];im=Image.open(root/'resources/icon-original.png').convert('RGBA');side=max(im.size);canvas=Image.new('RGBA',(side,side),(0,0,0,255));canvas.alpha_composite(im,((side-im.width)//2,(side-im.height)//2));target=root/'client-ui/src/main/resources/org/securemail/ui/icons';target.mkdir(parents=True,exist_ok=True)
for n in [16,24,32,48,64,128,256]:canvas.resize((n,n),Image.Resampling.LANCZOS).save(target/f'icon-{n}.png')
canvas.resize((256,256),Image.Resampling.LANCZOS).save(root/'resources/icon.ico',sizes=[(n,n) for n in [16,24,32,48,64,128,256]])
canvas.resize((512,512),Image.Resampling.LANCZOS).save(root/'resources/aegis.png')
