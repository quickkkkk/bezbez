"""Учебная реализация электронной подписи ГОСТ Р 34.10-94.

Параметры игрушечного размера генерируются автоматически. Для реальной защиты
следует использовать сертифицированную криптографическую библиотеку.
"""
from __future__ import annotations
import argparse, hashlib, json, secrets
from pathlib import Path

def is_prime(n: int) -> bool:
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n == p: return True
        if n % p == 0: return False
    d,s=n-1,0
    while d%2==0: d//=2; s+=1
    for _ in range(24):
        a=secrets.randbelow(n-3)+2; x=pow(a,d,n)
        if x in (1,n-1): continue
        for __ in range(s-1):
            x=x*x%n
            if x==n-1: break
        else: return False
    return True

def prime(bits: int) -> int:
    while True:
        n=secrets.randbits(bits)|(1<<(bits-1))|1
        if is_prime(n): return n

def parameters() -> tuple[int,int,int]:
    q=prime(160)
    while True:
        b=secrets.randbits(256-160)
        p=b*q+1
        if p.bit_length()==256 and is_prime(p): break
    while True:
        a=secrets.randbelow(p-3)+2; g=pow(a,(p-1)//q,p)
        if g!=1: return p,q,g

def generate_keys(private_file: Path, public_file: Path) -> None:
    p,q,g=parameters(); x=secrets.randbelow(q-1)+1; y=pow(g,x,p)
    private_file.write_text(json.dumps({'p':p,'q':q,'g':g,'x':x},indent=2)+'\n')
    public_file.write_text(json.dumps({'p':p,'q':q,'g':g,'y':y},indent=2)+'\n')

def digest(path: Path, q: int) -> int:
    # SHA-256, усечённый до разрядности q, как требуется схемой.
    return int.from_bytes(hashlib.sha256(path.read_bytes()).digest(),'big') % q or 1

def sign(path: Path, key_path: Path, out: Path) -> None:
    k=json.loads(key_path.read_text()); p,q,g,x=(k[n] for n in ('p','q','g','x')); h=digest(path,q)
    while True:
        z=secrets.randbelow(q-1)+1; r=pow(g,z,p)%q
        if not r: continue
        s=(x*r+z*h)%q
        if s: break
    out.write_text(json.dumps({'algorithm':'GOST R 34.10-94','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'r':r,'s':s},indent=2)+'\n')

def verify(path: Path, key_path: Path, sig_path: Path) -> bool:
    k=json.loads(key_path.read_text()); sig=json.loads(sig_path.read_text()); p,q,g,y=(k[n] for n in ('p','q','g','y'))
    r,s=sig['r'],sig['s']; h=digest(path,q)
    if not (0<r<q and 0<s<q): return False
    v=pow(h,-1,q); u1=s*v%q; u2=(-r*v)%q
    return (pow(g,u1,p)*pow(y,u2,p)%p)%q==r

def main() -> None:
    ap=argparse.ArgumentParser(description=__doc__); sub=ap.add_subparsers(dest='cmd',required=True)
    g=sub.add_parser('keygen'); g.add_argument('--private',type=Path,default=Path('private.json')); g.add_argument('--public',type=Path,default=Path('public.json'))
    s=sub.add_parser('sign'); s.add_argument('file',type=Path); s.add_argument('--key',type=Path,default=Path('private.json')); s.add_argument('--out',type=Path)
    v=sub.add_parser('verify'); v.add_argument('file',type=Path); v.add_argument('signature',type=Path); v.add_argument('--key',type=Path,default=Path('public.json'))
    a=ap.parse_args()
    if a.cmd=='keygen': generate_keys(a.private,a.public); print('Ключи записаны.')
    elif a.cmd=='sign': sign(a.file,a.key,a.out or Path(str(a.file)+'.sig')); print('Подпись записана.')
    else: print('Подпись верна.' if verify(a.file,a.key,a.signature) else 'Подпись НЕВЕРНА.')
if __name__=='__main__': main()
