"""Учебная реализация DSA (FIPS 186-4), подпись файлов с SHA-256."""
from __future__ import annotations
import argparse, hashlib, json, secrets
from pathlib import Path

def is_prime(n: int) -> bool:
    if n<2:return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n==p:return True
        if n%p==0:return False
    d,s=n-1,0
    while d%2==0:d//=2;s+=1
    for _ in range(24):
        a=secrets.randbelow(n-3)+2;x=pow(a,d,n)
        if x in (1,n-1):continue
        for __ in range(s-1):
            x=x*x%n
            if x==n-1:break
        else:return False
    return True
def prime(bits: int) -> int:
    while True:
        n=secrets.randbits(bits)|(1<<(bits-1))|1
        if is_prime(n):return n
def parameters() -> tuple[int,int,int]:
    q=prime(160)
    while True:
        p=secrets.randbits(256-160)*q+1
        if p.bit_length()==256 and is_prime(p):break
    while True:
        g=pow(secrets.randbelow(p-3)+2,(p-1)//q,p)
        if g>1:return p,q,g
def generate_keys(priv:Path,pub:Path)->None:
    p,q,g=parameters();x=secrets.randbelow(q-1)+1;y=pow(g,x,p)
    priv.write_text(json.dumps({'p':p,'q':q,'g':g,'x':x},indent=2)+'\n')
    pub.write_text(json.dumps({'p':p,'q':q,'g':g,'y':y},indent=2)+'\n')
def hash_file(file:Path)->int:return int.from_bytes(hashlib.sha256(file.read_bytes()).digest(),'big')
def sign(file:Path,keyfile:Path,out:Path)->None:
    k=json.loads(keyfile.read_text());p,q,g,x=(k[n] for n in ('p','q','g','x'));z=hash_file(file)
    while True:
        nonce=secrets.randbelow(q-1)+1;r=pow(g,nonce,p)%q
        if r:
            s=pow(nonce,-1,q)*(z+x*r)%q
            if s:break
    out.write_text(json.dumps({'algorithm':'DSA FIPS 186','sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'r':r,'s':s},indent=2)+'\n')
def verify(file:Path,keyfile:Path,sigfile:Path)->bool:
    k=json.loads(keyfile.read_text());sig=json.loads(sigfile.read_text());p,q,g,y=(k[n] for n in ('p','q','g','y'));r,s=sig['r'],sig['s']
    if not (0<r<q and 0<s<q):return False
    w=pow(s,-1,q);z=hash_file(file)
    return (pow(g,z*w%q,p)*pow(y,r*w%q,p)%p)%q==r
def main()->None:
    ap=argparse.ArgumentParser(description=__doc__);sp=ap.add_subparsers(dest='cmd',required=True)
    a=sp.add_parser('keygen');a.add_argument('--private',type=Path,default=Path('private.json'));a.add_argument('--public',type=Path,default=Path('public.json'))
    a=sp.add_parser('sign');a.add_argument('file',type=Path);a.add_argument('--key',type=Path,default=Path('private.json'));a.add_argument('--out',type=Path)
    a=sp.add_parser('verify');a.add_argument('file',type=Path);a.add_argument('signature',type=Path);a.add_argument('--key',type=Path,default=Path('public.json'))
    a=ap.parse_args()
    if a.cmd=='keygen':generate_keys(a.private,a.public);print('Ключи записаны.')
    elif a.cmd=='sign':sign(a.file,a.key,a.out or Path(str(a.file)+'.sig'));print('Подпись записана.')
    else:print('Подпись верна.' if verify(a.file,a.key,a.signature) else 'Подпись НЕВЕРНА.')
if __name__=='__main__':main()
