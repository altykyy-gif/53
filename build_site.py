#!/usr/bin/env python3
"""usage: python3 build_site.py 33333.mdb template.html index.html [passphrase]
needs: mdbtools (mdb-export) + pip install cryptography"""
import sys, csv, io, json, gzip, os, re, secrets, subprocess, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
mdb, tpl, out = sys.argv[1:4]
pw = sys.argv[4] if len(sys.argv) > 4 else '-'.join(secrets.token_hex(2) for _ in range(4))
TABLES = ['empolye','NESAB','repot','TAMAM_ARC','Descunt','work_end','Proced','ivi_del','SCHOOLS','BIAN']  # users/adm/LOGIN are never exported
data = {}
for t in TABLES:
    raw = subprocess.run(['mdb-export', mdb, t], capture_output=True).stdout.decode('utf-8', 'replace')
    rows = []
    for r in csv.DictReader(io.StringIO(raw)):
        r = {k.strip(): (v or '').strip() for k, v in r.items() if k}
        if 'NAME' not in r and 'NAME1' in r:
            r['NAME'] = ' '.join(r.get(f'NAME{i}', '') for i in range(1, 5) if r.get(f'NAME{i}'))
        r = {k: v for k, v in r.items() if v != '' and not (re.fullmatch(r'd\d+', k) and v == '0')}
        if r: rows.append(r)
    data[t] = rows
    print(t, len(rows))
plain = gzip.compress(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode(), 9)
salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000).derive(pw.encode())
blob = base64.b64encode(salt + iv + AESGCM(key).encrypt(iv, plain, None)).decode()
open(out, 'w', encoding='utf-8').write(open(tpl, encoding='utf-8').read().replace('__BLOB__', blob))
print('size KB', os.path.getsize(out) // 1024)
print('PASSPHRASE:', pw)
