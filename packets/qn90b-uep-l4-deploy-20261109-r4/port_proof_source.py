"""Extract the receipted automatic proof (base64 unwrapped) from the spent
L2 session's identity receipt into port-proof-source.json — host-only, no TV.

The rehearsal's wrapped-base64 case uses this as the real-length proof
(bytes the TV served that boot). Provenance:
.memhub/prep/qn90b-uep-l2-20261108-r1/identity.json field 'proof'.
"""
import base64
import hashlib
import json

SRC = 'C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l2-20261108-r1/identity.json'
DST = 'C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261109-r4/port-proof-source.json'

out = json.load(open(SRC, encoding='utf-8'))['output']
line = next(l for l in out.splitlines() if l.startswith('proof='))
p64 = line[len('proof='):]
data = base64.b64decode(p64)
document = {
    'source': SRC,
    'boot': next(l.split('=', 1)[1] for l in out.splitlines() if l.startswith('boot=')),
    'proof_base64': p64,
    'proof_sha256': hashlib.sha256(data).hexdigest(),
    'proof_bytes': len(data),
    'note': 'receipted proof of the spent L2 live session; r1 receipt lineage',
}
json.dump(document, open(DST, 'w', encoding='utf-8'), indent=2)
print(json.dumps({k: document[k] for k in ('boot', 'proof_sha256', 'proof_bytes')}))
