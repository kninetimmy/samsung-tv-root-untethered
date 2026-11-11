"""S3 proof-capture rehearsal (suite module): wrapped base64 at the receipted
real length must keep failing `fields()`, and the one-line normalized form
must round-trip the exact bytes (review finding 4a)."""
import base64
import json
import subprocess
import sys
from pathlib import Path

from driver_shim import BASH, bash, p

sys.path.insert(0, r'C:\Users\Kninetimmy\samtv\.memhub\prep\qn90b-uep-l4-deploy-20261109-r6')
from stage_lib import fields


def receipted_proof():
    document = json.loads((p.HERE / 'port-proof-source.json').read_text(encoding='utf-8'))
    return base64.b64decode(document['proof_base64']), document


def run():
    results = []
    proof, document = receipted_proof()
    assert len(proof) == document['proof_bytes'], 'proof length drift vs receipt'

    # the exact proto of activate.py: printf 'proof='; base64 < file
    proc = bash("printf 'proof='; base64 | tr -d '\\n'; echo")
    waved = subprocess.run([BASH, '-c', 'base64'], input=proof, capture_output=True)
    wrapped = waved.stdout.decode()
    line_count = len(wrapped.splitlines())
    assert line_count >= 20, 'the receipted proof did not wrap on this host'

    try:
        fields('proof=' + wrapped)
        raise AssertionError('wrapped proof was accepted by fields()')
    except p.Stop as error:
        p.require('malformed capture' in str(error), 'unexpected refusal text: ' + str(error))
    results.append('wrapped base64 (%d lines, %d bytes) refuses in fields() at the real proof length'
                   % (line_count, len(proof)))

    normalized = subprocess.run([BASH, '-c', "base64 | tr -d '\\n'; echo"],
                                input=proof, capture_output=True)
    out = fields('proof=' + normalized.stdout.decode())
    p.require('\n' not in out['proof'], 'one-line proof leaked newlines')
    p.require(base64.b64decode(out['proof']) == proof, 'one-line roundtrip drifted')
    results.append('one-line normalized capture round-trips the exact receipted bytes')

    docs = document['boot']
    p.require(len(docs) == 36, 'receipt boot malformed')
    results.append('receipt provenance intact (boot ' + docs + ')')
    return results
