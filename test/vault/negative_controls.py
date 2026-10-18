"""Demonstrate simulator tests actually enforce the vault's security guards.

Run only in a disposable cloud checkout, never against a reader. Each mutation is
restored byte-for-byte in finally, then the restored suite must pass.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
source = ROOT / 'card/vault/NuriVault.java'
original = source.read_bytes()
mutations = [
    ('mandatory-PIN', 'if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);', 'if (false) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);', 'setup is not VERIFY'),
    ('HMAC-never-reveal', 'if (kinds[slot] != BEARER_KIND) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);', 'if (false) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);', 'RFC1 export forbidden'),
    ('fixed-slot-class', 'if (find((short) 2, nl) >= 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);', 'if (false) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);', 'class immutable on duplicate'),
]
for name, old, new, expected in mutations:
    text = original.decode()
    assert text.count(old) == 1, name
    try:
        source.write_text(text.replace(old, new, 1))
        broken = subprocess.run(['bash', str(ROOT / 'scripts/test-vault-sim.sh')], capture_output=True, text=True, cwd=ROOT)
        output = broken.stdout + broken.stderr
        print(output, end='')
        assert broken.returncode != 0 and expected in output, (name, broken.returncode, output)
        print('VAULT_NEGATIVE_CONTROL_RED', name, 'exit=' + str(broken.returncode))
    finally:
        source.write_bytes(original)
    restored = subprocess.run(['bash', str(ROOT / 'scripts/test-vault-sim.sh')], cwd=ROOT)
    assert restored.returncode == 0, name
    assert source.read_bytes() == original
    print('VAULT_NEGATIVE_CONTROL_RESTORED_GREEN', name, flush=True)
