import os
import pytest

from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
from constants_for_test import PW1_TEST4
from rsa_keys import rsa_pk


def test_change_pw1_fault_preserves_old_private_key(card):
    """AK-DUR-012: failed PW1/DEK transaction preserves old private-key usability."""
    if not os.environ.get("PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE"):
        pytest.skip("fault-injection-only test")

    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    template = rsa_pk.key_list[0].build_privkey_template(card.is_yubikey)
    assert card.cmd_put_data_odd(0x3F, 0xFF, template)

    with pytest.raises(ValueError):
        card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST4)

    assert card.verify(1, FACTORY_PASSPHRASE_PW1)
    digestinfo = rsa_pk.compute_digestinfo(rsa_pk.test_vector["sign_0"])
    signature = card.cmd_pso(0x9E, 0x9A, digestinfo)
    assert rsa_pk.key_list[0].verify_signature(digestinfo, signature)
