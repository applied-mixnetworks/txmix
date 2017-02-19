
from txmix import MixKeyState, EntropyReader
from test_txmix import generate_node_keypair


def test_mix_key_state():
    entropy_reader = EntropyReader()
    public_key, private_key = generate_node_keypair(entropy_reader)
    state = MixKeyState(public_key, private_key)
    assert state.public_key == public_key
    assert state.private_key == private_key
