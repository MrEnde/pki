from typing import Sequence
from typing import Tuple

from pygost.gost3410 import GOST3410Curve


PublicKey = Tuple[int, int]


def kdf_gostr3411_2012_256(key: bytes, label: bytes, seed: bytes) -> bytes: ...


def kdf_tree_gostr3411_2012_256(
        key: bytes,
        label: bytes,
        seed: bytes,
        keys: int,
        i_len: int = 1,
) -> Sequence[bytes]: ...


def keg(curve: GOST3410Curve, prv: int, pub: PublicKey, h: bytes) -> bytes: ...
