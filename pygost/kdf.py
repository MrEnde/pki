# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2022 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Key derivation functions, Р 50.1.113-2016, Р 1323565.1.020-2018
"""

import hmac

from pygost.gost3410_vko import kek_34102012256
from pygost.gost3410_vko import kek_34102012512
from pygost.gost34112012256 import GOST34112012256
from pygost.utils import bytes2long
from pygost.utils import long2bytes


def kdf_gostr3411_2012_256(key, label, seed):
    """KDF_GOSTR3411_2012_256

    :param bytes key: initial key
    :param bytes label: label
    :param bytes seed: seed
    :returns: 32 bytes
    """
    return hmac.new(
        key=key,
        msg=b"".join((b"\x01", label, b"\x00", seed, b"\x01\x00")),
        digestmod=GOST34112012256,
    ).digest()


def kdf_tree_gostr3411_2012_256(key, label, seed, keys, i_len=1):
    """KDF_TREE_GOSTR3411_2012_256

    :param bytes key: initial key
    :param bytes label: label
    :param bytes seed: seed
    :param int keys: number of generated keys
    :param int i_len: length of iterations value (called "R")
    :returns: list of 256-bit keys
    """
    keymat = []
    _len = long2bytes(keys * 32 * 8, size=1)
    for i in range(keys):
        keymat.append(hmac.new(
            key=key,
            msg=b"".join((long2bytes(i + 1, size=i_len), label, b"\x00", seed, _len)),
            digestmod=GOST34112012256,
        ).digest())
    return keymat


def keg(curve, prv, pub, h):
    """Export key generation (Р 1323565.1.020-2018)

    :param GOST3410Curve curve: curve to use
    :param long prv: private key
    :param pub: public key
    :type pub: (long, long)
    :param bytes h: "h"-value, 32 bytes
    """
    if len(h) != 32:
        raise ValueError("h must be 32 bytes long")
    ukm = bytes2long(h[:16])
    if ukm == 0:
        ukm = 1
    if curve.point_size == 64:
        return kek_34102012512(curve, prv, pub, ukm)
    k_exp = kek_34102012256(curve, prv, pub, ukm)
    return b"".join(kdf_tree_gostr3411_2012_256(k_exp, b"kdf tree", h[16:24], 2))
