# -*- coding: utf-8 -*-
#
# Copyright © 2020 The Aerospace Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""Various utilities for Samba"""


import time
import sys
import struct
import os
from out import Out


class Utils:

    @staticmethod
    def sys_time(epoch=time.time()) -> bytes:
        """Returns SMB-compatible time in hexadecimal format. If no argument is given, the current time is used.
        Background: SMB's time is kept in two little-endian 32-bit integers, which is read as a 64-bit signed integer
        representing the number of tenths of a microsecond since midnight of January 1, 1601.
        """

        # Multiplier for converting to tenths of a microsecond
        multiplier = 10000000

        # Seconds after January 1, 1601 until UNIX Epoch
        microsoft_epoch = 11644473600

        # Converting to signed little-endian 64-bit integer
        return struct.pack("<q", int(round((microsoft_epoch + epoch) * multiplier)))

    @staticmethod
    def rand_num_gen(length: int = 8) -> bytes:
        """Generates a random number in bytes (default length 8 bytes); used for SMB challenge and User ID generation.
        """
        try:
            output = os.urandom(length)
        except NotImplementedError:
            Out.err("Samba: Your OS does not support crypto-safe random number generation. "
                    "Samba deception will not function. Shutting down.")
            sys.exit(1)
        return bytes(output)

    @staticmethod
    def sambify_name(to_sambify: str, lower: bool = False) -> bytes:
        """SMB protocol occasionally lists names in all caps in UTF-16; this method does that

        Attributes:
            to_sambify -- string to make into the aforementioned format
            lower -- if the name must be in lowercase (rare), this should be set to true
        """
        if not lower:
            to_sambify = to_sambify.upper()
        else:
            to_sambify = to_sambify.lower()

        output = bytes(to_sambify, "utf-16")
        return output[2:]

    @staticmethod
    def identify_user(client_packet: bytes) -> bytes:
        """When encountering a Samba connection without extended security, this method can return the username with
        which Samba is attempting to connect"""
        data_split = client_packet[113:].split(sep=b'\0')
        return data_split[0]

    @staticmethod
    def identify_tree_path(client_packet: bytes) -> str:
        return str(client_packet[47 + struct.unpack('<H', client_packet[43:45])[0]:].split(b'\0')[0])
