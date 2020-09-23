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
"""Interacts with Nmap's scan and Metasploit's module for LibSSH"""


from logger import LogData
from constants import NMAP_PROBES


class LibSSH:
    @staticmethod
    def greeting():
        log = LogData("probe", "low", "potential", "nmap")
        return b'SSH-2.0-libssh-0.8.3\r\n', log

    @staticmethod
    def identify_and_respond(client_packet: bytes):
        if client_packet == b"SSH-2.0-Ruby/Net::SSH_5.2.0 x86_64-linux-gnu\r\n":
            log = LogData("exploitation", "high", "potential", "metasploit")
            return None, log
        elif client_packet in NMAP_PROBES:
            return LibSSH.greeting()
