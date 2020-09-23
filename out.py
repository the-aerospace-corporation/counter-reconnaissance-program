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
"""Print handler"""

from sys import stderr

red: str = '\033[31m'
orange: str = '\033[33m'
blue: str = '\033[34m'
green: str = '\033[32m'
end: str = '\033[0m'


class Out:
    """Prints messages to console using Msfconsole-inspired colors and format"""
    @staticmethod
    def err(message: str):
        """Prints error message to sys.stderr using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{red}[-] " + message + f"{end}", file=stderr)

    @staticmethod
    def warn(message: str):
        """Prints warning message using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{orange}[!] " + message + f"{end}")

    @staticmethod
    def norm(message: str):
        """Prints a message using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{blue}[*] " + message + f"{end}")

    @staticmethod
    def good(message: str):
        """Prints a message using Msfconsole-inspired color and format.
        :param message: Message to be printed
        """
        print(f"{green}[+] " + message + f"{end}")
