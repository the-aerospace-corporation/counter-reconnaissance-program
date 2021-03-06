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
"""Handles communications with Docker container"""

import subprocess
from typing import Union, Tuple
from out import Out
from logger import Logger
import time
from random import choice
from string import ascii_letters, digits


class __Docker:
    """Creates methods for communicating with a Docker container.

    Should not be used directly. See DockerRunning and DockerInitialize below."""
    def __init__(self, stdout: bool, log_location: str, container_name: str):
        if log_location:
            self.log: Logger = Logger(location_shell=log_location)
        else:
            self.log: Logger = Logger()
        self.log.stdout = stdout
        self.container_name: str = container_name
        self.current_location: str = "/"
        self.shell: str = "sh"

    def cmd(self, cmd: bytes, ip: str) -> (Union[bytes, None], Union[bytes, None]):
        """Sanitizes command and sends it to Docker; supports changing directory.
        :param cmd: Unsanitized command
        :param ip: IP address of the attacker
        :return: A tuple of bytes, wherein the first bytes variable is the response back to the attacker and the
        second is a command to be sent to main.py; either one could be null.
        """
        self.log.write_shell(cmd, ip, True)
        cmd = cmd[0:len(cmd) - 1]  # Strips newline character
        if cmd.isspace() or len(cmd) == 0:
            # If we set the path each time an empty command is sent, we can run into an error and throw it back to the
            # attacker, which can look suspicious
            ret_tup: Tuple[bytes, bytes] = self._raw_cmd(cmd[0:len(cmd) - 1])
            ret: bytes = ret_tup[1]
            self.log.write_shell(ret, ip, False)
            return ret
        else:
            if cmd.strip()[0:1] == b';':
                # If attacker starts his command with ";" then it should crash with a specific error, as showcased below
                unmodified_return = self._raw_cmd(cmd)[0]
                unmodified_return = unmodified_return.split(b'\n')[0] + b'\n'
                if unmodified_return.startswith(b'sh: -c: line 0:'):
                    # This portion is done for a CentOS-based Docker container. Extraneous data is received from
                    # Docker when this particular crash occurs; hence, we identify and remove it.
                    modified_return = b'sh:' + unmodified_return[15:]
                else:
                    modified_return = b'/bin/sh: 3: Syntax error: ";" unexpected'

                ret: Tuple[bytes, bytes] = (modified_return, b'CORECPROCloseConn')
            else:
                send_exit: bool = False  # Makes sure to not send any commands after the "exit" command is invoked
                # This prevents commands like these "whoami; exit; whoami" from sending back two responses
                ret = b''
                for cmd_indiv in cmd.split(b';'):
                    if cmd_indiv.strip() == b'exit':
                        send_exit = True
                        ret: Tuple[bytes, bytes] = (ret, b'CORECPROCloseConn')
                    elif not send_exit:
                        ret_pwd = self._raw_cmd(cmd_indiv + b'; echo; pwd')
                        self.current_location = ret_pwd[1].split(b'\n')[len(ret_pwd[1].split(b'\n')) - 2].decode(
                            "UTF-8")
                        ret = ret + ret_pwd[0] + ret_pwd[1][0:len(ret_pwd) - 4 - len(self.current_location)]  # -4 is
                        # for the extra newline characters

            if type(ret) is tuple:
                self.log.write_shell(ret[0], ip, False)  # Discarding second element b/c it's meant for main.py only
            else:
                self.log.write_shell(ret, ip, False)
            return ret

    def _raw_cmd(self, cmd: bytes) -> (bytes, bytes):
        """Sends commands without any input validation directly to Docker container; SHOULD NOT be used without first
        input validating the commands.

        Shortcomings:
        -If used directly, the change directory command will not function. This is abnormal behavior for the sh shell
        and will likely be noticed by attackers. This is why the cmd method exists.

        :param cmd: Unsanitized command
        :return: A tuple of bytes, wherein the first bytes variable is stderr and the second stdout"""
        docker = subprocess.run(['docker', 'exec', '-w', self.current_location, self.container_name, self.shell,
                                 '-c', cmd.decode("UTF-8")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return docker.stderr, docker.stdout


class DockerRunning(__Docker):
    """Imitates a reverse shell by connecting to a running Docker container."""

    def __init__(self, stdout: bool, log_location: str, container_name: str = "corecpro_shell"):
        super().__init__(stdout, log_location, container_name)

        rand: bytes = ''.join(choice(digits + ascii_letters) for n in range(20)).encode()
        docker_run = self._raw_cmd(b'echo ' + rand)
        if docker_run[0] != b'':
            Out.err("Failed to connect to Docker container " + self.container_name + ".")
            Out.err("SYSTEM: " + docker_run[0].decode('UTF-8'))
            raise ChildProcessError()
        elif docker_run[1][:-1] != rand:
            Out.err("Failed to verify connectivity, but no error is thrown.")
            Out.err("We sent the following command: echo " + rand.decode('UTF-8'))
            Out.err("We expected to receive: " + rand.decode('UTF-8'))
            Out.err("Instead we got: " + docker_run[1].decode('UTF-8'))
            Out.err("Please report this error.")
            raise ChildProcessError()
        else:
            Out.good("Successfully connected to Docker container " + self.container_name)


class DockerInitialize(__Docker):
    """Imitates a reverse shell by initializing a Docker container from an image."""
    def __init__(self, stdout: bool, log_location: str, image_name: str, host_name: str,
                 container_name: str = "corecpro_shell"):
        super().__init__(stdout, log_location, container_name)
        if log_location:
            self.log: Logger = Logger(location_shell=log_location)
        else:
            self.log: Logger = Logger()
        self.log.stdout = stdout
        self.image_name: str = image_name
        self.host_name: str = host_name
        self.container_name: str = container_name + "_" + str(time.time())

        docker_init = subprocess.run(['docker', 'run', '-dit', '-h', self.host_name, '--name', self.container_name,
                                      self.image_name, self.shell], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if docker_init.stderr:
            Out.err("Docker container failed to initialize.")
            Out.err("SYSTEM: " + docker_init.stderr.decode("UTF-8"))
            raise ChildProcessError()
        else:
            self.container_id: str = docker_init.stdout[0:len(docker_init.stdout) - 1].decode("UTF-8")
            Out.norm("Docker container ID  : " + self.container_id)
            Out.norm("Docker container name: " + self.container_name)
            Out.good("Docker container successfully initialized.")
