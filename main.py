#!/usr/bin/env python3
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
"""CORECPRO's main class; handles sockets and command flags."""


import getopt
import selectors
import socket
import sys
import traceback
import types
import os
import binascii
from out import Out
from constants import *
from samba_deception.samba import Samba
from samba_deception.docker import DockerRunning, DockerInitialize
from libssh import LibSSH
from logger import Logger, LogData
from typing import Union


class CoRecPro:
    """
    COunter REConnaissance PROgram is a honeypot utility designed to detect and deceive
    Nmap scanning attempts and detect and provide high interactivity to exploitation attempts.
    """

    def __init__(self, hostname: str = binascii.b2a_hex(os.urandom(6)).decode("UTF-8"),
                 workgroup_name: str = "workgroup"):
        self.docker: Union[None, Docker] = None  # Used to run a Docker container at the start of CORECPRO; prevents
        # abnormal loading times for a Metasploit reverse shell
        self.samba_dict = dict()
        self.hostname: str = hostname
        self.workgroup_name: str = workgroup_name
        self.log = Logger()
        self.event: str = ""  # Last log written
        self.last_event_time: float = 0.0  # Last time a log was written; epoch, utc
        self.cool_down: int = 30  # Cool down between identical logs in seconds
        self.ssh_port: int = 2222
        self.smb_port: int = 4445

    def accept_conn(self, sock: socket, sel: selectors):
        conn, addr = sock.accept()
        conn.setblocking(False)
        port = conn.getsockname()[1]
        data = types.SimpleNamespace(addr=addr, port=port, inb=b'', outb=b'')
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        sel.register(conn, events, data=data)
        self.greeting(conn)  # If the service requires a banner to be sent after 3-way handshake (e.g., libSSH),
        # say hello

    def greeting(self, conn):
        """Sends a greeting to the Nmap NULL probe; used for services that send a banner after a 3-way handshake,
        like libSSH"""
        port = conn.getsockname()[1]
        if port == self.ssh_port:
            out, log_data = LibSSH.greeting()
            self.log.write(log_data, conn.getsockname()[0], conn.getsockname()[1])
            conn.sendall(out)

    def deceive_conn(self, key, mask, sel):
        sock = key.fileobj
        data = key.data
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(BUFFER_SIZE)  # Should be ready to read
            if data.port == self.ssh_port and recv_data:
                data.outb, log_data = LibSSH.identify_and_respond(recv_data)
                self.log.write(recv_data, data.addr[0], data.port)
            elif data.port == self.smb_port:
                if recv_data == PROBE_SMB_PROG_NEG:
                    smb = self.get_smb(data.addr)
                    data.outb, log_data = smb.version_scan_response(recv_data)
                    self.log.write(log_data, data.addr[0], data.port)
                elif recv_data:
                    smb = self.get_smb(data.addr)
                    data.outb, log_data = smb.identify_and_respond(recv_data, data.addr, self.docker)
                    self.log.write(log_data, data.addr[0], data.port)
                else:
                    sel.unregister(sock)
                    sock.close()
            elif recv_data:
                unknown = LogData("interaction", "info", "N/A", "confirmed", "Received unknown data")
                self.log.write(unknown, data.addr[0], data.port)
                data.outb = b""
            else:
                sel.unregister(sock)
                sock.close()
        if mask & selectors.EVENT_WRITE:
            if type(data.outb) is not tuple:
                if data.outb and data.outb != b'CORECPROCloseConn':
                    sock.sendall(data.outb)  # Should be ready to write
                    data.outb = None
                elif data.outb == b'CORECPROCloseConn':
                    sel.unregister(sock)
                    sock.close()
            else:
                for response in data.outb:
                    if response != b'CORECPROCloseConn':
                        sock.sendall(response)
                    elif response == b'CORECPROCloseConn':
                        sel.unregister(sock)
                        sock.close()
                data.outb = None

    def get_smb(self, ip_addr: tuple):
        # Getting the IP address only, without the client port number.
        if type(ip_addr) is tuple:
            ip_addr = ip_addr[0]
        else:
            raise ValueError("CORECPRO-SAMBA Error: IP address in get_smb method is not a tuple when it should be; "
                             "contact the developer for assistance")

        if ip_addr in self.samba_dict:  # If Samba object has already been made, return it
            return self.samba_dict[ip_addr]
        else:  # Otherwise, make a new one and return it
            self.samba_dict[ip_addr] = Samba(self.hostname, self.workgroup_name)
            return self.samba_dict[ip_addr]


def main(argv):
    version: str = "1.0.2"
    ssh_port = None
    smb_port = None
    default_ssh_port: int = 2222
    default_smb_port: int = 4445
    docker_host_name: str = "localhost"
    docker_image: str = "centos:7"
    docker_running_container: Union[str, None] = None

    help_menu = "main.py [arguments]\n" + \
                "-v or --verbose: Dumps packet if an error occurs\n" + \
                "-o or --stdout: Prints logs to standard output in addition to a file\n" + \
                "-h or --help: Brings up this menu\n" + \
                "--logLocationMain: Specifies location wherein logs acquired for SIEM alerts are saved\n" + \
                "--logLocationShell: Specifies location wherein logs acquired from the reverse shell are saved\n" + \
                "--sshD: Disable SSH deception\n" + \
                "--smbD: Disable Samba deception\n" + \
                "--smbPort: Specify the port for Samba\n" + \
                "--smbHostName: Specify a host name to give when an attacker runs a script scan; default: " \
                "randomly generated hexadecimal\n" + \
                "--smbWorkgroupName: Specify a workgroup name to give when an attacker runs a script scan;" \
                " default: workgroup\n" + \
                "--dockerRunningContainer: Specify a Docker running container to tap into; cannot be used with " \
                "--dockerImage or --dockerHostName and attempts to do so will be ignored\n" + \
                "--dockerImage: Specify an image for Docker; default: centos:7\n" + \
                "--dockerHostName: Specify a host name to give an attacker when they get shell; " \
                "default: localhost\n"

    try:
        opts, args = getopt.getopt(argv, "haov", ["verbose", "help", "stdout", "all", "sshD", "sshPort=", "smbD",
                                                  "smbPort=", "smbHostName=", "smbWorkgroupName=", "logLocationMain=",
                                                  "logLocationShell=", "dockerRunningContainer=", "dockerHostName=",
                                                  "dockerImage="])
    except getopt.GetoptError:
        Out.err("Invalid arguments")
        print(help_menu)
        sys.exit(1)

    p = CoRecPro()
    sel = selectors.DefaultSelector()

    ssh_deception = True
    smb_deception = True
    Out.norm("Counter Reconnaissance Program V" + version)
    if len(opts) != 0:
        for opt, arg in opts:
            if opt in ("-v", "--verbose"):
                p.log.verbose = True
            elif opt in ("-h", "--help"):
                print(help_menu)
                sys.exit()
            elif opt in ("-o", "--stdout"):
                Out.norm("Will print logs to standard output")
                p.log.stdout = True
            elif opt == "--logLocationMain":
                p.log.location_main = arg
                try:
                    p.log.write_empty_main()
                except OSError:
                    Out.err("Unable to write to the given main log directory. Shutting down.")
                    sys.exit(1)
            elif opt == "--logLocationShell":
                p.log.location_shell = arg
                try:
                    p.log.write_empty_shell()
                except OSError:
                    Out.err("Unable to write to the given shell log directory. Shutting down.")
                    sys.exit(1)
            elif opt == "--sshD":
                ssh_deception = False
            elif opt == "--smbD":
                smb_deception = False
            elif opt == "--smbPort":
                try:
                    smb_port = int(arg)
                except ValueError:
                    Out.err("Samba: Port must be an integer. Shutting down")
                    sys.exit(1)
                p.smb_port = smb_port
                Out.norm("Samba port set to " + str(smb_port))
            elif opt == "--sshPort":
                try:
                    ssh_port = int(arg)
                except ValueError:
                    Out.err("libSSH: Port must be an integer. Shutting down.")
                    sys.exit(1)
                p.ssh_port = ssh_port
                Out.norm("libSSH port set to " + str(ssh_port))
            elif opt == "--smbHostName":
                for letter in arg:
                    if not letter.isalpha():
                        Out.err("Samba: The host name must only contain alphanumeric characters. Shutting down.")
                        sys.exit(1)
                p.hostname = arg
                Out.norm("Samba hostname set to: " + arg)
            elif opt == "--smbWorkgroupName":
                for letter in arg:
                    if not letter.isalpha():
                        Out.err("Samba: The workgroup name must only contain alphanumeric characters. Shutting down.")
                        sys.exit(1)
                p.workgroup_name = arg
                Out.norm("Samba workgroup set to: " + arg)
            elif opt == "--dockerRunningContainer":
                docker_running_container = arg
            elif opt == "--dockerHostName":
                if len(arg) > 64:
                    Out.err("Docker: The Docker host name must, at most, be 64 characters in length. Shutting down.")
                    sys.exit(1)
                docker_host_name = arg
            elif opt == "--dockerImage":
                docker_image = arg

        if ssh_deception:
            if ssh_port is None:
                ssh_port = default_ssh_port
            Out.norm("libSSH deception on port " + str(ssh_port) + ": " + str(ssh_deception))
        elif ssh_port and not ssh_deception:
            Out.warn("libSSH: Port set, but deception is disabled. Is this intentional?")

        if smb_deception:
            if smb_port is None:
                smb_port = default_smb_port
            Out.norm("Samba deception on port " + str(smb_port) + " : " + str(smb_deception))
        elif smb_port and not smb_deception:
            Out.warn("Samba: Port set, but deception is disabled. Is this intentional?")

    # No arguments leads us here. Both deception methods are launched.
    if len(opts) == 0:
        ssh_deception = True
        smb_deception = True
        ssh_port = default_ssh_port
        smb_port = default_smb_port
        try:
            p.log.write_empty_shell()
        except OSError:
            Out.err("Unable to write shell logs to the current directory. Shutting down.")
            sys.exit(1)

        try:
            p.log.write_empty_main()
        except OSError:
            Out.err("Unable to write SIEM logs to the current directory. Shutting down.")
            sys.exit(1)

        Out.norm("Launching with default options...")
        Out.norm("libSSH deception on port " + str(ssh_port) + ": " + str(ssh_deception))
        Out.norm("Samba deception on port " + str(smb_port) + " : " + str(smb_deception))

    if ssh_deception:
        try:
            ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_socket.bind(('', ssh_port))
            ssh_socket.listen()
            ssh_socket.setblocking(False)
            sel.register(ssh_socket, selectors.EVENT_READ)
        except Exception as ex:
            if type(ex) == OSError and ex.errno == 98:
                Out.err("libSSH: The port number "
                        + str(smb_port) + " is already taken by a different process. Shutting down.")
                sys.exit(1)
            else:
                Out.err("libSSH: An unknown error occurred when attempting to bind port " + str(ssh_port)
                        + ". Printing exception and shutting down.")
                Out.err("SYSTEM: " + "".join(traceback.TracebackException.from_exception(ex).format()))
                sys.exit(1)

    if smb_deception:
        try:
            smb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            smb_socket.bind(('', smb_port))
            smb_socket.listen()
            smb_socket.setblocking(False)
            sel.register(smb_socket, selectors.EVENT_READ)

            try:
                if docker_running_container is None:
                    Out.norm("Initializing Docker container. This might take awhile...")
                    p.docker = DockerInitialize(p.log.stdout, p.log.location_shell, docker_image, docker_host_name)
                else:
                    Out.norm("Tapping into running container...")
                    p.docker = DockerRunning(p.log.stdout, p.log.location_shell, docker_running_container)
            except ChildProcessError:
                Out.err("Samba: Deception cannot function without Docker. Shutting down.")
                sys.exit(1)

        except Exception as ex:
            if type(ex) == OSError and ex.errno == 98:
                Out.err("Samba: The port number "
                        + str(smb_port) + " is already taken by a different process. Shutting down.")
                sys.exit(1)
            else:
                Out.err("Samba: An unknown error occurred when attempting to bind port " + str(smb_port)
                        + ". Printing exception and shutting down.")
                Out.err("SYSTEM: " + "".join(traceback.TracebackException.from_exception(ex).format()))
                sys.exit(1)

    try:
        while True:
            events = sel.select()
            for key, mask in events:
                try:
                    if key.data is None:  # None means a client is attempting to connect
                        p.accept_conn(key.fileobj, sel)
                    else:
                        p.deceive_conn(key, mask, sel)
                except Exception as ex:
                    if type(ex) == ConnectionResetError:
                        # Logging any reset attempts, in case of an Nmap connect scan
                        p.log.write(LogData("interaction", "info", "N/A", "unknown"), key.data.addr[0], key.data.port)
                    else:
                        Out.warn("An exception was caught at the server loop. Printing exception and moving on.")
                        Out.warn("SYSTEM: " + "".join(traceback.TracebackException.from_exception(ex).format()))

    except KeyboardInterrupt:
        Out.good("Goodbye!")


if __name__ == "__main__":
    main(sys.argv[1:])
