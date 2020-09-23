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
"""Responds to Samba packets"""


import struct
import sys
from typing import Union

from logger import LogData
from out import Out
from samba_deception.constants import *
from samba_deception.docker import Docker
from samba_deception.smb1 import Smb1
from samba_deception.utils import Utils


class Samba:
    def __init__(self, hostname: str, workgroup_name: str):
        self.logged_in: list = list()
        self.failed_login: bool = False
        self.session_key: int = 1
        self.packet: bytes = b''
        self.client_port: int = -1  # Used for Metasploit shell deception
        try:
            self.hostname: str = hostname
            self.workgroup_name: str = workgroup_name
        except (AttributeError, TypeError):
            Out.err("Samba: The workgroup and host names must be strings. Shutting down.")
            sys.exit(1)

        self.current_dir: str = ""
        self.bind: bool = False  # If false, NetShareEnumAll is requested; if true, Bind packet was received.
        self.info: str = ""  # Used for NetShareGetInfo; if data, will give info on data; if ipc, info on ipc, etc.
        self.files: dict = dict()
        self.call_id: bytes = b''  # Used for NetShare-messages; Default--Nmap 'AAAA', Metasploit '0000'
        self.payload: bytes = b''  # Stores malicious payloads sent by Nmap/Metasploit; stored to verify later
        self.packet_to_reassemble: bytes = b''  # Stores packets that may be fragmented and sent out of order
        self.exploited: list = list()  # This is used to deceive Metasploit shell and is tied to a specific client port
        self.log_interaction = LogData("interaction", "info", "N/A", "unknown")  # Default log, used frequently
        self.log_nmap = LogData("vulnerability scan", "medium", "confirmed", "nmap")  # Default log, used frequently
        self.log_metasploit = LogData("exploitation", "high", "confirmed", "metasploit")  # Default log, used frequently

    def identify_and_respond(self, packet: bytes, ip_port: (str, int), docker: Union[None, Docker]) -> (bytes, LogData):
        """Identifies and responds to SMB packets from Nmap and Metasploit

        :param ip_port: Client IP address and port, where ip[0] is their IP address and ip[1] is their port
        :param packet: Packet to identify
        :param docker: Docker object to use when sending reverse shell data
        :return: tuple of the response, in bytes, and a LogData object
        """
        self.packet = packet
        self.client_port = ip_port[1]
        log_error_small = LogData("interaction", "info", "N/A", "unknown", "Packet is too small to be an SMB packet",
                                  self.packet)

        # Metasploit's automatic attempt for an echo command to verify remote shell access
        if self.packet[:5] == b'\necho' and self.client_port in self.exploited:
            return b'\n' + self.packet[6:], self.log_metasploit
        elif self.client_port in self.exploited:
            return docker.cmd(self.packet, ip_port[0]), self.log_metasploit
        elif len(self.packet) < 36:  # Bad packet
            return None, log_error_small
        elif len(self.packet) < 53 and self.packet[8:9] == b'\x72':  # Bad packet
            return None, log_error_small
        elif self.packet[8:9] == b'\x72':  # Negotiate Protocol Request
            return self.__id_npr()
        elif self.packet[8:9] == b'\x73':  # Session Setup AndX Request
            return self.__id_saxr()
        elif self.packet[8:9] == b'\x74':  # Logoff AndX Request
            return self.__logoff(), self.log_interaction
        elif self.client_port in self.logged_in:
            if self.packet[8:9] == b'\x75':  # Tree Connect AndX Request
                return self.__id_treecon()
            elif self.packet[8:9] == b'\xa2':  # NT Create AndX Request
                return self.__id_create()
            elif self.packet[8:9] == b'\x2f':  # Write AndX Request
                if struct.unpack(">H", self.packet[2:4])[0] > len(self.packet) - 4:  # If the data is fragmented
                    self.packet_to_reassemble = self.packet
                    return None, self.log_interaction
                return self.__id_write()
            elif self.packet[8:9] == b'\x2e':  # Read AndX Request
                return self.__id_read()
            elif self.packet[8:9] == b'\x2d' and self.packet[36:67] == MSF_OPEN_ANDX_REQUEST[36:67]:
                return self.__open_andx_response(), self.log_interaction
            elif self.packet[8:9] == b'\x32' and self.packet[36:] == MSF_TRANS2_REQUEST[36:]:
                return self.__trans2_response_empty(), self.log_interaction
            elif self.packet[8:9] == b'\x71':
                return self.__tree_disconnect(), self.log_interaction
            elif self.packet[8:9] == b'\x04':
                return self.__close(), self.log_interaction
            elif self.packet[8:9] == b'\x06':
                return self.__delete(self.packet[42:]), self.log_interaction
            else:
                return self.__write_reassembler()
        else:
            log = LogData("interaction", "info", "N/A", "unknown", "Unknown data received. Please report this error.",
                          self.packet)
            return None, log

    def __write_reassembler(self) -> (bytes, LogData):
        if len(self.packet_to_reassemble) != 0 \
                and self.packet_to_reassemble[8:9] == b'\x2f':  # Write AndX Request
            self.packet = self.packet_to_reassemble + self.packet
            if struct.unpack(">H", self.packet[2:4])[0] == len(self.packet) - 4:
                self.packet_to_reassemble = b''
                return self.__id_write()
            elif struct.unpack(">H", self.packet[2:4])[0] > len(self.packet) - 4:
                self.packet_to_reassemble = self.packet
                return None, self.log_interaction
            else:
                log = LogData("interaction", "info", "N/A", "unknown",
                              "Write AndX Request packet received but reassembly failed. Please report this "
                              "error.", self.packet)
                return None, log
        else:
            log = LogData("interaction", "info", "N/A", "unknown",
                          "Unknown data received. Please report this error.",
                          self.packet)
            return None, log

    def __id_npr(self) -> (bytes, LogData):
        if self.packet[0:30] == INIT_NPR[0:30] and self.packet[32:53] == INIT_NPR[32:53]:
            return self.__init_npr(), self.log_interaction
        # Extended Security is requested
        elif self.packet[0:15] == INIT_NPR[0:15] \
                and self.packet[15:16] == b'\x68' \
                and self.packet[16:30] == INIT_NPR[16:30] \
                and self.packet[32:53] == INIT_NPR[32:53]:
            return self.__es_npr(), self.log_interaction
        elif self.packet[4:30] == MSF_INIT_NPR[4:30] \
                and self.packet[32:34] == MSF_INIT_NPR[32:34] \
                and self.packet[36:] == MSF_INIT_NPR[36:]:
            return self.__msf_npr(), self.log_interaction
        # If we don't know what's going on, we log it just in case
        else:
            log = LogData("interaction", "info", "N/A", "unknown",
                          "Received a Negotiate Protocol Request, but not from Metasploit nor Nmap; this could be a "
                          "genuine client connection or a custom script.", self.packet)
            return None, log

    def __id_saxr(self) -> (bytes, LogData):
        if self.packet[-19:-1] == b'Nmap\0Native Lanman':
            # CONFIRMED: Beginning of Nmap Script Scan; login failure
            utils = Utils
            if utils.identify_user(self.packet) == b'guest':
                # Logon attempted with account name "guest." This must fail.
                return self.__init_saxr_1(), self.log_nmap
            elif self.packet[9:13] == b'\x6d\0\0\xc0' and self.failed_login:
                return self.__init_saxr_2(), self.log_nmap
            else:
                log = LogData("interaction", "info", "N/A", "Nmap",
                              "SMB packet received from Nmap, but packet not recognized. Please report this error.",
                              self.packet)
                return None, log
        elif self.packet[-20:-2] == b'Nmap\0Native Lanman':
            # CONFIRMED: Continued Nmap Script Scan, this should not fail
            if self.packet[51:] == ES_SAXR1[51:]:
                return self.__es_saxr_1(), self.log_nmap

            elif self.packet[51:] == ES_SAXR2[51:]:
                return self.__es_saxr_2(), self.log_nmap

            else:
                log = LogData("interaction", "info", "N/A", "nmap",
                              "SMB packet received from Nmap, but login is invalid. This is potentially due to a bug "
                              "in Nmap 7.80.",
                              self.packet)
                return self.__logon_failure(), log
        # Metasploit-like exploit attempts
        elif self.packet[13:16] == b'\x18\x01\x28' \
                and self.packet.endswith(b'Windows 2000 2195\0Windows 2000 5.0\0') \
                and self.packet[-51:-35].isalnum() \
                and self.packet[-52:-51] == b'.':
            return self.__msf_saxr_1(), self.log_interaction
        elif self.packet[13:16] == b'\x18\x01\x28' \
                and self.packet[-69:-67] == b'.\0' \
                and self.packet[-67:-35]. \
                decode('utf-16').isalnum():
            return self.__msf_err(), self.log_interaction
        elif self.packet[13:16] == b'\x18\x01\x20' \
                and self.packet.endswith(b'.\x00Windows 2000 2195\x00Windows 2000 5.0\0'):
            return self.__msf_saxr_2(), self.log_interaction
        else:
            host_identity_location = struct.unpack("<H", self.packet[51:53])[0] + 63
            host_identity = self.packet[host_identity_location:]
            log = LogData("interaction", "info", "N/A", "unknown",
                          "Unknown connection on Samba, potential identity: " + host_identity.decode('ascii'),
                          self.packet)
            return None, log

    def __id_treecon(self) -> (bytes, LogData):
        if self.packet.endswith(b'\\IPC$\0?????\0'):
            return self.__tree_connected("IPC$"), self.log_interaction
        elif self.packet.endswith(b'\\data\0?????\0'):
            return self.__tree_connected("data"), self.log_interaction
        elif self.packet.endswith(b'nmap-share-test\0?????\0'):
            return self.__tree_connect_failure(), self.log_nmap
        else:
            # Grabbing path name but starting at the end of the password; we find the end of the password using the
            # password length at [43:45]
            path = str(self.packet[47 + struct.unpack('<H', self.packet[43:45])[0]:].split(b'\0')[0])
            log = LogData("interaction", "info", "N/A", "unknown",
                          "Client attempted a connection on an unknown path \"" + path + "\". Please report this " +
                          "error.", self.packet)
            return self.__tree_connect_failure(), log

    def __id_create(self) -> (bytes, LogData):
        if self.current_dir == "IPC$":
            if self.packet.endswith(b'\\srvsvc\0'):
                return self.__create_existed(), self.log_interaction
            elif self.packet.endswith(b'nmap-test-file\0'):
                return self.__create_failure(), self.log_nmap
            elif self.packet.endswith(b'2test.so\0') and self.payload == NMAP_EXPLOIT:
                return b'CORECPROCloseConn', self.log_nmap
            elif self.payload == MSF_EXPLOIT:
                self.exploited.append(self.client_port)
                return self.__create_path_invalid(), self.log_metasploit
            else:
                # This should only be an interaction as Nmap and Metasploit send exploits that do not work; do not
                # change this
                return self.__create_failure(), self.log_interaction
        elif self.current_dir == "data":
            if self.packet.endswith(b'nmap-test-file\0'):
                return self.__create_new(), self.log_nmap
            else:
                return self.__create_new(), self.log_interaction
        else:
            log = LogData("interaction", "info", "N/A", "unknown",
                          "This part of the code should not be reached. Please report this error. Method: __id_create",
                          self.packet)
            return None, log

    def __id_write(self) -> (bytes, LogData):
        if self.current_dir == "IPC$":
            if self.packet[67:139] == BIND[67:139] or self.packet[67:139] == MSF_BIND[67:139]:
                self.bind = True
                return self.__write(), self.log_interaction
            elif self.packet.endswith(NETSHARE_ENUM_ALL[137:]):
                self.bind = False
                self.info = "all"
                return self.__write(), self.log_nmap
            elif self.packet.endswith(GET_INFO_IPC[139:]):
                self.bind = False
                self.info = "IPC$"
                return self.__write(), self.log_interaction
            elif self.packet[79:83] == NMAP_GET_INFO_DATA[79:83] \
                    and self.packet[91:95] == NMAP_GET_INFO_DATA[91:95] \
                    and self.packet[89:91] == NMAP_GET_INFO_DATA[89:91] \
                    and self.packet.endswith(NMAP_GET_INFO_DATA[-28:]):
                self.bind = False
                self.info = "data"
                return self.__write(), self.log_interaction
            elif self.packet[89:91] == MSF_GET_INFO_DATA[89:91] \
                    and self.packet.endswith(NMAP_GET_INFO_DATA[-28:]):
                self.bind = False
                self.info = "data"
                return self.__write(), self.log_interaction
            elif len(self.packet) > 91 and self.packet[89:91] == b'\x0f\x00':
                self.bind = False
                self.info = "all"
                return self.__write(), self.log_interaction
            else:  # In Metasploit exploitation, occasionally a random write request turns up. We respond here.
                return self.__write(), self.log_interaction
        elif self.current_dir == "data":
            self.payload = self.packet[67:]
            return self.__write(), self.log_interaction
        else:
            log = LogData("interaction", "info", "N/A", "unknown",
                          "This part of the code should not be reached. Please report this error. Method: __id_write",
                          self.packet)
            return None, log

    def __id_read(self) -> (bytes, LogData):
        if len(self.packet) == 63:
            if self.bind:  # bind_ack requested
                if self.packet[36:41] == READ_ANDX_REQUEST[36:41] and self.packet.endswith(READ_ANDX_REQUEST[43:63]):
                    return self.__bind_ack(), self.log_interaction  # Nmap requested bind_ack
                elif self.packet[36:41] == MSF_READ_ANDX_REQUEST[36:41] \
                        and self.packet.endswith(MSF_READ_ANDX_REQUEST[43:63]):
                    return self.__bind_ack(), self.log_interaction  # Metasploit requested bind_ack
            else:  # NetShareGetInfo requested
                if self.packet[36:41] == READ_ANDX_REQUEST[36:41] \
                        and self.packet[43:47] == READ_ANDX_REQUEST[43:47] \
                        and self.packet[47:51] == b'\x01\x10\x01\x10' \
                        and self.packet.endswith(READ_ANDX_REQUEST[51:63]):  # Nmap requested NetShareGetInfo
                    if self.info == "IPC$":
                        return self.__netshare_get_info(True), self.log_interaction
                    elif self.info == "data":
                        return self.__netshare_get_info(), self.log_interaction
                    elif self.info == "all":
                        return self.__netshare_enum_all(), self.log_interaction
                    else:
                        log = LogData("interaction", "info", "N/A", "unknown",
                                      "Received an Nmap Read AndX packet but unable to recognize the requested info. "
                                      "Please report this error. Method: __id_read", self.packet)
                        return None, log
                if self.packet[36:41] == MSF_READ_ANDX_REQUEST[36:41] \
                        and self.packet.endswith(MSF_READ_ANDX_REQUEST[43:63]):  # Metasploit requested NetShareGetInfo
                    if self.info == "data":
                        return self.__msf_netshare_get_info(), self.log_interaction
                    elif self.info == "all":
                        return self.__msf_netshare_enum_all(), self.log_interaction
                    else:
                        log = LogData("interaction", "info", "N/A", "unknown",
                                      "Received a Metasploit Read AndX packet but unable to recognize the requested "
                                      "info. Please report this error. Method: __id_read", self.packet)
                        return None, log
        else:
            log = LogData("interaction", "info", "N/A", "unknown",
                          "Received a Read AndX packet but unable to recognize it. Please report this error. "
                          "Method: __id_read", self.packet)
            return None, log

    def __init_npr(self) -> bytes:
        smb = Smb1
        self.session_key = self.session_key + 1

        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, False,
                                                   smb.negotiate_protocol_response(
                                                       self.session_key - 1, smb.npr_attachment_basic(
                                                           self.workgroup_name, self.hostname), 0)))

    def __init_saxr_1(self, custom_flag1: bytes = None, custom_flag2: bytes = None) -> bytes:
        smb = Smb1
        # Logon attempted with account name "guest." This must fail.
        self.failed_login = True
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, False, smb.empty(), nt_status=b'\x6d\0\0\xc0',
                                                   flags1=custom_flag1, flags2=custom_flag2))

    def __init_saxr_2(self) -> bytes:
        smb = Smb1
        utils = Utils
        self.failed_login = False  # Resetting for future portions of the script scan
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, False,
                                                   smb.session_andx_response(self.workgroup_name),
                                                   user_id=utils.rand_num_gen(2)))

    def __msf_saxr_1(self) -> bytes:
        smb = Smb1
        utils = Utils
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.session_andx_response(
            self.workgroup_name, more_proc_req=True, security_blob=smb.sess_andx_security_blob
            (self.hostname, True, metasploit=True)), user_id=utils.rand_num_gen(2),
                                                   nt_status=b'\x16\0\0\xc0', flags1=b'\x88', flags2=b'\x03\x48'))

    def __msf_saxr_2(self) -> bytes:
        smb = Smb1
        utils = Utils
        self.logged_in.append(self.client_port)
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.session_andx_response(
            self.workgroup_name, security_blob=smb.sess_andx_security_blob()), flags1=b'\x88', flags2=b'\x03\x48',
                                                   user_id=utils.rand_num_gen(2)))

    def __msf_err(self) -> bytes:
        smb = Smb1
        # Logon attempted with account name "guest." This must fail.
        self.failed_login = True
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, False, smb.empty(), nt_status=b'\x6d\0\0\xc0',
                                                   flags1=b'\x88', flags2=b'\x03\x48'))

    def __logoff(self) -> bytes:
        smb = Smb1
        self.logged_in.remove(self.client_port)
        self.failed_login = False
        self.current_dir = ""
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, False, smb.logoff_andx_response()))

    def __es_npr(self, custom_flag1: bytes = None, custom_flag2: bytes = None, index: int = 0) -> bytes:
        smb = Smb1
        self.session_key = self.session_key + 1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.negotiate_protocol_response(
            self.session_key - 1, smb.npr_attachment_ex_sec(self.hostname), index, True), flags1=custom_flag1,
                                                   flags2=custom_flag2))

    def __msf_npr(self) -> bytes:
        smb = Smb1
        self.session_key = self.session_key + 1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.negotiate_protocol_response(
            self.session_key - 1, smb.npr_attachment_ex_sec(self.hostname), 2, True), flags1=b'\x88',
                                                   flags2=b'\x01\x28'))

    def __es_saxr_1(self, custom_flag1: bytes = None, custom_flag2: bytes = None, metasploit: bool = False) -> bytes:
        smb = Smb1
        utils = Utils
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.session_andx_response(
            self.workgroup_name, more_proc_req=True, security_blob=smb.sess_andx_security_blob(
                self.hostname, True, metasploit=metasploit)), user_id=utils.rand_num_gen(2),
                                                   nt_status=b'\x16\0\0\xc0', flags1=custom_flag1, flags2=custom_flag2))

    def __es_saxr_2(self, custom_flag1: bytes = None, custom_flag2: bytes = None) -> bytes:
        smb = Smb1
        self.logged_in.append(self.client_port)
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.session_andx_response(
            self.workgroup_name, security_blob=smb.sess_andx_security_blob()), flags1=custom_flag1,
                                                   flags2=custom_flag2))

    def __tree_connected(self, location) -> bytes:
        smb = Smb1
        utils = Utils
        self.current_dir = location
        if location == "IPC$":
            ipc = True
        else:
            ipc = False
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.tree_andx_response(ipc),
                                                   tree_id=utils.rand_num_gen(2)))

    def __tree_connect_failure(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty(), nt_status=b'\xcc\0\0\xc0'))

    def __tree_disconnect(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty()))

    def __create_existed(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.create_andx_response()))

    def __create_new(self) -> bytes:
        smb = Smb1
        utils = Utils
        fid = utils.rand_num_gen(2)
        self.files[self.packet[87:]] = fid
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.create_andx_response(True)))

    def __create_failure(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty(), nt_status=b'\x34\0\0\xc0'))

    def __create_path_invalid(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty(), nt_status=b'\x39\0\0\xc0'))

    def __write(self) -> bytes:
        smb = Smb1
        self.call_id = self.packet[79:83]
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True,
                                                   smb.write_andx_response(self.packet)))

    def __bind_ack(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.read_andx_response(smb.bind_ack(
            self.call_id))))

    def __netshare_enum_all(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True,
                                                   smb.read_andx_response(smb.netshare_enum_all(self.call_id))))

    def __msf_netshare_enum_all(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True,
                                                   smb.read_andx_response(smb.netshare_enum_all(self.call_id, True))))

    def __netshare_get_info(self, ipc: bool = False) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True,
                                                   smb.read_andx_response(smb.netshare_get_info(ipc))))

    def __msf_netshare_get_info(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True,
                                                   smb.read_andx_response(smb.netshare_get_info(False,
                                                                                                call_id=b'\0\0\0\0'))))

    def __close(self):
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty()))

    def __delete(self, filename: bytes):
        smb = Smb1
        try:
            del self.files[filename]
        except KeyError:
            Out.warn("Samba: Client attempted to delete a file that doesn't exist. Ignoring.")
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty()))

    def __trans2_response_empty(self):
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.trans2_response_empty()))

    def __open_andx_response(self) -> bytes:
        smb = Smb1
        utils = Utils
        fid = utils.rand_num_gen(2)
        self.files[self.packet[69:]] = fid
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.open_andx_response(fid)))

    def __logon_failure(self) -> bytes:
        smb = Smb1
        return smb.netbios_wrapper(smb.smb_wrapper(self.packet, True, smb.empty(), nt_status=b'\x6d\0\0\xc0'))

    def version_scan_response(self, packet) -> (bytes, LogData):
        """Used to respond to a version scan packet from Nmap

        :param packet: Packet sent by Nmap
        :return: An Nmap-parsable packet that responds with a version info for Samba.
        """
        log = LogData("version scan", "medium", "confirmed", "nmap")
        smb = Smb1
        self.session_key = self.session_key + 1
        return smb.netbios_wrapper(
            smb.smb_wrapper(packet, False, smb.negotiate_protocol_response(
                self.session_key - 1, smb.npr_attachment_basic(self.workgroup_name, self.hostname)), flags1=b'\x88',
                            flags2=b'\x03\x40')), log
