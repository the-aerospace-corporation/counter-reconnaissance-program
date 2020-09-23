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
"""Contains packets for SMB1 protocol; used by Samba.py"""


import struct
import os  # for directory enumeration in Trans2 Response
import time  # for Open AndX response
from samba_deception.exceptions import NotNmapError
from samba_deception.utils import Utils


class Smb1:
    @staticmethod
    def netbios_wrapper(attachment: bytes, message_type: bytes = b'\0') -> bytes:
        return message_type + struct.pack(">xH", len(attachment)) + attachment

    @staticmethod
    def smb_wrapper(client_packet: bytes, extended_security: bool, attachment: bytes = b'',
                    nt_status: bytes = b'\0\0\0\0', tree_id: bytes = None, user_id: bytes = None,
                    flags1: bytes = None, flags2: bytes = None) -> bytes:

        if flags1 is None and flags2 is None:
            # Here we determine flag types; if these do not match regular Nmap script scan flags, we do not respond
            if client_packet[13:14] != b'\x18' and client_packet[13:14] != b'\x88':  # [13:14] is Flags1
                raise NotNmapError("Flags1 does not match Nmap script scan Flags1. This is NOT an Nmap scan.")
            elif client_packet[13:14] == b'\x88' and client_packet[14:16] == b'\x07\x40':  # [14:16] is Flags2
                # This only occurs when during a failed login w/o extended security where the client conducts a Session
                # Setup AndX Response. In a regular script scan, this occurs only once.
                flags1 = b'\x88'
                flags2 = b'\x07\x40'
            elif client_packet[13:14] == b'\x18' and client_packet[14:16] == b'\x01\x28':  # Metasploit
                if client_packet[8:9] == b'\x72':
                    flags1 = b'\x88'
                    flags2 = b'\x01\x28'
                else:
                    flags1 = b'\x88'
                    flags2 = b'\x03\x48'
            elif client_packet[13:14] == b'\x18' and client_packet[14:16] == b'\x01\x20':  # Metasploit
                flags1 = b'\x88'
                flags2 = b'\x03\x48'
            else:
                flags1 = b'\x88'
                if client_packet[14:16] == b'\x45\x60':  # [14:16] is Flags2
                    flags2 = b'\x07\x40'
                elif client_packet[14:16] == b'\x45\x68' and extended_security:
                    # Initial Negotiate Protocol Response when client uses extended security
                    flags2 = b'\x45\x68'
                    # Used for all other traffic with extended security
                elif client_packet[14:16] == b'\x45\x68' and not extended_security:
                    flags2 = b'\x07\x48'
                else:
                    raise NotNmapError("Flags2 does not match Nmap script scan Flags2. This is NOT an Nmap scan.")
        elif flags1 is not None and flags2 is None:
            raise TypeError("When assigning flags1, flags2 must also be assigned.")
        elif flags1 is None and flags2 is not None:
            raise TypeError("When assigning flags2, flags1 must also be assigned.")

        server_component = b'\xffSMB'
        smb_command = client_packet[8:9]
        # nt_status defined by argument
        # flags1 goes here
        # flags2 goes here
        process_id_high = b'\0\0'
        signature = client_packet[18:26]  # Determined by client; must match client.
        reserved = b'\0\0'

        if tree_id is None:
            tree_id = client_packet[28:30]  # tree_id is assigned by server; we can copy client after assignment

        process_id = client_packet[30:32]  # Determined by client; must match client.
        if user_id is None:
            user_id = client_packet[32:34]
            # User_ID is determined by the server; however, if we already gave the client a user_id we can simply
            # copy what they have, or, if one wasn't assigned yet, the client and server would both use \0\0, which
            # this accommodates for
        multiplex_id = client_packet[34:36]  # Determined by client; must match client; has value "1" iff Nmap

        return server_component + smb_command + nt_status + flags1 + flags2 + process_id_high + signature + reserved \
            + tree_id + process_id + user_id + multiplex_id + attachment

    @staticmethod
    def negotiate_protocol_response(session_key: int, attachment: bytes, index: int = 6,
                                    extended_security: bool = False) -> bytes:
        utils = Utils

        word_count = bytes([17])
        index = struct.pack("<H", index)
        security_mode = b'\x03'
        max_mpx_count = b'\x32\0'
        max_vcs = b'\x01\0'
        max_buffer_size = b'\x04\x41\0\0'
        max_raw_buffer = b'\0\0\x01\0'
        session_key = struct.pack("<L", session_key)
        if extended_security:
            capabilities = b'\xfd\xf3\x80\x80'
        else:
            capabilities = b'\xfd\xf3\x80\0'
        sys_time = utils.sys_time()
        time_zone = b'\0\0'

        return word_count + index + security_mode + max_mpx_count + max_vcs + max_buffer_size \
            + max_raw_buffer + session_key + capabilities + sys_time + time_zone \
            + attachment

    @staticmethod
    def npr_attachment_basic(workgroup, hostname):
        utils = Utils

        challenge_len = b'\x08'
        # byte_count should be here but is defined below
        challenge = utils.rand_num_gen()
        workgroup = utils.sambify_name(workgroup) + b'\0\0'
        hostname = utils.sambify_name(hostname) + b'\0\0'

        byte_count = struct.pack("<H", len(challenge) + len(workgroup) + len(hostname))

        return challenge_len + byte_count + challenge + workgroup + hostname

    @staticmethod
    def npr_attachment_ex_sec(hostname):
        challenge_len = b'\x00'
        byte_count = b'\x5a\0'  # Static as the server_guid is always 16 characters and the security blob never changes
        server_guid = bytes(hostname.lower(), "utf-8")

        # The following if statements limit server_guid to 16 characters because that is how Samba implements the
        # server_guid
        if len(server_guid) < 16:
            server_guid = server_guid + b'\0' * (16 - len(server_guid))
        elif len(server_guid) > 16:
            server_guid = server_guid[0:16]

        security_blob = b'\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06' \
                        b'\x01\x04\x01\x82\x37\x02\x02\x0a\xa3\x2a\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f\x64\x65' \
                        b'\x66\x69\x6e\x65\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31\x37\x38\x40\x70\x6c\x65\x61\x73' \
                        b'\x65\x5f\x69\x67\x6e\x6f\x72\x65'

        return challenge_len + byte_count + server_guid + security_blob

    @staticmethod
    def session_andx_response(workgroup_name: str = "", more_proc_req: bool = False, security_blob: bytes = b''):
        """Session AndX Response with various configurations

        Attributes:
            hostname -- hostname as a string
            workgroup_name -- workgroup name as a string
            more_proc_req -- specific version of the andx response that requires some modification of default values
            security_blob -- security blob, if needed; requires some modification of default values"""

        # Why in ints, why now? All of the following may be modified depending on the input given.
        # If empty, both word_count and byte_count must be 0 (and that's all we're returning)
        # byte_count and security_blob_length may be added to later down the line

        byte_count = 0
        security_blob_length = b''

        if security_blob != b'':
            word_count = 4
            security_blob_length = struct.pack("<H", len(security_blob))
            byte_count = len(security_blob)  # Will be added to below
        else:
            word_count = 3

        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'

        if more_proc_req:
            action = b'\0\0'
        else:
            action = b'\x01\0'

        # byte_count should be here but is defined below
        native_os = b'Windows 6.1\0'
        native_lanman = b'Samba 4.5.9\0'
        primary_domain = bytes(workgroup_name.upper(), "utf-8") + b'\0'
        byte_count = byte_count + len(native_os) + len(native_lanman) + len(primary_domain)

        return struct.pack("B", word_count) + andx_command + reserved + andx_offset + action \
            + security_blob_length + struct.pack("<H", byte_count) + security_blob \
            + native_os + native_lanman + primary_domain

    @staticmethod
    def sess_andx_security_blob(hostname: str = None, more_proc_req: bool = False,
                                dns_computer_name: str = 'd589f9efe821', metasploit: bool = False):
        if more_proc_req:
            utils = Utils

            if metasploit:
                blob_beginning = b'\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\0\0\0'
            else:
                blob_beginning = b'\xa1\x81\xd0\x30\x81\xcd\xa0\x03\x0a\x01\x01\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01' \
                                 b'\x82\x37\x02\x02\x0a\xa2\x81\xb7\x04\x81\xb4\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\0' \
                                 b'\0\0'
            hostname_len = struct.pack("H", len(hostname) * 2)
            max_hostname_len = hostname_len
            offset = struct.pack("i", 56)

            negotiate_flags = b'\x15\x82\x8a\x02'

            ntlm_server_challenge = utils.rand_num_gen()
            reserved = b'\0\0\0\0\0\0\0\0'

            # list_len should be here but is calculated below
            # list_max_len should be here but is calculated below
            list_offset = struct.pack("i", 56 + (len(hostname) * 2))

            smb_version = b'\x06\x01\0\0\0\0\0\x0f'

            sambified_hostname = utils.sambify_name(hostname)
            # Related variables to above: hostname_len, max_hostname_len, offset1

            net_bios_domain_type = b'\x02\0'
            net_bios_domain_len = hostname_len
            net_bios_domain_name = sambified_hostname

            net_bios_computer_type = b'\x01\0'
            net_bios_computer_len = hostname_len
            net_bios_computer_name = sambified_hostname

            dns_domain_all = b'\x04\0\x02\0\0\0'  # Includes: DNS_domain_type, DNS_domain_len, DNS_domain_name

            dns_computer_type = b'\x03\0'
            dns_computer_len = struct.pack("H", 24)
            dns_computer_name = utils.sambify_name(dns_computer_name, True)

            timestamp_type_len = b'\x07\0\x08\0'  # First two characters are type, rest is length
            timestamp = utils.sys_time()

            end_of_list = b'\0\0\0\0'

            list_len = len(net_bios_domain_type) + len(net_bios_domain_len) + len(net_bios_domain_name) \
                + len(net_bios_computer_type) + len(net_bios_computer_len) + len(net_bios_computer_name) \
                + len(dns_domain_all) + len(dns_computer_type) + len(dns_computer_len) + len(dns_computer_name) \
                + len(timestamp_type_len) + len(timestamp) + len(end_of_list)
            list_max_len = list_len

            return blob_beginning + hostname_len + max_hostname_len + offset + negotiate_flags \
                + ntlm_server_challenge + reserved + struct.pack("H", list_len) + struct.pack("H", list_max_len) \
                + list_offset + smb_version + sambified_hostname + net_bios_domain_type + net_bios_domain_len \
                + net_bios_domain_name + net_bios_computer_type + net_bios_computer_len + net_bios_computer_name \
                + dns_domain_all + dns_computer_type + dns_computer_len + dns_computer_name + timestamp_type_len \
                + timestamp + end_of_list

        else:
            return b'\xa1\x07\x30\x05\xa0\x03\x0a\x01\0'

    @staticmethod
    def empty() -> bytes:
        word_count = b'\0'
        byte_count = b'\0\0'

        return word_count + byte_count

    @staticmethod
    def create_andx_response(nmap_test_file: bool = False) -> bytes:
        utils = Utils
        word_count = struct.pack("B", 42)
        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'

        if nmap_test_file:
            oplock_level = b'\x02'
            create_action = b'\x02\0\0\0'  # According to Wireshark, this means "file did not exist but was created"
            create_time = utils.sys_time()
            file_type = b'\0\0'
            ipc_state = b'\x07\0'
            guest_mar = b'\0' * 4
        else:
            oplock_level = b'\0'
            create_action = b'\x01\0\0\0'  # According to Wireshark, this means "file existed and was opened"
            create_time = b'\0' * 8
            file_type = b'\x02\0'
            ipc_state = b'\xff\x05'
            guest_mar = b'\x9b\x01\x12\0'

        file_id = utils.rand_num_gen(2)
        # create_action and create_time should be here but are defined above
        last_access = create_time  # Samba's responses appear to have identical values for all time variables
        last_write = create_time
        change_time = create_time
        file_attr = b'\x80\0\0\0'  # According to Wireshark, this means "an ordinary file/dir"
        alloc_size = b'\0' * 8
        end_of_file = b'\0' * 8
        # file_type and ipc_state should be here but are defined above
        is_directory = b'\0'  # no
        volume_guid = b'\0' * 16
        uniq_file_id = b'\0' * 8
        maximal_access_rights = b'\xff\x01\x1f\0'
        # guest_mar should be here but is defined above
        byte_count = b'\0\0'

        return word_count + andx_command + reserved + andx_offset + oplock_level + file_id + create_action \
            + create_time + last_access + last_write + change_time + file_attr + alloc_size + end_of_file \
            + file_type + ipc_state + is_directory + volume_guid + uniq_file_id + maximal_access_rights \
            + guest_mar + byte_count

    @staticmethod
    def open_andx_response(fid: bytes) -> bytes:
        utils = Utils

        word_count = struct.pack("B", 15)
        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'
        # fid is defined by argument
        file_attributes = b'\x80\0'
        last_write = utils.sys_time(round(time.time()) + 18000)  # Time must jump ahead 5 hours and lose precision down
        # to seconds instead of milliseconds in accordance to Samba 4.5.9; I don't know why it's implemented this way
        file_size = b'\0\0\0\0'
        granted_access = b'\x02\0'
        file_type = b'\0\0'
        ipc_state = b'\0\0'
        action = b'\x02\0'
        server_fid = b'\0\0\0\0'
        reserved_2_electric_boogaloo = b'\0\0'
        byte_count = b'\0\0'

        return word_count + andx_command + reserved + andx_offset + fid + file_attributes + last_write + file_size + \
            granted_access + file_type + ipc_state + action + server_fid + reserved_2_electric_boogaloo + byte_count

    @staticmethod
    def write_andx_response(client_packet: bytes) -> bytes:
        word_count = b'\x06'
        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'
        count_low = client_packet[53:55]
        remaining = b'\0\0'
        count_high = client_packet[55:57]
        reserved2 = b'\0\0'
        byte_count = b'\0\0'

        return word_count + andx_command + reserved + andx_offset + count_low + remaining + count_high + reserved2 \
            + byte_count

    @staticmethod
    def read_andx_response(attachment: bytes) -> bytes:
        word_count = struct.pack("B", 12)
        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'
        remaining = b'\0\0'
        data_compact_mode = b'\0\0'
        reserved2 = b'\0\0'
        data_length_low = struct.pack("<H", len(attachment))
        data_offset = struct.pack("<H", 60)
        data_length_high = b'\0' * 4
        reserved3 = b'\0' * 6
        byte_count = struct.pack("<H", len(attachment) + 1)  # Assumption: the + 1 is due to the padding below
        padding = b'\0'

        return word_count + andx_command + reserved + andx_offset + remaining + data_compact_mode + reserved2 \
            + data_length_low + data_offset + data_length_high + reserved3 + byte_count + padding + attachment

    @staticmethod
    def bind_ack(call_id: bytes) -> bytes:
        # All bind-acks are identical in network analysis; it's broken down in case of future development
        version = b'\x05'
        version_minor = b'\0'
        packet_type = b'\x0c'  # Bind_ack
        packet_flags = b'\x03'
        data_rep = b'\x10\0\0\0'  # Little-endian order, ASCII characters, IEEE floats
        frag_length = struct.pack("<H", 68)  # This is the length of the entire dcerpc portion
        auth_length = b'\0\0'
        # Call_ID determined by argument
        max_xmit_flag = struct.pack("<H", 4280)
        max_recv_flag = max_xmit_flag
        assoc_group = b'\xf0\x53\0\0'  # Unknown; doesn't appear to change
        scndry_addr_len = struct.pack("<H", 13)  # Unknown; doesn't appear to change
        scndry_addr = b'\\PIPE\\srvsvc\0'
        num_results = b'\0\x01'
        unmarked = b'\0' * 3  # This portion is not labelled by Wireshark
        ctx_item = b'\0\0\0\0\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\0\x2b\x10\x48\x60\x02\0\0\0'

        return version + version_minor + packet_type + packet_flags + data_rep + frag_length + auth_length + call_id \
            + max_xmit_flag + max_recv_flag + assoc_group + scndry_addr_len + scndry_addr + num_results + unmarked \
            + ctx_item

    @staticmethod
    def netshare_enum_all(call_id: bytes, metasploit: bool = False) -> bytes:
        version = b'\x05'
        version_minor = b'\0'
        packet_type = b'\x02'  # Response
        packet_flags = b'\x03'
        data_rep = b'\x10\0\0\0'  # Little-endian order, ASCII characters, IEEE floats
        # frag_length determined below
        auth_length = b'\0\0'
        # Call_ID determined by argument
        # alloc_hint determined below
        context_id = b'\0\0'
        cancel_count = b'\0'

        gap = b'\0'  # Some kind of gap not detected by Wireshark

        smb = Smb1
        if metasploit:
            enum_all = smb.msf_enum_all()
        else:
            enum_all = smb.nmap_enum_all()

        alloc_hint = struct.pack("<L", len(enum_all))
        frag_length = struct.pack("<H", 24 + len(enum_all))

        return version + version_minor + packet_type + packet_flags + data_rep + frag_length + auth_length + call_id \
            + alloc_hint + context_id + cancel_count + gap + enum_all

    @staticmethod
    def nmap_enum_all() -> bytes:
        utils = Utils
        pointer_to_level = b'\0\0\0\0'
        ctr = b'\0\0\0\0'
        referent_id_netsharectr0 = b'\x0c\0\x02\0'
        count_ctr0 = b'\x02\0\0\0'
        referent_id_netshareinfo0 = b'\x10\0\x02\0'
        count_max_netshareinfo0 = b'\x02\0\0\0'
        referent_id_data = b'\x14\0\x02\0'
        referent_id_ipc = b'\x18\0\x02\0'
        count_max_data = b'\x05\0\0\0'
        offset_data = b'\0\0\0\0'
        count_data = b'\x05\0\0\0'
        name_data = utils.sambify_name("data", True) + b'\0\0'
        gap = b'\0\0'  # gap not recognized by Wireshark
        count_max_ipc = b'\x05\0\0\0'
        offset_ipc = b'\0\0\0\0'
        count_ipc = b'\x05\0\0\0'
        name_ipc = utils.sambify_name("IPC$") + b'\0\0'
        gap2 = gap
        total_entries = b'\x02\0\0\0'
        referent_id_resume_handle = b'\x1c\0\x02\0'
        resume_handle = b'\0\0\0\0'
        windows_error = b'\0\0\0\0'  # Error Code: WERR_OK (?; "we're okay"? Got this from Wireshark...)

        return pointer_to_level + ctr + referent_id_netsharectr0 + count_ctr0 + referent_id_netshareinfo0 + \
            count_max_netshareinfo0 + referent_id_data + referent_id_ipc + count_max_data + offset_data + \
            count_data + name_data + gap + count_max_ipc + offset_ipc + count_ipc + name_ipc + gap2 + \
            total_entries + referent_id_resume_handle + resume_handle + windows_error

    @staticmethod
    def msf_enum_all(server_string: str = "Samba 4.5.9") -> bytes:
        utils = Utils

        pointer_to_level = b'\x01\0\0\0'
        ctr = b'\x01\0\0\0'
        referent_id_netsharectr0 = b'\x0c\0\x02\0'
        count_ctr0 = b'\x02\0\0\0'
        referent_id_netshareinfo0 = b'\x10\0\x02\0'
        count_max_netshareinfo0 = b'\x02\0\0\0'
        referent_id_data = b'\x14\0\x02\0'
        type_data = b'\0\0\0\0'  # STYPE_DISKTREE
        referent_id_data_upper = b'\x18\0\x02\0'
        referent_id_ipc = b'\x1c\0\x02\0'
        type_ipc = b'\x03\0\0\x80'
        referent_id_comment = b'\x20\0\x02\0'
        count_max_data = b'\x05\0\0\0'
        offset_data = b'\0\0\0\0'
        count_data = b'\x05\0\0\0'
        name_data = utils.sambify_name("data", True) + b'\0\0'
        gap = b'\0\0'  # gap not recognized by Wireshark
        count_max_data_upper = b'\x05\0\0\0'
        offset_data_upper = b'\0\0\0\0'
        count_data_upper = b'\x05\0\0\0'
        name_data_upper = b'D' + name_data[1:]
        gap2 = gap
        count_max_ipc = b'\x05\0\0\0'
        offset_ipc = b'\0\0\0\0'
        count_ipc = b'\x05\0\0\0'
        name_ipc = utils.sambify_name("IPC$") + b'\0\0'
        gap3 = gap
        comment_str = "IPC Service (" + server_string + ")"
        # max_count_comment should be here
        offset_comment = b'\0\0\0\0'
        # count_comment should be here
        comment = bytes(comment_str, "utf-16")[2:] + b'\0\0'

        max_count_comment = struct.pack("<l", len(comment_str) + 1)
        count_comment = max_count_comment

        total_entries = b'\x02\0\0\0'
        referent_id_resume_handle = b'\x24\0\x02\0'
        resume_handle = b'\0\0\0\0'
        windows_error = b'\0\0\0\0'  # Error Code: WERR_OK (?; "we're okay"? Got this from Wireshark...)

        return pointer_to_level + ctr + referent_id_netsharectr0 + count_ctr0 + referent_id_netshareinfo0 + \
            count_max_netshareinfo0 + referent_id_data + type_data + referent_id_data_upper + referent_id_ipc + \
            type_ipc + referent_id_comment + count_max_data + offset_data + count_data + name_data + gap + \
            count_max_data_upper + offset_data_upper + count_data_upper + name_data_upper + gap2 + \
            count_max_ipc + offset_ipc + count_ipc + name_ipc + gap3 + max_count_comment + offset_comment + \
            count_comment + comment + total_entries + referent_id_resume_handle + resume_handle + windows_error

    @staticmethod
    def netshare_get_info(ipc: bool, call_id: bytes = b'AAAA', server_string: str = "Samba 4.5.9"):
        utils = Utils

        if ipc:
            storage_name = "IPC$"
        else:
            storage_name = "Data"

        version = b'\x05'
        version_minor = b'\0'
        packet_type = b'\x02'  # Response
        packet_flags = b'\x03'
        data_rep = b'\x10\0\0\0'  # Little-endian order, ASCII characters, IEEE floats
        # frag_length should be here but is defined below
        auth_length = b'\0\0'
        # Call_ID determined by argument
        # alloc_hint should be here but is defined below
        context_id = b'\0\0'
        cancel_count = b'\0'

        gap = b'\0'

        # Server Service begins here
        info = b'\x02\0\0\0'
        referent_id = b'\x04\0\x02\0'
        referent_id_2 = b'\x08\0\x02\0'
        if ipc:
            serv_type = b'\x03\0\0\x80'
        else:
            serv_type = b'\0\0\0\0'
        referent_id_3 = b'\x0c\0\x02\0'
        permissions = b'\0\0\0\0'
        max_users = b'\xff\xff\xff\xff'
        if ipc:
            curr_users = b'\x02\0\0\0'
        else:
            curr_users = b'\0\0\0\0'
        referent_id_4 = b'\x10\0\x02\0'
        referent_id_5 = b'\x14\0\x02\0'

        max_count = struct.pack("<l", len(storage_name) + 1)
        offset = b'\0\0\0\0'
        actual_count = max_count
        if ipc:
            name = bytes(storage_name, "utf-16")[2:]
        else:
            name = utils.sambify_name(storage_name, True)

        gap_2 = b'\0\0\0\0'  # Unknown gap, not recognized in Wireshark

        if ipc:
            # max_count_2 should be here but is calculated below
            offset_2 = b'\0\0\0\0'
            # actual_count_2 should be here but is calculated below
            comment_str = "IPC Service (" + server_string + ")"
            # Sizing is based off actual size, hence we use comment_str to calculate 'max_count_2'
            comment = bytes(comment_str, "utf-16")[2:] + b'\0\0'
            max_count_2 = struct.pack("<l", len(comment_str) + 1)
            actual_count_2 = max_count_2
        else:
            max_count_2 = struct.pack("<l", len(storage_name) + 1)
            offset_2 = b'\0\0\0\0'
            actual_count_2 = max_count
            comment = bytes(storage_name, "utf-16")[2:] + b'\0\0'

        # Unknown gap not recognized in Wireshark; if IPC, must exist if server_string even, must not if it is odd.
        if ipc:
            if len(server_string) % 2 == 0:
                gap_3 = b'\0\0'
            else:
                gap_3 = b''
        else:
            gap_3 = b'\0\0'

        if ipc:
            max_count_3 = b'\x07\0\0\0'
            offset_3 = b'\0\0\0\0'
            actual_count_3 = max_count_3
            path = bytes("C:\\tmp", "utf-16")[2:] + b'\0\0'
        else:
            max_count_3 = struct.pack("<l", len(storage_name) + 4)
            offset_3 = b'\0\0\0\0'
            actual_count_3 = max_count_3
            path = bytes("C:\\" + storage_name.lower(), "utf-16")[2:]

        gap_4 = b'\0\0'
        max_count_4 = b'\x01\0\0\0'
        offset_4 = b'\0\0\0\0'
        actual_count_4 = b'\x01\0\0\0'
        password = b'\0\0'

        gap_5 = b'\0\0'

        windows_error = b'\0\0\0\0'  # Error: WERR_OK; I assume this means "We're okay"

        alloc_hint = len(info) + len(referent_id) + len(referent_id_2) + len(serv_type) + len(referent_id_3) \
            + len(permissions) + len(max_users) + len(curr_users) + len(referent_id_4) + len(referent_id_5) \
            + len(max_count) + len(offset) + len(actual_count) + len(name) + len(gap_2) + len(max_count_2) \
            + len(offset_2) + len(actual_count_2) + len(comment) + len(gap_3) + len(max_count_3) \
            + len(offset_3) + len(actual_count_3) + len(path) + len(gap_4) + len(max_count_4) + len(offset_4) \
            + len(actual_count_4) + len(password) + len(gap_5) + len(windows_error)

        frag_length = alloc_hint + len(version) + len(version_minor) + len(packet_type) + len(packet_flags) \
            + len(data_rep) + len(auth_length) + len(call_id) + len(context_id) + len(cancel_count) + len(gap) + 6
        # The '6' accounts for the lengths of frag_length and alloc_hint combined

        return version + version_minor + packet_type + packet_flags + data_rep + struct.pack("<H", frag_length) \
            + auth_length + call_id + struct.pack("<l", alloc_hint) + context_id + cancel_count + gap + info \
            + referent_id + referent_id_2 + serv_type + referent_id_3 + permissions + max_users + curr_users \
            + referent_id_4 + referent_id_5 + max_count + offset + actual_count + name + gap_2 + max_count_2 \
            + offset_2 + actual_count_2 + comment + gap_3 + max_count_3 + offset_3 + actual_count_3 + path + gap_4 \
            + max_count_4 + offset_4 + actual_count_4 + password + gap_5 + windows_error

    @staticmethod
    def trans2_response_empty():
        utils = Utils

        word_count = struct.pack("B", 10)
        total_parameter_count = struct.pack("<H", 10)
        total_data_count = struct.pack("<H", 196)
        reserved = b'\0\0'
        parameter_count = total_parameter_count
        parameter_offset = struct.pack("<H", 56)
        parameter_displacement = b'\0\0'
        data_count = total_data_count
        data_offset = struct.pack("<H", 68)
        data_displacement = b'\0\0'
        setup_count = b'\0'
        reserved_2 = b'\0'
        byte_count = struct.pack("<H", 209)
        padding = b'\0'

        # FIND_FIRST2 Parameters will follow
        search_id = b'\xfd\xff'
        search_count = b'\x02\0'
        end_of_search = b'\x01\0'
        ea_error_offset = b'\0\0'
        last_name_offset = struct.pack("<H", 96)

        padding_2 = b'\0\0'

        # Current directory metadata
        cur_next_entry_offset = struct.pack("<I", 96)
        file_index = struct.pack("<I", 0)
        cur_creation_dt = utils.sys_time(os.stat(".").st_ctime)
        cur_access_dt = utils.sys_time(os.stat(".").st_atime)
        cur_write_dt = utils.sys_time(os.stat(".").st_mtime)
        cur_change_dt = cur_creation_dt
        end_of_file = struct.pack("<Q", 0)  # Appears to be file size; 0 for directories
        alloc_size = end_of_file
        file_attributes = b'\x10\0\0\0'
        cur_file_name_len = b'\x02\0\0\0'
        ea_list_len = b'\0\0\0\0'
        short_file_name_len = b'\0'
        reserved_3 = b'\0'
        short_file_name = b'\0' * 24
        cur_filename = b'.\0'

        # Parent directory metadata
        par_next_entry_offset = struct.pack("<I", 100)
        # file_index is identical to current directory metadata
        par_creation_dt = utils.sys_time(os.stat("..").st_ctime)
        par_access_dt = utils.sys_time(os.stat("..").st_atime)
        par_write_dt = utils.sys_time(os.stat("..").st_mtime)
        par_change_dt = par_creation_dt
        # end_of_file, alloc_size, file_attributes are identical to current directory metadata
        par_file_name_len = b'\x03\0\0\0'
        # ea_list_len, short_file_name_len, reserved_3, short_file_name are identical to current directory metadata
        par_filename = b'..\0'

        gap = b'\0\0\0'  # Not identified in Wireshark

        return word_count + total_parameter_count + total_data_count + reserved + parameter_count + parameter_offset \
            + parameter_displacement + data_count + data_offset + data_displacement + setup_count + reserved_2 \
            + byte_count + padding + search_id + search_count + end_of_search + ea_error_offset + last_name_offset \
            + padding_2 + cur_next_entry_offset + file_index + cur_creation_dt + cur_access_dt + cur_write_dt \
            + cur_change_dt + end_of_file + alloc_size + file_attributes + cur_file_name_len + ea_list_len \
            + short_file_name_len + reserved_3 + short_file_name + cur_filename + par_next_entry_offset + file_index \
            + par_creation_dt + par_access_dt + par_write_dt + par_change_dt + end_of_file + alloc_size \
            + file_attributes + par_file_name_len + ea_list_len + short_file_name_len + reserved_3 + short_file_name \
            + par_filename + gap

    @staticmethod
    def tree_andx_response(ipc: bool):
        word_count = b'\x03'
        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'
        optional_support = b'\x01\0'
        # byte_count should be here but is calculated below
        if ipc:
            service = b'IPC\0'
            native_fs = b'\0'
        else:
            service = b'A:\0'
            native_fs = b'NTFS\0'

        byte_count = struct.pack("<H", len(service) + len(native_fs))

        return word_count + andx_command + reserved + andx_offset + optional_support + byte_count + service + native_fs

    @staticmethod
    def logoff_andx_response() -> bytes:
        word_count = struct.pack("B", 2)
        andx_command = b'\xff'
        reserved = b'\0'
        andx_offset = b'\0\0'
        byte_count = b'\0\0'

        return word_count + andx_command + reserved + andx_offset + byte_count
