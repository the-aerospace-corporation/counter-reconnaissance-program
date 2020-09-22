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
