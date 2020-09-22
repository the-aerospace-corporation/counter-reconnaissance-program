BUFFER_SIZE = 16384  # arbitrary size, probably needs something else

NMAP_PROBES = {
    b'\r\n\r\n': "Generic Lines",
    b'GET / HTTP/1.0\r\n\r\n': "Get Request",
    b'OPTIONS / HTTP/1.0\r\n\r\n': "HTTP Options",
    b'OPTIONS / RTSP/1.0\r\n\r\n': "RTSP Request",
    b'\x80\x00\x00(r\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97|\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': "TCP RPC Check",
    b'\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03': "TCP DNS "
                                                                                                        "Version Bind"
                                                                                                        " Request "
}

PROBE_GENERIC_LINES = b'\r\n\r\n'
PROBE_GET_REQUEST = b'GET / HTTP/1.0\r\n\r\n'

PROBE_HTTP_OPTIONS = b'OPTIONS / HTTP/1.0\r\n\r\n'
PROBE_RTSP_REQUEST = b'OPTIONS / RTSP/1.0\r\n\r\n'
PROBE_TCP_RPC_CHECK = b'\x80\x00\x00(r\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97|\x00' \
                  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Missing equivalent UDP probe
PROBE_TCP_DNS_VERSION_BIND_REQ = b'\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00' \
                                 b'\x00\x10\x00\x03'

# Missing equivalent UDP probe
PROBE_TCP_DNS_STATUS_REQUEST = b'\x00\x0c\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'
PROBE_HELLO = b'EHLO\r\n'

# Missing equivalent UDP probe
PROBE_TCP_HELP = b'HELP\r\n'
PROBE_SSL_SESSION_REQ = b'\x16\x03\x00\x00S\x01\x00\x00O\x03\x00?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\x00\xfd\x82{\xb9' \
                        b'\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\x00\x00(\x00\x16\x00\x13\x00\n\x00f\x00\x05' \
                        b'\x00\x04\x00e\x00d\x00c\x00b\x00a\x00`\x00\x15\x00\x12\x00\t\x00\x14\x00\x11\x00\x08\x00' \
                        b'\x06\x00\x03\x01\x00'
PROBE_TSL_SESSION_REQ = b'\x16\x03\x00\x00i\x01\x00\x00e\x03\x03U\x1c\xa7\xe4random1random2random3random4\x00' \
                        b'\x00\x0c\x00/\x00\n\x00\x13\x009\x00\x04\x00\xff\x01\x00\x000\x00\r\x00,\x00*\x00\x01' \
                        b'\x00\x03\x00\x02\x06\x01\x06\x03\x06\x02\x02\x01\x02\x03\x02\x02\x03\x01\x03\x03\x03' \
                        b'\x02\x04\x01\x04\x03\x04\x02\x01\x01\x01\x03\x01\x02\x05\x01\x05\x03\x05\x02'
# Missing SSLv23SessionReq probe
PROBE_KERBEROS = b'\x00\x00\x00qj\x81n0\x81k\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa4\x81^0\\\xa0\x07\x03' \
                 b'\x05\x00P\x80\x00\x10\xa2\x04\x1b\x02NM\xa3\x170\x15\xa0\x03\x02\x01\x00\xa1\x0e0\x0c\x1b' \
                 b'\x06krbtgt\x1b\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04\x1f\x1e\xb9\xd9\xa8' \
                 b'\x170\x15\x02\x01\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03\x02\x01\x02'
PROBE_SMB_PROG_NEG = b'\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0' \
                   b'\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT N' \
                   b'ETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0'
PROBE_X11 = b'l\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00'
PROBE_404_REQ = b'GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n'
PROBE_LPD_STRING = b'\x01default\n'

# Missing equivalent UDP probe
PROBE_TCP_LDAP_SEARCH_REQ = b'0\x84\x00\x00\x00-\x02\x01\x07c\x84\x00\x00\x00$\x04\x00\n\x01\x00\n\x01\x00\x02\x01' \
                        b'\x00\x02\x01d\x01\x01\x00\x87\x0bobjectClass0\x84\x00\x00\x00\x00'
PROBE_LDAP_BIND_REQ = b'0\x0c\x02\x01\x01`\x07\x02\x01\x02\x04\x00\x80\x00'

# Missing equivalent UDP probe
PROBE_TCP_SIP_OPTIONS = b'OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\nFrom: <sip:nm@nm>;tag=root\r\n' \
                    b'To: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: ' \
                    b'0\r\nContact: <sip:nm@nm>\r\nAccept: application/sdp\r\n\r\n'
PROBE_LANDESK_RC = b'TNMP\x04\x00\x00\x00TNME\x00\x00\x04\x00'
# Missing TerminalServerCookie
PROBE_TERMINAL_SERVER = b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'
PROBE_NCP = b'DmdT\x00\x00\x00\x17\x00\x00\x00\x01\x00\x00\x00\x00\x11\x11\x00\xff\x01\xff\x13'
PROBE_NOTES_RPC = b':\x00\x00\x00/\x00\x00\x00\x02\x00\x00@\x02\x0f\x00\x01\x00=\x05\x00\x00\x00\x00\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x00\x00\x00\x00'
# Missing DistCCD
PROBE_JAVA_RMI = b'JRMI\x00\x02K'
# Missing Radmin
# Missing UDP Sqlping
# Missing UDP NTPRequest
# Missing NessusTPv12
# Missing NessusTPv11
# Missing NessusTPv10
# Missing UDP SNMPv1public
# Missing UDP SNMPv3GetRequest
PROBE_WMSRequest = b'\x01\x00\x00\xfd\xce\xfa\x0b\xb0\xa0\x00\x00\x00MMS\x14\x00\x00\x00\x00\x00\x00\x00\x00' \
                   b'\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x01\x00\x03\x00\xf0\xf0\xf0\xf0\x0b\x00\x04' \
                   b'\x00\x1c\x00\x03\x00N\x00S\x00P\x00l\x00a\x00y\x00e\x00r\x00/\x009\x00.\x000\x00.\x000' \
                   b'\x00.\x002\x009\x008\x000\x00;\x00 \x00{\x000\x000\x000\x000\x00A\x00A\x000\x000\x00-\x000' \
                   b'\x00A\x000\x000\x00-\x000\x000\x00a\x000\x00-\x00A\x00A\x000\x00A\x00-\x000\x000\x000\x000' \
                   b'\x00A\x000\x00A\x00A\x000\x00A\x00A\x000\x00}\x00\x00\x00\xe0m\xdf_'
PROBE_ORACLE_TNS = b'\x00Z\x00\x00\x01\x00\x00\x00\x016\x01,\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01' \
                   b'\x00 \x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x004\xe6\x00\x00' \
                   b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00(CONNECT_DATA=(COMMAND=version))'
# Missing UDP xdmcp
# Missing UDP AFSVersionRequest
# Missing OfficeScan
PROBE_MS_SQL_S = b'\x12\x01\x004\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00' \
                 b'(\x00\x04\xff\x08\x00\x01U\x00\x00\x00MSSQLServer\x00H\x0f\x00\x00'
# Missing HELP4STOMP
# Missing Memcache
# Missing beast2
# Missing firebird
# Missing ibm-db2-das
# Missing ibm_db2
# Missing pervasive-relational
# Missing pervasive-btrieve
# Missing UDP ibm-db2-das-udp
# Missing ajp
# Missing UDP DNS-SD
# Missing hp-pjl
# Missing UDP Citrix
# Missing UDP Kerberos
# Missing UDP SqueezeCenter
PROBE_AFP = b'\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x0f\x00'
# Missing UDP Quake1_server_info
# Missing UDP Quake2_status
# Missing UDP Quake3_getstatus
# Missing UDP Quake3_master_getservers
# Missing SqueezeCenter_CLI
# Missing Arucer
# Missing UDP serialnumberd
# Missing dominoconsole
# Missing informix
# Missing drda
# Missing ibm-mqseries
# Missing apple-iphoto
# Missing ZendJavaBridge
# Missing UDP BackOrifice
# Missing gkrellm
# Missing metasploit-xmlrpc
# Missing mongodb
# Missing UDP sybaseanywhere
# Missing UDP vuze-dht
# Missing UDP pc-anywhere
# Missing UDP pc-duo
# Missing UDP pc-duo-gw
# Missing redis-server
# Missing UDP memcached
# Missing riak-pbc
# Missing tarantool
# Missing couchbase-data
# Missing epmd
# Missing vp3
# Missing kumo-server
# Missing metasploit-msgrpc
# Missing UDP svrloc
# Missing hazelcast-http
# Missing minecraft-ping
# Missing erlang-node
# Missing UDP Murmur
# Missing UDP Ventrilo
# Missing teamspeak-tcpquery-ver
# Missing UDP TeamSpeak2
# Missing UDP TeamSpeak3
# Missing xmlsysd
# Missing UDP FreelancerStatus
# Missing UDP AndroMouse
# Missing AirHID
# Missing UDP NetMotionMobility
# Missing docker
# Missing tor-versions
# Missing TLS-PSK
# Missing NJE
# Missing tn3270
PROBE_GIOP = b'GIOP\x01\x00\x01\x00$\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00' \
             b'\x00abcdef\x00\x00\x04\x00\x00\x00get\x00\x00\x00\x00\x00'
# Missing OpenVPN
# Missing UDP OpenVPN
# Missing pcworx
# Missing proconos
# Missing niagara-fox
# Missing mqtt
# Missing UDP ipmi-rmcp
# Missing UDP coap-request
# Missing UDP DTLSSessionReq
# Missing iperf3
# Missing UDP QUIC
# Missing VersionRequest
# Missing NoMachine
# Missing JMON
# Missing LibreOfficeImpressSCPair
# Missing UDP ARD
# Missing LSCP
# Missing rotctl
# Missing SharpTV
