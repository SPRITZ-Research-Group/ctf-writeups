[writeup by @abiondo]

**CTF:** 0x00 CTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** pwn / Left

**Points:** 250

We're given a 64-bit ELF executable, along with its libc:

```
left:         ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3d8808a82ddfa25f6f142a4de2d7e877f526a5de, with debug_info, not stripped
libc-2.23.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=088a6e00a1814622219f346b41e775b8dd46c518, for GNU/Linux 2.6.32, stripped
```

Checksec shows full RELRO and NX, but no stack canary and no PIE.

The program is pretty simple. First, it prints out the address of `printf` (so we have a libc leak). Then, it asks for a read address and prints out a qword read from that address. Finally, it asks for a write address and for a qword that it will write at that address. The write is immediately followed by termination via `exit`.

Given the conditions (full RELRO, no malloc/free after the write, hard to create fake structures), the only realistic way of exploitation is by corrupting `atexit` handlers. The `atexit` library function allows to add a function to a list of functions that will be called upon `exit`. This list can extend via dynamic allocations, but it's initially inside the libc data section (named `initial`). Its type is `struct exit_function_list`:

```c
struct exit_function {
    long int flavor;
    union { /* bunch of fptr types */ } func;
};
struct exit_function_list {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
};
```

By overwriting an existing entry in `fns` we can hijack execution once `exit` is called. There's an issue, though. The pointers are mangled to prevent exactly this kind of attack, via the `PTR_(DE)MANGLE` macros. Mangling consists in XORing with a secret value (in TLS), then rotating left by 17 bits. When the function has to be called, the pointer is demangled by rotating right by 17 bits and XORing with the secret. Since we don't know the secret, we can't contruct a mangled pointer and we'll only be able to crash the program.

However, we have a memory read before the write. Say that we know the function pointer for an `atexit` entry. We can read the mangled pointer and compute the secret, then use it to mangle our pointer for the write. So let's see what entries are already there. In this libc, `initial` is at offset 0x3C5C40 (you can see it by looking at `__cxa_atexit`):

```
gef➤  x/4xg 0x00007f776310a000+0x3c5c40
0x7f77634cfc40: 0x0000000000000000  0x0000000000000001
0x7f77634cfc50: 0x0000000000000004  0x8094f89617513c86
```

We can see that `next` is NULL (there's only the `initial` list) and `idx` is 1 (there's one entry). The function pointer (at libc+0x3C5C58) has flavor 4 (`ef_cxa`), which is not really important for us. What does this correspond to? We could mess with the TLS, o set breakpoints, or just:

```
gef➤  set *((unsigned long *) 0x7f77634cfc58) = 0
gef➤  c
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x00007f7763143ff6 in ?? ()
gef➤  x/i $rip
=> 0x7f7763143ff6:  call   rdx
gef➤  p/x $rdx
$1 = 0x9e433f3d1f054f58
```

I set the mangled pointer to zero. When the pointer was demangled, it was rotated (still zero) and XORed with the secret, so now the address it's trying to jump to is exactly the secret. Now that we have the secret for the current run, we can demangle the entry we found earlier and see what it points to:

```
$ python
>>> ror17 = lambda x : ((x << 47) & (2**64 - 1)) | (x >> 17)
>>> hex(ror17(0x8094f89617513c86) ^ 0x9e433f3d1f054f58)
'0x7f77634e44f0L'
```

Let's check it out:

```
gef➤  x/i 0x7f77634e44f0
   0x7f77634e44f0 <_dl_fini>:   push   rbp
```

Ouch, that's bad news. The only entry points to `_dl_fini`, which is a function from the dynamic loader (`ld.so`). When a program is executed on Linux, the loader passes a finalization function (`rtld_fini`) to the entry point, which then passes it to `__libc_start_main`, which registers it with `atexit`. This is what we're seeing. Unfortunately, `_dl_fini` resides in ld, which we don't have a leak for.

There's a technique to calculate addresses in other libraries, sometimes called offset2lib. Linux loads libraries one after the other, which means that one library will be at a fixed offset from another. Since we have leaked libc, if we determine the offset to ld we can calculate addresses inside of ld. There's another obstacle: we don't have the server's ld, so we don't know at what offset `_dl_fini` is.

What we do have is an arbitrary read. With each connection to the server we get a read. The offsets we're looking for are fixed between executions, so what about using the read to find the offset to `_dl_fini`? Without bothering with symbol tables, I noticed that the entry point of ld had an instruction that loaded the address of `_dl_fini` into a register with RIP-relative addressing. Hoping that this instruction would be there remotely, I did the following:

1. Starting at the end of libc, look for the `\x7fELF` ELF header, which marks the base of ld (because it's the only other library and it follows libc). This can be done in 4kB increments because library bases are page-aligned.
2. Read the entry point at offset 0x18 within the ELF header.
3. Read the `lea rdx, [rip+X]` instruction at offset 0x3A in the entry function. This loads the address of `_dl_fini` into `rdx`. By decoding the instruction you get the offset of `_dl_fini` from RIP.

See the [script](./leak.py) for more details.

With this, I found out that `_dl_fini` is at libc+0x3DAAB0 on the remote side. At this point it's pretty easy to read the entry, calculate the secret, mangle a pointer and write it back. RIP control achieved!

At this point I tried a few one-gadgets, and found one that worked at libc+0x4526A:

```
$ cat /home/left/flag.txt
0x00CTF{exPL0it1ng__EXit_FUNkz_LikE_4b0sZ!}
```
