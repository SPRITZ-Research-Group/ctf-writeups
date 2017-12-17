[writeup by @abiondo]

**CTF:** 0x00 CTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** pwn / babyheap

**Points:** 200

```
Baby's play.
```

**Beware: this is a heap challenge, but I didn't exploit it through the heap!**

We're given a 64-bit Linux binary, along with its libc:

```
babyheap:     ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=482118237e809a1e6b662d422025f5cdc3581901, not stripped
libc-2.23.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=088a6e00a1814622219f346b41e775b8dd46c518, for GNU/Linux 2.6.32, stripped
```

Checksec shows full RELRO, stack canary, NX and no PIE.

When run, the program asks for a name and then presents a menu:

```
enter your name:
spritzers
Member manager!
1. add
2. edit
3. ban
4. change name
5. get gift
6. exit
```

This is obviously a heap challenge. You can add (allocate), edit and ban (free) users. You can also change your name (only once), and option 5 gives you a libc leak by printing the address of `read`. There are two kinds of user edit (secure and insecure), and you can do each only once.

You can have up to four users, the pointers to which are stored in a BSS array at 0x602040. The name can be up to 40 characters, stored at 0x6020A0.

While auditing the program I saw this code for the insecure edit:

```c
puts("index: ");
fflush(stdout);
user2 = users[read_num()];
if (user2) {
    user_len2 = strlen(user2);
    puts("new username: ");
    fflush(stdout);
    new_user_len2 = read(0, user2, user_len2);
    if (malloc_usable_size(user2) != new_user_len2)
        user2[new_user_len2] = 0;
    ++edit2;
    puts("user edited!");
    fflush(stdout);
} else {
    puts("no such user!");
    fflush(stdout);
}
```

Now, `read_num` reads an integer from the standard input. There is no bounds checking on the access to `users`. The return value of `read_num` is treated as unsigned, so we can make it access any memory after `users`. Notice that we control the name buffer, and it is indeed after `users`! This means that we can control the pointer `user2` by putting it into the name and fetching it with a big enough index.

The code then considers `user2` as a pointer to string and allows to read into it up to its original length. Note that `malloc_usable_size` will return zero if the pointer doesn't lie within the heap.

This gives as an almost arbitrary write primitive. We can write what we want where we want in memory, as long as the original bytes don't contain zeroes (because they would terminate `strlen`).

An idea strikes me: can I exploit the binary using only this memory write, without bothering with the heap? Well, I'm always up for a challenge! Maybe it'll be more complex, but hey, this should be fun.

A good place for an overwrite is libc, as it's full of function pointers and the program gives us a leak via option 5. Pointers do contain two top zero bytes on x64, but we're fine with just overwriting the first six as those two are always zero. Since this program uses `malloc` and `free`, we could overwrite the memory allocation hooks. However, those are initially NULL, so they won't work with our memory write. Another strategy would be to hijack an `atexit` entry, but they're XORed with a secret value that we don't know.

There is another source of non-NULL function pointers which this program surely invokes. You can see it uses `puts` and `fflush(stdout)`. It's accessing `stdout` through the stdio interface. Each stdio file is described by a `_IO_FILE` structure. This is part of a larger `_IO_FILE_plus` structure, which contains a pointer to a virtual table. This virtual table contains function pointers for things like writing, reading, flushing, and so forth (see [abusing the FILE structure](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/) if you're not familiar).

The structures for `stdout` reside inside of libc. The vtable is read-only, however, the `_IO_FILE_plus` structure is writable. So we can create a fake vtable inside a controlled memory area (the name buffer), then overwrite the vtable pointer of `stdout` to point to our fake vtable. Whenever a call through that vtable is made, it'll use our vtable with our pointers.

A small thing to note is that the vtable is larger than the name buffer, so we can't really create a whole fake vtable. This is not a problem: if we determine what's the first function to be called after the overwrite, we can offset the vtable pointer so that specific entry will be within the name buffer. The rest of the table will be invalid, but who cares? We've already hijacked the flow.

So I did this:

1. When first asked for a name, set it to something arbitrary (we don't have the info we need yet).
2. Leak the address of `read` via option 5 and calculate the libc base.
3. Edit the name, putting the address of the vtable pointer for `stdout` at the beginning. To find the address, notice there's a `stdout` pointer in the BSS of the program, which points to libc+0x3C5620. The size of the `_IO_FILE` struct is 0xD8, and the vtable pointer in `_IO_FILE_plus` immediately follows, so just sum 0xD8 to the address of `stdout` and you've got the vtable pointer address.
4. Perform an insecure edit with an index of 12. There are 96 bytes between `users` and the name buffer. Since `users` is a pointer array, it's indexed by 8-byte elements, which gives you that index.

Now the program will read 6 bytes into the vtable pointer. I overwrote it with an invalid address that would crash when accessed:

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffb8eb8b735 in ?? ()
gef➤  x/i $rip
=> 0x7ffb8eb8b735:  call   QWORD PTR [rax+0x38]
```

Where `rax` contains our vtable pointer. So the first called function pointer is at offset 0x38 in the vtable, which corresponds to `xsputn` for the `puts` call. I offsetted the vtable pointer so that this entry would fall within the name buffer, and I got RIP control.

At this point I tried a one-gadget RCE, but unfortunately I couldn't satisfy the gadget constraints. Okay, we'll have to do more serious code reuse. Maybe stack pivoting and ROP? The vtable pointer is in `rax`, and there are plenty of libc gadgets that make indirect calls though `rax`, so maybe we can do something [COOP](http://ieeexplore.ieee.org/document/7163058/)-like?

After looking for a while, I found this gadget at libc+0x12B82B:

```
mov     rdi, rsp
call    qword ptr [rax+20h]
mov     cs:dword_3C8D9C, eax
mov     rax, [rsp+8]
mov     rax, [rax+38h]
test    rax, rax
jz      short loc_12B84A
mov     rdi, rsp
call    rax
loc_12B84A:
add     rsp, 30h
pop     rbx
retn
```

We can sum it up as:

```
mov     rdi, rsp
call    qword ptr [rax+20h]
if (![[rsp+8]+0x38]) {
    rsp += 0x38
    ret
}
```

It calls the vtable entry at 0x20 with the stack pointer as its first argument (`rdi`). Then, it takes the pointer at `rsp+8`, dereferences a qword at 0x38 from it and, if the qword is zero, it returns.

We can control 0x20 in our vtable, because having both 0x20 and 0x38 in the fake vtable requires it to be 32 bytes, which fits within the name buffer (with some offsetting). The idea here is to put the address of `gets` at 0x20. It will read as much as we want into the stack. We can now build a ROP buffer:

- At offset 8, we put `ZERO_ADDR-0x38`, where `ZERO_ADDR` is the address of a zero qword somewhere in memory (I used 0x6020C8 at the end of the program's BSS).
- At offset 0x38, we put our ROP chain.

The ROP chain I built is trivial. I put a /bin/sh string inside the name buffer (there's unused space between the vtable entries), then with ROP popped its address into `rdi` and called `system`. It worked:

```
$ cat /home/babypwn/flag.txt
0x00CTF{ins3cuRE_pluZ_s3cuR3_EQ_pAWN!}
```

Yeah, that's definitely not the road I followed ;)
