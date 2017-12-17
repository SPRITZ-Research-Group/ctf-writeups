[writ[writeup by @bonaff]

**CTF:** 0x00CTF

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** Reverse / challenge-004 

**Points:** 50

We are given an ELF x86-64 executable:
```
$ file hello
hello: ERROR: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=b8ccefeffb8978b2289ec31802396333def9dfad error reading (Invalid argument)
```

The file is a little messy, but nothing exceptional.
At 0x40084E we can see the function that checks if the key is valid or not:

```
signed __int64 __fastcall sub_40084E(char *input_key)
{
  char buf; // [rsp+1Bh] [rbp-5h]
  int i; // [rsp+1Ch] [rbp-4h]

  if ( (*buffer[0] ^ (unsigned __int8)*input_key) != 48 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][1] ^ (unsigned __int8)input_key[1]) != 120 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][2] ^ (unsigned __int8)input_key[2]) != 48 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][3] ^ (unsigned __int8)input_key[3]) != 48 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][4] ^ (unsigned __int8)input_key[4]) != 67 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][5] ^ (unsigned __int8)input_key[5]) != 84 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][6] ^ (unsigned __int8)input_key[6]) != 70 )
    return 0xFFFFFFFFLL;
  if ( (buffer[0][7] ^ (unsigned __int8)input_key[7]) == 123 )
  {
    for ( i = 0; i < dword_602080; ++i )
    {
      buf = input_key[i % 8] ^ buffer[0][i];
      write(1, &buf, 1uLL);
    }
    exit(1);
  }
```

In the final `for`, the program will decrypt the flag using the buffer and the key we give to it (if it was right).

The quickest way to obtain the flag is to xor the buffer with `0x00CTF{` (that is the first part of the flag) in order to obtain our key. And then run the program with that key or simply xoring all the buffer with the key we found.

```
buffer[0]: 01 16 79 44 04 64 12 5A 01 0C 2F 21 72 53 60 16 02 2A 16 24 33 62 60 7B
```

Here's `get_key.py`:

```python
buf = [0x01, 0x16, 0x79, 0x44, 0x04, 0x64, 0x12, 0x5A, 0x01, 0x0C,
0x2F, 0x21, 0x72, 0x53, 0x60, 0x16, 0x02, 0x2A, 0x16, 0x24,
0x33, 0x62, 0x60, 0x7B ]
f = map(ord, "0x00CTF{")

key = ''.join([chr(x^y) for x,y in zip(f, buf)])

print(key)
```

And finally, let's get the flag:

```
$ python get_key.py
1nItG0T!
$ ./hello
Welcome to the Twinlight Zone!!!
Password: 1nItG0T!
0x00CTF{0bfU5c473D_PtR4Z3}
```