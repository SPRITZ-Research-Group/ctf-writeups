[writeup by @abiondo]

**CTF:** VolgaCTF 2017 Quals

**Team:** spritzers

**Task**: reverse / Transformer

**Points:** 400

```
We've got a file that was processed with a binary called transformer. We really need the contents of this file. Can you help?
```

We have an unstripped ELF 64-bit Linux binary of something that looks like an encryption application, along with an encrypted file named `ciphertext.zip.enc`.

After loading the binary in IDA, we immediately see it's written in Rust. We also have plenty debug info, which makes it more bearable. Before jumping to reversing, let's play around with it a bit to get a feel for it and maybe make our lives easier.

Executing the program without arguments prints:

```
Usage: transformer <input_file> <output_file>
```

We try out different input sizes and find a pattern:

| Input size(s) | Output size |
| ------------- | ----------- |
|     0...7     |      12     |
|     8...15    |      20     |
|    16...23    |      28     |

We suspect a 64-bit block cipher (with always at least one byte of padding) with 4 extra bytes somewhere.

When trying longer inputs we notice part of the plaintext appears unencrypted in the output. Take for example the following input:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz9876543210
```

Which produces this output:

```
00000000: 37f8 9c55 79c7 e40d ec3f 5c05 e27c e952  7..Uy....?\..|.R
00000010: c564 1e78 1f84 f8d5 2551 4e41 595a 3031  .d.x....%QNAYZ01
00000020: 3233 3435 03bb 2823 aca5 1d78 23f8 4363  2345..(#...x#.Cc
00000030: 8dd7 a1cf c4b8 c116 a26b 35c2 7576 7778  .........k5.uvwx
00000040: 797a 3938 1126 fefd 0e22 5b1a f58c 38cf  yz98.&..."[...8.
00000050: 550c ab30                                U..0
```

Notice `YZ012345` at offset 0x1C and `uvwxyz98` at offset 0x3C. Those are 64-bit blocks straight from the plaintext! The offset between those two substrings in the plaintext is 32 bytes, and sure enough 0x3C - 0x1C = 32. However, the offset of `YZ012345` from the start of the plaintext is 24 bytes, while the offset of that same block from the start of the ciphertext is 28 bytes, i.e. it looks like those extra 4 bytes might be at the beginning of the ciphertext.

We also notice that multiple runs with the same input produce different outputs each time. There's some randomization involved, and most likely the 4 extra bytes have something to do with it (this later turned out to be true).

To recap, our best guess is: 4 extra bytes at the beginning, 64-bit block cipher, every fourth block is left unencrypted, there's some kind of randomization.

Now that we have some idea of what we're dealing with, let's get to reversing. The actually interesting functions seem to be:

```
transformer::main::he40168f1b93e998b
transformer::mode::encrypt_crt_ecb::hd9b87ece0c780db7
transformer::mode::encrypt_thread::h3e003e4395b60fbd
transformer::rc5::Rc5::encrypt_block::hc307a8b30c5c81e1
transformer::rc5::Rc5::new::h30d6eb4c1bfeb265
transformer::rc5::data_to_s::he50325ddf278b94d
```

[RC5](https://en.wikipedia.org/wiki/RC5) is a block cipher with variable key size, block size and number of rounds, all of which are unknown to us. The block size is twice the word size, which is a tweakable parameter. In our case, with 64-bit blocks, we'd have a 32-bit word size. Also, `encrypt_crt_ecb` could be a misspelling of `encrypt_ctr_ecb`, i.e. counter mode encryption.

Looking at `Rc5::new` we notice some interesting constants:

```
.text:7AD0  mov dword ptr [r13+0], 0B7E15163h
...
.text:7B01  add eax, 9E3779B9h
```

Those are the RC5 key expansion magic constants for a 32-bit word size, indeed. By comparing to the RC5 algorithm, we reverse `Rc5::new` and `Rc5::encrypt_block` to gain more information about how they're called and on the structures used to maintain context.

`Rc5::new` takes (in order) an RC5 context struct, the number of rounds and the key (in a wrapper struct) as arguments. It initializes the RC5 context through the key expansion algorithm. Due to all the wrappers it wasn't obvious where things came from. We breakpointed on the function and saw that the number of rounds was always 16. We also noticed that two different keys were being used.

`Rc5::encrypt_block` takes (in order) an RC5 context struct (initialized by `Rc5::new`), the higher 32 bits of the plaintext block and the lower 32 bits of the plaintext block. It returns the encrypted 64-bit block.

Those functions are called from `mode::encrypt_thread`. It accepts (amongst other things) two keys and two 32-bit block halves. It creates two RC5 ciphers, one for each key. The first key is used to encrypt the block passed in the arguments. The second key is used to encrypt a block read from an input buffer. Then, the two encrypted blocks are XORed and the result is written to an output buffer.

Helping ourselves with a debugger, we see that the input blocks are our input data and the output blocks are written to the output file. Also, the blocks passed as arguments look like this:

```
pt[0] = 0x798d5d19, pt[1] = 0x0
pt[0] = 0x798d5d19, pt[1] = 0x1
pt[0] = 0x798d5d19, pt[1] = 0x2
pt[0] = 0x798d5d19, pt[1] = 0x4
pt[0] = 0x798d5d19, pt[1] = 0x5
pt[0] = 0x798d5d19, pt[1] = 0x6
pt[0] = 0x798d5d19, pt[1] = 0x8
...
```

That's a counter mode! The high 32-bit half is fixed, while the lower 32-bit half is a counter starting from zero. Notice how every fourth block is skipped, but the counter is still incremented.

The fixed high half matches the first 4 bytes of the output file. It's generated randomly in `mode::encrypt_crt_ecb`.

The only missing piece of the puzzle are the encryption keys. Those are passed in a pretty obvious way from `main` to `mode::encrypt_crt_ecb` (which then hands them over to `mode::encrypt_thread`). They are:

```
1st key: A0 93 91 A8 CA 87 39 5C
2nd key: 86 5F AF 32 60 95 71 74
```

We can finally write a decryption tool (RC5 implementation from [here](https://github.com/tbb/pyRC5/blob/master/RC5.py)):

```python
#!/usr/bin/python3

from RC5 import RC5
import struct
import sys

KEY_1 = bytes.fromhex('A09391A8CA87395C')
KEY_2 = bytes.fromhex('865FAF3260957174')

with open(sys.argv[1], 'rb') as f:
    data = f.read()

ctr_seed = data[:4]
blocks = [data[i:i+8] for i in range(4, len(data), 8)]

# 64bit blocks, 16 rounds
rc5_1 = RC5(32, 16, KEY_1)
rc5_2 = RC5(32, 16, KEY_2)

pt = b''
for i in range(len(blocks)):
    block = blocks[i]
    if i % 4 == 3:
        # every fourth block is not encrypted
        # counter is still advanced
        block_pt = block
    else:
        ctr_pt = ctr_seed + struct.pack('<I', i)
        ctr_ct = rc5_1.encryptBlock(ctr_pt)
        block_xor = [block[i] ^ ctr_ct[i] for i in range(8)]
        block_pt = rc5_2.decryptBlock(block_xor)
    pt += block_pt

sys.stdout.buffer.write(pt)
```

And we get the flag:

```
$ ./decrypt.py ciphertext.zip.enc > plaintext.zip

$ file plaintext.zip
plaintext.zip: Zip archive data, at least v2.0 to extract

$ unzip plaintext.zip -d plaintext
Archive:  plaintext.zip
  inflating: plaintext/plaintext.txt

$ cat plaintext/plaintext.txt 
This document defines four ciphers with enough detail to ensure interoperability between different implementations.  The first cipher is the raw RC5 block cipher.  The RC5 cipher takes a fixed size input block and produces a fixed sized output block using a transformation that depends on a key.  The second cipher, RC5-CBC, is the Cipher Block Chaining (CBC) mode for RC5. It can process messages whose length is a multiple of the RC5 block size.  The third cipher, RC5- CBC-Pad, handles plaintext of any length, though the ciphertext will be longer than the plaintext by at most the size of a single RC5 block.  The RC5-CTS cipher is the Cipher Text Stealing mode of RC5, which handles plaintext of any length and the ciphertext length matches the plaintext length.

In the meantime your flag is VolgaCTF{Wh1te_b0x_crypto_i$_not_crYpto}.

The RC5 cipher was invented by Professor Ronald L. Rivest of the Massachusetts Institute of Technology in 1994.  It is a very fast and simple algorithm that is parameterized by the block size, the number of rounds, and key length.  These parameters can be adjusted to meet different goals for security, performance, and exportability.

RSA Data Security Incorporated has filed a patent application on the RC5 cipher and for trademark protection for RC5, RC5-CBC, RC5-CBC-Pad, RC5-CTS and assorted variations.
```
