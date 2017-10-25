[writeup by @dantt]

**CTF:** Pwn2Win CTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** crypto / differential privacy

**Points:** 173

```
Is it possible to have privacy on these days? The Rebelious Fingers do not think so. Get the flag.
```

We're given a server to connect to, which prompts us with the following:

```
Hello, chose an option:
[1] Info
[2] Query the flag (in ASCII)
[3] Quit
```

If we select `1` we discover interesting information:
```
1
You can query the flag, but the characters are private (indistinguishable).
Differential privacy mechanism: Laplace
Sensitivity: ||125 - 45|| = 80
Epsilon: 6.5
```
The scheme employed is then differential privacy, with Laplace additive noise. This means that the computed function (or query) on the "database" is perturbed with random noise, drawn from a Laplace distribution. The challenge also tells us some information about this: the security parameter `epsilon` (capturing information about the variance of the specific Laplace distribution, and the sensitivity of the computer function.
In particular, this hints that the computed function is actually very simple: `ord(char) + noise`. Indeed, sensitivity here is the maximum absolute difference between the minimum and maximum values that the function can have. Interestingly, `chr(125) = }` and `chr(45) = -`, which we expect to be part of the flag.

If we query the flag, we have confirmation of this:

```
2
[80, 79, 95, 49, 48, 79, 149, 46, 87, 126, 123, 131, 91, 109, 105, 120, 97, 80, 89, 93, 142, 125, 114, 104, 111, 61, 85, 74, 89, 91, 126, 83, 103, 119, 99, 101, 111]
```

Interpreting this as ASCII characters, we find a nonsensical `PO_10O\x95.W~{\x83[mixaPY]\x8e}rho=UJY[~Sgwceo`, as every character is perturbated by some random amount. 

If we query again the flag within the same connection, we obtain the same encrypted string. However, if we reconnect, we get a different perturbation of the flag. This means that the task is very easy: Laplace distribution has zero mean - it is symmetric and zero-centered. Therefore, if we query the flag enough times, and average character-by-character, we eventually cancel out the noise. We setup a simple script to do it:

```python
from pwn import *
import ast
import numpy as np

guess = []

for __ in range(1000):
    p = remote("200.136.213.143", 9999)
    
    p.recvuntil("Quit")
    p.sendline("2")
    guess.append(ast.literal_eval(p.recvuntil("]").strip("\n")))
    print "".join([chr(int(round(xx))) for xx in np.mean(guess, axis=0)])
    p.close()
    
print guess
```

1000 iterations are not enough to obtain perfect cancellation, but good enough for a bit of manual tweaking, giving us the flag:
`CTF-BR{I_am_just_filtering_the_noise}`
