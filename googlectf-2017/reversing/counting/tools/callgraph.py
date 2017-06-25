#!/usr/bin/env python3

import struct
from collections import deque


import networkx as nx


INSTR_INC = 0
INSTR_DEC = 1
INSTR_FRK = 2
INSTR_JMP = 3
INSTR_RET = 4


def pretty(i):
    if i.opcode == INSTR_INC:
        return 'inc r{}, {}'.format(i.op, i.next1)
    elif i.opcode == INSTR_DEC:
        return 'cdec r{}, {}, {}'.format(i.op, i.next1, i.next2)
    elif i.opcode == INSTR_FRK:
        return 'call {{{}}}, {}, {}'.format(','.join('r{}'.format(a) for a in range(i.op)), i.next1, i.next2)
    elif i.opcode == INSTR_JMP:
        return 'jmp {}'.format(i.next1)
    elif i.opcode == INSTR_RET:
        return 'ret'.format(i.addr)
    else:
        assert 1 == 0


class Instruction(object):
    def __init__(self, addr, opcode, op, next1, next2):
        self.addr = addr
        self.opcode = opcode
        self.op = op
        self.next1 = next1
        self.next2 = next2

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return 'Instr({}, {}, {}, {}, {})'.format(self.addr, self.opcode, self.op, self.next1, self.next2)
    

class Call(object):
    def __init__(self, addr, regs):
        self.addr = addr
        self.regs = regs

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return 'Call({}, {})'.format(self.addr, self.regs)


class Function(object):
    def __init__(self, addr, regs):
        self.addr = addr
        self.calls = set()
        self.instrs = dict()
        self.regs = regs

    def add(self, instr):
        self.instrs[instr.addr] = instr

    def __str__(self):
        return 'Function({}, {}, {}, {{{}}})'.format(
            self.addr, str(self.calls), self.instrs, ','.join('r{}'.format(i) for i in range(self.regs))
        )


def analyze(instrs, start=0, regs=1, called=set()):
    f = Function(start, regs)
    funks = {start: f}
    q = deque()
    analyzed = set()
    q.append(instrs[start])
    while len(q) > 0:
        i = q.popleft()
        if i in analyzed:
            continue
        analyzed.add(i)

        if i.addr > len(instrs):
            print("EXIT")
            continue
        if i.opcode == INSTR_FRK:
            f.calls.add(Call(i.next1, i.op))
            f.add(i)
            q.append(instrs[i.next2])
        elif i.opcode == INSTR_DEC:
            f.add(i)
            q.append(instrs[i.next1])
            q.append(instrs[i.next2])
        elif i.opcode == INSTR_INC:
            f.add(i)
            q.append(instrs[i.next1])
        elif i.opcode == INSTR_JMP:
            f.add(i)
            q.append(instrs[i.next1])
        elif i.opcode == INSTR_RET:
            f.add(i)

    for c in f.calls:
        if c.addr in called:
            continue
        called.add(c.addr)
        bb, cc = analyze(instrs, start=c.addr, regs=c.regs, called=called)
        funks.update(bb)
        called.update(cc)

    return funks, called


def load_file(file_path):
    code = open(file_path, 'rb').read()
    n = struct.unpack('I', code[:4])[0]
    code = code[4:]
    instrs = []
    for i in range(n):
        instr = Instruction(i, *struct.unpack('<4I', code[16 * i:16 * (i + 1)]))
        if instr.opcode == INSTR_DEC and instr.op == 25:
            instr = Instruction(i, INSTR_JMP, 0, instr.next2, 0)
        instrs.append(instr)
    instrs.append(Instruction(119, INSTR_RET, 0, 0, 0))
    return instrs


def print_disassembly(funks):
    for b in sorted(funks):
        b = funks[b]
        print("Function: {}".format(b.addr))
        ii = sorted(b.instrs.values(), key=lambda x: x.addr)
        for i in ii:
            print('{: 3}:'.format(i.addr), pretty(i))
        print()


def draw_callgraph(funks):
    block_graph = nx.DiGraph()
    for b in funks.values():
        block_graph.add_node(b.addr)
    for b in funks.values():
        for c in b.calls:
            block_graph.add_edge(b.addr, c.addr)

    a = nx.nx_agraph.to_agraph(block_graph)
    a.layout(prog='dot')
    a.draw('callgraph.png')


def draw_cfg(funks):
    fgs = {}
    for b in funks.values():
        fg = nx.DiGraph()
        for i in b.instrs.values():
            fg.add_node(i.addr, { 'label': '{}: {}'.format(i.addr, pretty(i)) })
        for i in b.instrs.values():
            if i.opcode == INSTR_INC:
                fg.add_edge(i.addr, i.next1)
            elif i.opcode == INSTR_DEC:
                fg.add_edge(i.addr, i.next1)
                fg.add_edge(i.addr, i.next2)
            elif i.opcode == INSTR_FRK:
                fg.add_edge(i.addr, i.next2)
            elif i.opcode == INSTR_JMP:
                fg.add_edge(i.addr, i.next1)
            else:
                assert i.opcode == INSTR_RET
        fgs[b.addr] = fg

        a = nx.nx_agraph.to_agraph(fg)
        a.layout(prog='dot')
        a.draw('function_{}.png'.format(b.addr))


def main(file_path, print_bytecode=False, make_callgraph=False):
    instrs = load_file(file_path)
    funks, _ = analyze(instrs)

    if print_bytecode:
        print_disassembly(funks)

    if make_callgraph:
        draw_callgraph(funks)
        draw_cfg(funks)


if __name__ == '__main__':
    main('code', make_callgraph=True)
