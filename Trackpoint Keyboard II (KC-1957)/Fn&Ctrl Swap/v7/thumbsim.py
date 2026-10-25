# -*- coding: utf-8 -*-
"""最小 Thumb 解释器 —— 供 v5.1 / v6 的验证脚本做 trampoline 行为仿真共用。

只实现补丁 trampoline 用到的指令子集：
  cmp / tst / movs / mov / mov.w / add / lsls / bic /
  ldrb(.w) / ldr(.w) / strb(.w) / str(.w) / b / beq / bne / bpl / bmi / bx

内存模型：
  * 0x20000000-0x20007FFF 视为 RAM（按字节读写）
  * 其余地址从传入的固件镜像里读
  * periph 里的地址视为 32 位外设寄存器（整字读写）
"""
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


# ---------------------------------------------------------------- 最小 Thumb 解释器
def split_ops(o):
    """按顶层逗号切分操作数（括号内逗号不切）。"""
    out, depth, cur = [], 0, ''
    for ch in o:
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


class Sim:
    """只支持 v6 trampoline 用到的指令子集，用于行为仿真。"""

    def __init__(self, image, ram=None, periph=None):
        self.img = image
        self.ram = dict(ram or {})          # 字节地址 -> 字节值
        self.periph = dict(periph or {})    # 外设地址 -> 32 位值
        self.reg = [0] * 16
        self.N = 0
        self.Z = 0
        self.sp = 0

    # ---- 内存 ----
    def rd(self, addr, n):
        if addr in self.periph:
            v = self.periph[addr]
            return bytes([(v >> (8 * i)) & 0xFF for i in range(n)])
        out = bytearray()
        for i in range(n):
            a = addr + i
            if 0x20000000 <= a < 0x20008000:
                out.append(self.ram.get(a, 0))
            else:
                out.append(self.img[a])
        return bytes(out)

    def wr(self, addr, n, val):
        for i in range(n):
            a = addr + i
            self.ram[a] = (val >> (8 * i)) & 0xFF

    def rd32(self, addr):
        return struct.unpack('<I', self.rd(addr, 4))[0]

    def rd8(self, addr):
        return self.rd(addr, 1)[0]

    # ---- 执行 ----
    def run(self, pc, limit=400):
        steps = 0
        while steps < limit:
            steps += 1
            self.pc_now = pc
            ins = list(md.disasm(self.img[pc:pc + 4], pc, 1))
            if not ins:
                raise RuntimeError('无法解码 @0x%X' % pc)
            i = ins[0]
            m, o = i.mnemonic, i.op_str
            mk = m.replace('.w', '').replace('.n', '')
            ops = split_ops(o)

            def rr(x):
                """取寄存器值（支持 sp / sl 名称）。"""
                x = x.strip().lstrip('#')
                if x == 'sp':
                    return self.sp
                if x == 'sl':
                    return self.reg[10]
                if x == 'lr':
                    return self.reg[14]
                return self.reg[int(x.lstrip('r'))]

            def ri(x):
                return int(x.strip().lstrip('#'), 0)

            if mk == 'cmp':
                v = rr(ops[0])
                imm = ri(ops[1])
                res = (v - imm) & 0xFFFFFFFF
                self.N = 1 if res >> 31 else 0
                self.Z = 1 if res == 0 else 0
                pc += i.size
            elif mk == 'tst':
                res = rr(ops[0]) & ri(ops[1])
                self.N = 1 if res >> 31 else 0
                self.Z = 1 if res == 0 else 0
                pc += i.size
            elif mk == 'movs':
                self.reg[int(ops[0].lstrip('r'))] = ri(ops[1]) & 0xFFFFFFFF
                self.N = 1 if (ri(ops[1]) >> 31) else 0
                self.Z = 1 if (ri(ops[1]) & 0xFFFFFFFF) == 0 else 0
                pc += i.size
            elif mk == 'mov':
                d = int(ops[0].lstrip('r'))
                if ops[1].startswith('#'):
                    self.reg[d] = ri(ops[1]) & 0xFFFFFFFF
                else:
                    self.reg[d] = rr(ops[1])
                pc += i.size
            elif mk == 'add':
                d = int(ops[0].lstrip('r'))
                if ops[1] == 'sp':
                    self.reg[d] = (self.sp + ri(ops[2])) & 0xFFFFFFFF
                else:
                    self.reg[d] = (rr(ops[0]) + rr(ops[1])) & 0xFFFFFFFF
                pc += i.size
            elif mk == 'lsls':
                d = int(ops[0].lstrip('r'))
                self.reg[d] = (rr(ops[1]) << ri(ops[2])) & 0xFFFFFFFF
                self.N = 1 if (self.reg[d] >> 31) else 0
                self.Z = 1 if self.reg[d] == 0 else 0
                pc += i.size
            elif mk == 'bic':
                d = int(ops[0].lstrip('r'))
                self.reg[d] = rr(ops[1]) & (~ri(ops[2]) & 0xFFFFFFFF)
                self.N = 1 if (self.reg[d] >> 31) else 0
                self.Z = 1 if self.reg[d] == 0 else 0
                pc += i.size
            elif mk == 'ldrb':
                self.reg[int(ops[0].lstrip('r'))] = self.rd8(self.addr_of(ops[1]))
                pc += i.size
            elif mk == 'strb':
                r = int(ops[0].lstrip('r'))
                self.wr(self.addr_of(ops[1]), 1, self.reg[r])
                pc += i.size
            elif mk == 'ldr':
                self.reg[int(ops[0].lstrip('r'))] = self.rd32(self.addr_of(ops[1]))
                pc += i.size
            elif mk == 'str':
                r = int(ops[0].lstrip('r'))
                self.wr(self.addr_of(ops[1]), 4, self.reg[r])
                pc += i.size
            elif mk in ('b', 'beq', 'bne', 'bpl', 'bmi', 'bhi', 'blt', 'bge', 'ble', 'bcs', 'bcc'):
                tgt = int(ops[0].lstrip('#'), 0)
                if mk == 'b':
                    pc = tgt
                elif mk == 'beq':
                    pc = tgt if self.Z else pc + i.size
                elif mk == 'bne':
                    pc = tgt if not self.Z else pc + i.size
                elif mk == 'bpl':
                    pc = tgt if not self.N else pc + i.size
                elif mk == 'bmi':
                    pc = tgt if self.N else pc + i.size
                else:
                    raise RuntimeError('未实现的分支 %s' % mk)
            elif mk == 'bx':
                raise RuntimeError('bx 结束')
            else:
                raise RuntimeError('未实现的指令: %s %s @0x%X' % (m, o, pc))
        raise RuntimeError('执行步数超限')

    def addr_of(self, expr):
        expr = expr.strip()
        if expr.startswith('[') and expr.endswith(']'):
            expr = expr[1:-1]
        parts = [x.strip() for x in expr.split(',')]
        if parts and parts[0] == 'pc':
            base = (self.pc_now + 4) & ~3
            return base + int(parts[1].lstrip('#'), 0)
        regs = []
        shift = 0
        for p in parts:
            if p.startswith('lsl'):
                shift = int(p.split('#')[1].strip(), 0)
            elif p.startswith('#'):
                regs.append(int(p[1:], 0))
            else:
                regs.append(self.rr(p))
        if len(regs) == 1:
            return regs[0]
        if len(regs) == 2:
            return regs[0] + (regs[1] << shift) if shift else regs[0] + regs[1]
        raise RuntimeError('无法解析地址 %s' % expr)

    def rr(self, x):
        x = x.strip().lstrip('#')
        if x == 'sp':
            return self.sp
        if x == 'sl':
            return self.reg[10]
        if x == 'lr':
            return self.reg[14]
        return self.reg[int(x.lstrip('r'))]


# ---------------------------------------------------------------- 主验证
