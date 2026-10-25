#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""v5.1 补丁独立验证脚本（含 v5 旧版 SEQ_B 的反例对照）。

用法：
    python verify_v51.py <原始.bin> <v5.1补丁后.bin> [v5旧版补丁后.bin]

验证内容：
  A. 改动范围：改动只落在允许清单内；与 v5 旧产物的差异**只**落在 trampoline B 区段。
  B. trampoline A（蓝牙行循环）行为：驱动 FN_MATRIX / E0F、清 local_64 的 bit、恢复 r1。
  C. trampoline B（2.4G 行循环）行为 —— **v5.1 的两处修正点**：
       C1 命中时寄存器 r0 的 bit 被清（2.4G 逐位测试用的就是 r0）
       C2 返回前标志位被复原（Z 与原 bics 语义一致），不会整行丢键
  D. trampoline C（2.4G P0.IN 判定）行为
  E. trampoline D（去抖保护）行为
  F. 反例对照：把 v5 旧版 SEQ_B 现场汇编出来跑同一场景，证明缺陷确实存在
"""
import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

from thumbsim import Sim

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

# ---------------------------------------------------------------- 常量
FN_MATRIX = 0x20004800
E0F = 0x20001E0F
P0IN = 0x50000510
ROWPIN = 0x2CBE0

HOOK_A = 0x1E4E4
HOOK_B = 0x41252
HOOK_C = 0x411C6
HOOK_D = 0x1B7C0
CAVE_A = 0x050000
CAVE_B = 0x050100
CAVE_C = 0x050200
CAVE_D = 0x050300

ORIG_CODE = {
    HOOK_A: bytes.fromhex('00BFDC49'),
    HOOK_B: bytes.fromhex('1AF80420'),
    HOOK_C: bytes.fromhex('F7480068410604D40127DF218DF810103D46'),
    HOOK_D: bytes.fromhex('002037490870'),
}
ORIG_MASK = {0x1E84C: bytes([0xE7]), 0x4A6B2: bytes([0x1C])}

FAILS = []
NTOTAL = [0]


def chk(cond, msg):
    NTOTAL[0] += 1
    print('  [%s] %s' % ('OK' if cond else '!!', msg))
    if not cond:
        FAILS.append(msg)


# ---------------------------------------------------------------- v5 旧版 SEQ_B（反例用）
OLD_SEQ_B = [
    ('i', 'cmp r4, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'strb r2, [r1]'),
    ('i', 'add r1, sp, #{l84}'),
    ('i', 'ldr.w r2, [r1, r4, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r4, lsl #2]'),
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'strb r2, [r1]'),
    ('L', '.restore'),
    ('i', 'ldrb.w r2, [sl, r4]'),
    ('i', 'bx lr'),
]
FMT = dict(row=12, mbit=0x10, l64=0x1C, l84=0x24,
           fnmat=FN_MATRIX, fnheld=0x20002109, e0f=E0F, e09=0x20001E09,
           p0in=P0IN, rowpin=ROWPIN, p06=0x40)


def build(seq, fmt, base):
    """与 fn_matrix_patch3.py 同款的迷你汇编器（用于现场编译反例）。"""
    labels, cur, plan = {}, 0, []
    for item in seq:
        if item[0] == 'L':
            labels[item[1]] = cur
            continue
        if item[0] == 'b':
            plan.append(['b', item[1], item[2], cur])
            cur += 2
        elif item[0] == 'LIT':
            plan.append(['lit', item[1], item[2], cur])
            cur += 4
        else:
            txt = item[1].format(**fmt)
            enc, _ = ks.asm(txt, addr=base + cur, as_bytes=False)
            plan.append(['i', txt, None, cur])
            cur += len(enc)
    code = bytearray(cur)
    lit_slots = []
    for p in plan:
        kind, a, b, off = p
        if kind == 'b':
            enc, _ = ks.asm('%s 0x%x' % (a, base + labels[b]), addr=base + off, as_bytes=False)
            code[off:off + 2] = enc
        elif kind == 'lit':
            lit_slots.append((off, int(a[1:]), fmt[b]))
        else:
            enc, _ = ks.asm(a, addr=base + off, as_bytes=False)
            code[off:off + len(enc)] = enc
    pad = (-len(code)) % 4
    code.extend(b'\x00\xbf' * (pad // 2))
    pool_off = len(code)
    for off, reg, val in lit_slots:
        code[off:off + 4] = struct.pack('<HH', 0xF8DF, reg << 12)
        code.extend(struct.pack('<I', val))
    for i, (off, reg, val) in enumerate(lit_slots):
        target = base + pool_off + i * 4
        pc = base + off + 4
        struct.pack_into('<HH', code, off, 0xF8DF,
                         (reg << 12) | ((target - (pc & ~3)) & 0xFFF))
    return bytes(code)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    orig = open(sys.argv[1], 'rb').read()
    new = open(sys.argv[2], 'rb').read()
    old = open(sys.argv[3], 'rb').read() if len(sys.argv) > 3 else None

    print('=' * 78)
    print('v5.1 补丁独立验证：%s -> %s' % (sys.argv[1], sys.argv[2]))
    print('=' * 78)

    # ---- A. 改动范围 ----
    print('\n=== A. 改动范围 ===')
    chk(len(orig) == len(new), '固件长度未变 (%d)' % len(new))
    chk(new[4:8] == orig[4:8], '向量表 Reset_Handler 未变 (0x%08X)'
        % struct.unpack('<I', new[4:8])[0])
    allowed = {}
    for a, b in ORIG_CODE.items():
        allowed[a] = a + len(b)
    for a in ORIG_MASK:
        allowed[a] = a + 1
    for base in (CAVE_A, CAVE_B, CAVE_C, CAVE_D):
        allowed[base] = base + 0x200
    diff = [i for i in range(len(new)) if new[i] != orig[i]]
    bad = [i for i in diff if not any(a <= i < b for a, b in allowed.items())]
    chk(not bad, '改动全部落在允许清单内 (越界 %d 处)' % len(bad))
    chk(new[0x1E84C] == 0xF7, '蓝牙行掩码 r12 = 0xF7（放行 bit4）')
    chk(new[0x4A6B2] == 0x0C, '2.4G 行掩码 r12 = 0x0C（放行 bit4）')
    for nm, addr, cave, size in (('A', HOOK_A, CAVE_A, 4), ('B', HOOK_B, CAVE_B, 4),
                                  ('C', HOOK_C, CAVE_C, 18), ('D', HOOK_D, CAVE_D, 6)):
        ins = list(md.disasm(new[addr:addr + 4], addr, 1))
        chk(bool(ins) and ins[0].mnemonic == 'bl'
            and int(ins[0].op_str.lstrip('#'), 0) == cave,
            '钩子 %s @0x%06X -> bl 0x%06X' % (nm, addr, cave))
    if old:
        d = [i for i in range(len(new)) if new[i] != old[i]]
        outside = [i for i in d if not (CAVE_B <= i < CAVE_B + 0x100)]
        chk(not outside,
            '与 v5 旧产物的差异只落在 trampoline B 区段 (越界 %d 处，共 %d 字节)'
            % (len(outside), len(d)))
        chk(len(d) > 0, '与 v5 旧产物确有差异（%d 字节，说明修正已生效）' % len(d))

    # ---- 仿真辅助 ----
    SP = 0x20006000

    def sim(img, cave, regs, ram=None, periph=None):
        s = Sim(img, ram=ram, periph=periph)
        s.sp = SP
        s.reg = list(regs) + [0] * (16 - len(regs))
        s.pc_now = cave
        try:
            s.run(cave)
        except RuntimeError as e:
            if 'bx 结束' not in str(e):
                raise
        return s

    # ---- B. trampoline A ----
    print('\n=== B. trampoline A（蓝牙行循环）===')
    ram = {SP + 0x1C + 12 * 4: 0x00000010}
    s = sim(new, CAVE_A, [0x10, 0, 0, 0, 0, 12, 0, 0], ram=ram)
    chk(s.ram.get(FN_MATRIX, 0) == 1, 'A: r5=12 且 bit4 命中 -> FN_MATRIX=1')
    chk(s.ram.get(E0F, 0) == 1, 'A: 命中时同时把 E0F 强制为 1（Fn 层激活）')
    chk(s.rd32(SP + 0x1C + 12 * 4) == 0x00, 'A: local_64[12] 的 bit4 已清 (->0x00)')
    chk(s.reg[1] == ROWPIN, 'A: 返回时 r1 = ROWPIN(0x%08X)' % ROWPIN)

    ram = {SP + 0x1C + 12 * 4: 0x00000000}
    s = sim(new, CAVE_A, [0x00, 0, 0, 0, 0, 12, 0, 0], ram=ram)
    chk(s.ram.get(FN_MATRIX, 0) == 0, 'A: r5=12 但 bit4 未命中 -> FN_MATRIX=0')
    chk(E0F not in s.ram or s.ram.get(E0F, 0) == 0, 'A: 未命中时不动 E0F')

    ram = {SP + 0x1C + 12 * 4: 0x00000010}
    s = sim(new, CAVE_A, [0x10, 0, 0, 0, 0, 11, 0, 0], ram=ram)
    chk(FN_MATRIX not in s.ram, 'A: r5!=12 时不触碰 FN_MATRIX')
    chk(s.rd32(SP + 0x1C + 12 * 4) == 0x10, 'A: r5!=12 时不修改位图')

    # ---- C. trampoline B（v5.1 的两处修正点）----
    print('\n=== C. trampoline B（2.4G 行循环）—— v5.1 修正点 ===')
    ram = {SP + 0x24 + 12 * 4: 0x00000010}
    s = sim(new, CAVE_B, [0x10, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.ram.get(FN_MATRIX, 0) == 1, 'C1: r4=12 且 bit4 命中 -> FN_MATRIX=1')
    chk((s.reg[0] & 0x10) == 0,
        'C1: **寄存器 r0 的 bit4 已被清**（2.4G 逐位测试 @0x4126C 用的就是 r0）')
    chk(s.rd32(SP + 0x24 + 12 * 4) == 0x00, 'C1: local_84[12] 的 bit4 也已清')
    chk(s.reg[2] == new[0x4A77A + 12], 'C1: 返回时 r2 = [sl,r4]（行掩码字节 0x%02X）'
        % new[0x4A77A + 12])
    chk(s.Z == 1,
        'C1: 屏蔽后该行已空 -> Z=1（原 beq 跳到下一行）'
        '—— 与原固件（r12c4 被掩码、该行本就是空）行为一致')

    ram = {SP + 0x24 + 12 * 4: 0x00000008}
    s = sim(new, CAVE_B, [0x08, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.ram.get(FN_MATRIX, 0) == 0, 'C2: r4=12、bit4 未命中、但行内有其它键 -> FN_MATRIX=0')
    chk(s.Z == 0,
        'C2: **Z=0**（行非空，原 beq 不跳）—— v5 此处会错成 Z=1 导致整行 r12 丢键')
    chk((s.reg[0] & 0x10) == 0 and s.reg[0] == 0x08, 'C2: r0 未被改动（bit4 本来就没按）')

    ram = {SP + 0x24 + 12 * 4: 0x00000000}
    s = sim(new, CAVE_B, [0x00, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.Z == 1, 'C2: 整行为空 -> Z=1（与原 bics 语义一致，原 beq 跳）')

    ram = {SP + 0x24 + 12 * 4: 0x00000008}
    s = sim(new, CAVE_B, [0x08, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(FN_MATRIX not in s.ram, 'C: r4!=12 时不触碰 FN_MATRIX')
    chk(s.Z == 0, 'C: r4!=12 且行非空 -> Z=0（未被 trampoline 破坏）')

    # ---- D. trampoline C ----
    print('\n=== D. trampoline C（2.4G P0.IN 判定）===')
    periph = {P0IN: 0x00000000}          # P0.6 为低 = 按下
    s = sim(new, CAVE_C, [0] * 16, ram={FN_MATRIX: 0}, periph=periph)
    chk(s.reg[7] == 1, 'D: P0.6 按下 -> r7=1（Fn 按住）')
    chk(s.ram.get(SP + 0x10, 0) == 0xDF, 'D: P0.6 按下 -> 伪 Fn 键 0xDF')
    chk(s.reg[5] == 1, 'D: P0.6 按下 -> uVar11(r5)=1')

    periph = {P0IN: 0x00000040}          # P0.6 为高 = 松开
    s = sim(new, CAVE_C, [0] * 16, ram={FN_MATRIX: 1}, periph=periph)
    chk(s.reg[7] == 1, 'D: P0.6 松开但 FN_MATRIX=1 -> r7=1（矩阵 Fn 并联生效）')
    chk(s.ram.get(SP + 0x10, 0) == 0xDF, 'D: 矩阵 Fn 成立时同样写伪 Fn 键 0xDF')
    chk(s.reg[5] == 1, 'D: 矩阵 Fn 成立时 uVar11(r5)=1')

    periph = {P0IN: 0x00000040}
    s = sim(new, CAVE_C, [0] * 16, ram={FN_MATRIX: 0}, periph=periph)
    chk(s.reg[7] == 0, 'D: P0.6 松开且 FN_MATRIX=0 -> r7=0')
    chk(SP + 0x10 not in s.ram, 'D: 此时不写伪键')
    chk(s.reg[5] == 0, 'D: 此时 uVar11(r5)=0')

    # ---- E. trampoline D ----
    print('\n=== E. trampoline D（去抖保护）===')
    s = sim(new, CAVE_D, [0] * 16, ram={FN_MATRIX: 1, E0F: 1})
    chk(s.ram.get(E0F, 0) == 1, 'E: FN_MATRIX!=0 时不清 E0F（矩阵 Fn 按住期间保住）')
    s = sim(new, CAVE_D, [0] * 16, ram={FN_MATRIX: 0, E0F: 1})
    chk(s.ram.get(E0F, 1) == 0, 'E: FN_MATRIX==0 时正常清 E0F（交还去抖状态机）')

    # ---- F. 反例对照：v5 旧版 SEQ_B ----
    print('\n=== F. 反例对照：现场编译 v5 旧版 SEQ_B，跑同一场景 ===')
    oldblob = build(OLD_SEQ_B, FMT, 0x051000)
    scratch = bytearray(new)
    scratch[0x051000:0x051000 + len(oldblob)] = oldblob
    scratch = bytes(scratch)

    # 场景 1：bit4 命中 -> 旧版没清 r0 的 bit4
    ram = {SP + 0x24 + 12 * 4: 0x00000010}
    s = sim(scratch, 0x051000, [0x10, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk((s.reg[0] & 0x10) != 0,
        'F1: **v5 旧版未清寄存器 r0 的 bit4** -> 2.4G 路径根本屏蔽不掉 r12c4（缺陷 1 复现）')
    s2 = sim(new, CAVE_B, [0x10, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A],
             ram={SP + 0x24 + 12 * 4: 0x00000010})
    chk((s2.reg[0] & 0x10) == 0, 'F1: v5.1 已清掉 r0 的 bit4（缺陷 1 已修）')

    # 场景 2：行内有其它键、bit4 未命中 -> 旧版把 Z 错成 1
    ram = {SP + 0x24 + 12 * 4: 0x00000008}
    s = sim(scratch, 0x051000, [0x08, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.Z == 1,
        'F2: **v5 旧版把 Z 错成 1** -> 原 0x4125E 的 beq 成立 -> 整行 r12 的其它键被丢弃（缺陷 2 复现）')
    s2 = sim(new, CAVE_B, [0x08, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0x4A77A],
             ram={SP + 0x24 + 12 * 4: 0x00000008})
    chk(s2.Z == 0, 'F2: v5.1 复原了 Z=0，整行不再被丢（缺陷 2 已修）')

    print()
    print('=' * 78)
    if FAILS:
        print('验证失败 %d 项：' % len(FAILS))
        for f in FAILS:
            print('  - %s' % f)
        raise SystemExit(1)
    print('验证全部通过（%d 项检查）' % NTOTAL[0])
    print('=' * 78)


if __name__ == '__main__':
    main()
