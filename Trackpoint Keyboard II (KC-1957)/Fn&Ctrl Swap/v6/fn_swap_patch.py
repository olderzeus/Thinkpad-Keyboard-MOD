#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""KC-1957_88.bin  左Ctrl <-> Fn 完全互换改造 —— v6

直接从**原始固件**（KC-1957_88.bin / KC-1957_88_orig.bin）打补丁，不依赖任何中间版本。

================================================================================
改造目标
================================================================================
  物理 Fn 键位（P0.6 + 矩阵 r12c4）  ->  发 Left Ctrl（0xE0 修饰位）
  物理 左 Ctrl 键位（矩阵 r15c0）    ->  充当 Fn（激活 Fn 层）
  P0.6 不再是 Fn

键位事实（已逐字节核对）
--------------------------------------------------------------------------------
  矩阵 r15c0 = idx 120 = 0xE0 (Left Ctrl)   BT 表 0x2CBF0 / 2.4G 表 0x4A6FA
  矩阵 r12c4 = idx 100 = 0x00 (空槽)        BT 表 0x2CC54 / 2.4G 表 0x4A75E
  P0.6 = GPIO 低有效 = 旧 Fn 键
       E0E(0x20001E0E) 去抖计数 -> E0F(0x20001E0F) 去抖按下
       -> 2109(0x20002109) Fn 层激活 = E0F && D7B

================================================================================
设计要点
================================================================================
1) E0F 语义整体换源：E0F 由「P0.6 去抖按下」改为「矩阵 r15c0 按下」。
   - 去抖状态机 FUN_0001b75c 的 E0F 池槽（0x1B8A0）改指新变量 E0F2，
     于是 P0.6 的去抖照常进行、但不再污染 E0F；
   - 其余 5 个「读 E0F」的池槽（0x1B714 / 0x1E868 / 0x1ECD0 / 0x020B4C / 0x020FD4）
     一个都不用动，全部自动改为跟随矩阵 Fn；
   - FUN_00020bd8 的 2109 计算（2109 = E0F && D7B）因此自动变成
     2109 = 矩阵Fn && D7B —— P0.6 不再激活 Fn 层。
   代价：P0.6 的「松开」边沿检测（E0F==1 判断）随之失效，
        故 Ctrl 注入一律采用**原始 P0.IN bit6**（与原固件在 2.4G 路径、
        BT 扫描内联处的用法一致），不依赖去抖值。

2) r12c4 -> Left Ctrl 完全走「键码表 + 行掩码」两条既有通路，零新增钩子：
   - 键码表 idx100 由 0x00 改为 0xE0（BT 0x2CC54 / 2.4G 0x4A75E）；
   - 行掩码放行 bit4（BT 0x1E84C |= 0x10；2.4G 0x4A6B2 &= ~0x10）；
   - 两条扫描路径都会把 0xE0 交给 HID 组装函数，由其转成修饰位 0。

3) r15c0 -> Fn：两条扫描路径的行循环各挂一个 trampoline，
   命中 r15c0 时写 E0F=1 并清掉该行位图的 bit0（避免产生键码），
   未命中时写 E0F=0。

4) P0.6 -> Left Ctrl：两条路径各有一个注入点
   - BT：HID 报告组装 FUN_00023a40 的修饰字节清零处（0x23A76），
     改写为「*param_1 = (P0.6 为低 ? 1 : 0)」；
   - 2.4G：扫描函数里原有的「P0.6 按下 -> 伪 Fn 键 0xdf」位置（0x411C6），
     改成「P0.6 按下 -> 伪 Left Ctrl 键 0xE0」。
   2.4G 侧的伪键 0xE0 会随键码数组进入报告，由报告组装函数转成修饰位 0，
   这条通路已被原始固件验证（KEYTBL_G[120] 原本就是 0xE0）。

================================================================================
补丁点清单
================================================================================
数据补丁
  0x02CC54  KEYTBL_BT[100]  0x00 -> 0xE0     r12c4 = Left Ctrl
  0x02CC68  KEYTBL_BT[120]  0xE0 -> 0x00     r15c0 = 不产生键码
  0x04A75E  KEYTBL_G [100]  0x00 -> 0xE0     r12c4 = Left Ctrl
  0x04A772  KEYTBL_G [120]  0xE0 -> 0x00     r15c0 = 不产生键码
  0x01E84C  BT  行掩码 r12   0xE7 -> 0xF7     放行 col4（高有效：|= bit4）
  0x04A6B2  2.4G 行掩码 r12   0x1C -> 0x0C     放行 col4（低有效：&= ~bit4）
  0x01B8A0  字面量池槽        0x20001E0F -> 0x20004800   去抖用 E0F2，与 E0F 解耦

代码钩子
  HOOK_A 0x1E4E4  (4B)   蓝牙扫描行循环     -> trampoline A
  HOOK_B 0x41252  (4B)   2.4G 扫描行循环    -> trampoline B
  HOOK_C 0x411C6  (18B)  2.4G P0.6 判定/伪键 -> trampoline C
  HOOK_D 0x1EB74  (22B)  BT 扫描内联 P0.IN 读 -> trampoline D
  HOOK_E 0x23A76  (4B)   BT HID 组装修饰位   -> trampoline E

命令行
  python fn_swap_patch.py <in.bin> [--out <out.bin>] [--apply]
                          [--force-mask] [--force]
  默认干跑（只报告不写盘）；--apply 才写出文件。
  --force-mask：键盘掩码与预期值不符时，仍按「实际值 + 位操作」强制修补。
  --force     ：在 --force-mask 基础上，连钩子代码点的字节差异也一并忽略。
"""
import argparse
import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

# ---------------------------------------------------------------- 常量
E0F = 0x20001E0F              # 复用为「矩阵 Fn(r15c0) 按下」（1/0）
E0F2 = 0x20004800             # 新变量：P0.6 去抖后状态（去抖状态机独占）
                              # 选址依据：按函数边界精确普查 2434 个函数实测，
                              # 全映像 pc 相对字面量引用的 RAM 变量共 661 个，最高只到
                              # 0x20003928；0x20003928 之上零引用（脚本启动时现场复核
                              # 256 字节窗口），故取最高引用 +3616 字节处。
FN_HELD = 0x20002109          # Fn 层激活 = E0F && D7B，由 FUN_00020bd8 计算
D7B = 0x20001D7B              # Fn 档位门控
P0IN = 0x50000510             # P0.IN（bit6 = P0.6，低有效）
ROWPIN = 0x2CBE0              # 蓝牙行引脚表

ROW = 15                     # r15c0 所在行
BIT = 0x01                    # r15c0 所在列 (col0 -> bit0)

# 补丁点
HOOK_A = 0x1E4E4              # 蓝牙扫描行循环（原 nop + ldr r1,[pc,#0x370]）
HOOK_B = 0x41252              # 2.4G 扫描行循环（原 ldrb.w r2,[sl,r4]）
HOOK_C = 0x411C6              # 2.4G 内联 P0.IN bit6 判定（18 字节）
HOOK_D = 0x1EB74              # BT 扫描内联 P0.IN 读（22 字节）
HOOK_E = 0x23A76              # BT HID 组装的修饰字节清零（4 字节）

# 代码空洞（限定 0x50000-0x60000，该 128KB 全区为擦除态 0xFF，
# 且静态不可达：代码最高 0x04A9A3，pc 相对 ldr 最远只到 0x04B9A2；
# 全映像 0 处 movw/movt 构造该区间地址，0/6236 条 pc 相对 ldr 指向该区间）
CAVE_A = 0x050000             # trampoline A（蓝牙扫描行循环）
CAVE_B = 0x050100             # trampoline B（2.4G 扫描行循环）
CAVE_C = 0x050200             # trampoline C（2.4G Fn 判定 / 伪 Ctrl 键）
CAVE_D = 0x050300             # trampoline D（BT 扫描内联 P0.IN 读）
CAVE_E = 0x050400             # trampoline E（BT HID 组装修饰位）
CAVE_LIMIT = (0x50000, 0x60000)

# 数据补丁
OFF_BT_MASK_BASE = 0x1E840      # 蓝牙行掩码表基址（16 字节，row r 在 +r）
OFF_G_MASK_BASE = 0x4A6A6       # 2.4G 行掩码表基址（16 字节）
OFF_BT_MASK = OFF_BT_MASK_BASE + 12   # 蓝牙行掩码 r12
OFF_G_MASK = OFF_G_MASK_BASE + 12    # 2.4G 行掩码 r12
OFF_BT_KEY100 = 0x2CC54       # KEYTBL_BT[100]  r12c4
OFF_BT_KEY120 = 0x2CC68       # KEYTBL_BT[120]  r15c0
OFF_G_KEY100 = 0x4A75E        # KEYTBL_G[100]   r12c4
OFF_G_KEY120 = 0x4A772        # KEYTBL_G[120]   r15c0
OFF_POOL_E0F = 0x1B8A0        # FUN_0001b75c 字面量池槽（E0F）

# 掩码的位语义（用于「实际值 + 位操作」的强制修补，不套用原版常量）：
#   蓝牙掩码为高有效（&= mask）：把 bit4 置 1 即让 r12 的 col4 参与扫描
#   2.4G 掩码为低有效（&= ~mask）：把 bit4 清 0 即让 r12 的 col4 参与扫描
#   两者都只改 bit4，其余位保留变体固件自身的值。
MASK_BIT_OP = {
    OFF_BT_MASK: ('置', 0x10),   # | 0x10
    OFF_G_MASK: ('清', 0x10),    # & ~0x10
}

# 期望原字节（安全断言）
#   ORIG_CODE：钩子代码点 + 键码表条目 —— 语义位置，必须逐字节吻合（除非 --force）
#   ORIG_POOL：字面量池槽 —— 必须是 0x20001E0F，否则去抖状态机写的就不是 E0F（硬约束）
#   ORIG_MASK：键盘掩码点 —— 允许不符后按位强制修补（--force-mask / --force）
ORIG_CODE = {
    HOOK_A: bytes.fromhex('00BFDC49'),
    HOOK_B: bytes.fromhex('1AF80420'),
    HOOK_C: bytes.fromhex('F7480068410604D40127DF218DF810103D46'),
    HOOK_D: bytes.fromhex('062000BF4FF0A042114600BFD1F81025C24002F00102'),
    HOOK_E: bytes.fromhex('00230B70'),
    OFF_BT_KEY100: bytes([0x00]),
    OFF_BT_KEY120: bytes([0xE0]),
    OFF_G_KEY100: bytes([0x00]),
    OFF_G_KEY120: bytes([0xE0]),
}
ORIG_POOL = {
    OFF_POOL_E0F: bytes.fromhex('0F1E0020'),      # 0x20001E0F
}
ORIG_MASK = {
    OFF_BT_MASK: bytes([0xE7]),
    OFF_G_MASK: bytes([0x1C]),
}
ORIG = dict(ORIG_CODE)
ORIG.update(ORIG_POOL)
ORIG.update(ORIG_MASK)

# 新值
NEW_KEY = {
    OFF_BT_KEY100: 0xE0,
    OFF_BT_KEY120: 0x00,
    OFF_G_KEY100: 0xE0,
    OFF_G_KEY120: 0x00,
}
NEW_POOL = {
    OFF_POOL_E0F: E0F2,
}


def asm1(txt, addr):
    enc, _ = ks.asm(txt, addr=addr, as_bytes=False)
    if enc is None:
        raise RuntimeError('keystone 汇编失败: %r' % txt)
    return bytes(enc)


# ---------------------------------------------------------------- 汇编器
# SEQ 元素:
#   ('i',  text)              普通指令
#   ('b',  mnemonic, label)   分支
#   ('L',  label)             标签
#   ('LIT', reg, value)       生成 ldr.w reg,[pc,#imm12] + 字面量池
def build(seq, fmt, base):
    """返回 (blob, disasm_list, pool_off, want_pool)。fmt 提供 {row},{bit} 等替换。"""
    labels = {}
    cur = 0
    plan = []
    for item in seq:
        k = item[0]
        if k == 'L':
            labels[item[1]] = cur
            continue
        if k == 'b':
            plan.append(['b', item[1], item[2], cur])
            cur += 2
        elif k == 'LIT':
            plan.append(['lit', item[1], item[2], cur])
            cur += 4
        else:
            txt = item[1].format(**fmt)
            plan.append(['i', txt, None, cur])
            cur += len(asm1(txt, base + cur))

    code = bytearray(cur)
    lit_slots = []
    for p in plan:
        kind, a, b, off = p
        if kind == 'b':
            tgt = base + labels[b]
            enc = asm1('%s 0x%x' % (a, tgt), base + off)
            assert len(enc) == 2, '分支宽度变化: %s -> %d' % (a, len(enc))
            code[off:off + 2] = enc
        elif kind == 'lit':
            code[off:off + 4] = b'\x00\xbf\x00\xbf'
            lit_slots.append((off, int(a[1:]), fmt[b]))
        else:
            enc = asm1(a, base + off)
            code[off:off + len(enc)] = enc

    # 字面量池：紧跟代码区，4 字节对齐（对齐用的 nop 仍属代码区）
    pad = (-len(code)) % 4
    code.extend(b'\x00\xbf' * (pad // 2))
    pool_off = len(code)
    for off, reg, val in lit_slots:
        hw1 = 0xF8DF
        hw2 = (reg << 12)
        code[off:off + 4] = struct.pack('<HH', hw1, hw2)
        code.extend(struct.pack('<I', val))

    blob = bytes(code)
    # 回填 imm12（此时已知池位置）
    for i, (off, reg, val) in enumerate(lit_slots):
        target = base + pool_off + i * 4
        pc = base + off + 4
        delta = target - (pc & ~3)
        assert 0 <= delta <= 4095, '字面量偏移过大: %d' % delta
        struct.pack_into('<HH', code, off, 0xF8DF, (reg << 12) | (delta & 0xFFF))

    blob = bytes(code)
    dis = list(md.disasm(blob, base))

    # ---------- 自检 ----------
    # (1) 代码区（到池之前）必须完整解码，去掉尾部对齐 nop 后以 bx lr 收尾
    code_dis = [x for x in dis if x.address < base + pool_off]
    while code_dis and code_dis[-1].mnemonic == 'nop':
        code_dis.pop()
    assert code_dis and code_dis[-1].mnemonic == 'bx' and code_dis[-1].op_str == 'lr', \
        '代码区未以 bx lr 结尾: %s' % (code_dis[-1] if code_dis else '空')
    consumed = sum(x.size for x in code_dis)
    n_pad = len(code_dis) and (code_dis[-1].address + code_dis[-1].size - base)
    popped = pool_off - n_pad if n_pad else 0
    assert n_pad + popped == pool_off, \
        '代码区未完整解码 (解码 %d + 对齐 %d != %d)' % (n_pad, popped, pool_off)
    # (2) 字面量池必须正好是预期的常量序列
    want_pool = [fmt[it[2]] for it in seq if it[0] == 'LIT']
    got_pool = [struct.unpack('<I', blob[pool_off + i * 4:pool_off + i * 4 + 4])[0]
                for i in range(len(want_pool))]
    assert got_pool == want_pool, '字面量池内容不符: %s != %s' % (got_pool, want_pool)
    # (3) 每条 ldr.w 的目标必须就是池中对应常量
    for i, (off, reg, val) in enumerate(lit_slots):
        tgt = base + pool_off + i * 4
        assert struct.unpack('<I', blob[tgt - base:tgt - base + 4])[0] == val
    return blob, dis, pool_off, want_pool


# ---------------------------------------------------------------- trampoline 定义
# A：蓝牙扫描行循环（HOOK_A）
#   命中 r15c0 -> E0F = 1，并清掉 local_64[row] 的 bit0（该行位图 = r0）
#   未命中     -> E0F = 0
#   返回前恢复 r1 = ROWPIN（原指令 ldr r1,[pc,#0x370] 的语义）
SEQ_A = [
    ('i', 'cmp r5, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),                 # E0F = 1（矩阵 Fn 按下）
    ('i', 'add r1, sp, #{l64}'),
    ('i', 'ldr.w r2, [r1, r5, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r5, lsl #2]'),     # 清 local_64[row] 的 bit0
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),                 # E0F = 0（矩阵 Fn 松开）
    ('L', '.restore'),
    ('LIT', 'r1', 'rowpin'),
    ('i', 'bx lr'),
]

# B：2.4G 扫描行循环（HOOK_B）
#   与 A 同义，但 2.4G 路径在钩子之后**用寄存器 r0** 逐位测试行位图，
#   所以必须同时清 r0 的 bit0（只改 local_84[row] 是无效的 —— 这是 v5 的已知缺陷）；
#   末尾用 cmp r0,#0 复原标志位（原代码 0x4125E 的 beq 依赖 bics 的 Z 位）。
SEQ_B = [
    ('i', 'cmp r4, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),                 # E0F = 1
    ('i', 'bic.w r0, r0, #{mbit}'),         # 清 r0 的 bit0（2.4G 逐位测试用的是 r0）
    ('i', 'add r1, sp, #{l84}'),
    ('i', 'ldr.w r2, [r1, r4, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r4, lsl #2]'),     # 清 local_84[row] 的 bit0
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),                 # E0F = 0
    ('L', '.restore'),
    ('i', 'ldrb.w r2, [sl, r4]'),           # 复原原指令（r2 = 行掩码字节）
    ('i', 'cmp r0, #0'),                    # 复原标志位（原 beq 依赖 bics 的 Z）
    ('i', 'bx lr'),
]

# C：2.4G 的 P0.6 判定 / 伪键注入（HOOK_C，替换原 18 字节）
#   原逻辑：r7 = (P0.IN bit6 == 0) 即「Fn 按住」；
#           P0.6 按下时写 local_98[0] = 0xdf（伪 Fn 键），并让 uVar11(r5) 从 1 开始。
#   v6  ：r7 = E0F（矩阵 Fn 按住）；
#          P0.6 按下时写 local_98[0] = 0xE0（伪 Left Ctrl 键），
#          由 HID 组装函数转成修饰位 0（KEYTBL_G[120] 原本就是 0xE0，通路已验证）。
SEQ_C = [
    ('LIT', 'r0', 'e0f'),
    ('i', 'ldrb r0, [r0]'),
    ('i', 'mov r7, r0'),                    # r7 = 矩阵 Fn（保持标志）
    ('i', 'mov.w r0, #0x50000000'),
    ('i', 'ldr.w r0, [r0, #0x510]'),        # r0 = P0.IN
    ('i', 'lsls r0, r0, #0x19'),            # bit6 -> bit31
    ('b', 'bpl', '.pressed'),               # P0.6 为低 -> 按下
    ('i', 'movs r5, #0'),
    ('b', 'b', '.done'),
    ('L', '.pressed'),
    ('i', 'movs r5, #1'),                   # uVar11 = 1
    ('i', 'movs r1, #0xE0'),
    ('i', 'strb.w r1, [sp, #0x10]'),        # local_98[0] = 0xE0（伪 Left Ctrl 键）
    ('L', '.done'),
    ('i', 'bx lr'),
]

# D：蓝牙扫描里的内联 P0.IN 读（HOOK_D，替换原 22 字节）
#   原逻辑：r2 = P0.IN bit6（1 = P0.6 松开），随后 cbnz r2 -> 走「普通键」分支。
#   该条件实际是「P0.6 松开 = Fn 未按住」。
#   v6  ：改成读 E0F（矩阵 Fn）：r2 = 1 表示矩阵 Fn 未按住。
SEQ_D = [
    ('LIT', 'r2', 'e0f'),
    ('i', 'ldrb r2, [r2]'),
    ('i', 'cmp r2, #0'),
    ('b', 'bne', '.held'),
    ('i', 'movs r2, #1'),                   # 矩阵 Fn 未按住
    ('i', 'bx lr'),
    ('L', '.held'),
    ('i', 'movs r2, #0'),                   # 矩阵 Fn 按住
    ('i', 'bx lr'),
]

# E：蓝牙 HID 报告组装的修饰字节清零（HOOK_E，替换原 4 字节）
#   原指令：movs r3,#0 ; strb r3,[r1]   （*param_1 = 0，param_1[0] 即修饰字节）
#   v6  ：*param_1 = (P0.6 为低 ? 1 : 0)，即注入 Left Ctrl 修饰位 0。
#   返回时 r3 必须为 0（后续 0x23A7A 的 strb r3,[r1,#7] 依赖它）。
SEQ_E = [
    ('i', 'movs r3, #0'),
    ('i', 'strb r3, [r1]'),                # *param_1 = 0
    ('i', 'mov.w r0, #0x50000000'),
    ('i', 'ldr.w r0, [r0, #0x510]'),        # r0 = P0.IN
    ('i', 'lsls r0, r0, #0x19'),            # bit6 -> bit31
    ('b', 'bpl', '.pressed'),
    ('b', 'b', '.fin'),
    ('L', '.pressed'),
    ('i', 'movs r3, #1'),
    ('i', 'strb r3, [r1]'),                # *param_1 = 1（Left Ctrl）
    ('L', '.fin'),
    ('i', 'movs r3, #0'),
    ('i', 'bx lr'),
]

FMT = dict(row=ROW, mbit=BIT, l64=0x1C, l84=0x24,
           e0f=E0F, e0f2=E0F2, p0in=P0IN, rowpin=ROWPIN)


# ---------------------------------------------------------------- 工具
def scan_ram_refs(data):
    """扫描全映像里所有 pc 相对字面量，返回落在 RAM 区的地址集合。"""
    vals = set()
    for i in range(0, len(data) - 2, 2):
        hw = struct.unpack('<H', data[i:i + 2])[0]
        if (hw & 0xF800) == 0x4800:
            base = (i + 4) & ~3
            tgt = base + (hw & 0xFF) * 4
        elif (hw & 0xFF7F) == 0xF85F:
            base = (i + 4) & ~3
            tgt = base + (hw & 0xFFF)
        else:
            continue
        if tgt + 4 > len(data):
            continue
        v = struct.unpack('<I', data[tgt:tgt + 4])[0]
        if 0x20000000 <= v <= 0x20007FFF:
            vals.add(v)
    return vals


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(
        description='KC-1957 左Ctrl <-> Fn 完全互换补丁 v6（直接对原始固件打补丁）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例：\n'
               '  python fn_swap_patch.py KC-1957_88.bin                  # 干跑，检查\n'
               '  python fn_swap_patch.py KC-1957_88.bin --apply           # 写出补丁固件\n'
               '  python fn_swap_patch.py KC-1957_88.bin --force-mask --apply\n')
    ap.add_argument('bin')
    ap.add_argument('--out', default=None,
                    help='输出文件（默认与输入同名）')
    ap.add_argument('--apply', action='store_true',
                    help='实际写盘（缺省为干跑，只报告不修改）')
    ap.add_argument('--force-mask', action='store_true',
                    help='键盘掩码与预期值不符时忽略警告，按「实际值+位操作」强制修补')
    ap.add_argument('--force', action='store_true',
                    help='在 --force-mask 基础上，连钩子代码点的字节差异也一并忽略')
    args = ap.parse_args()

    src = args.bin
    out = args.out or src
    data = bytearray(open(src, 'rb').read())
    orig_len = len(data)

    print('=' * 78)
    print('左Ctrl <-> Fn 完全互换改造补丁 v6（直接在原始固件上打补丁）')
    print('=' * 78)
    print('  输入      : %s  (%d 字节)' % (src, orig_len))
    print('  E0F       : 0x%08X  (复用为「矩阵 r15c0 Fn 按下」)' % E0F)
    print('  E0F2      : 0x%08X  (新增：P0.6 去抖后状态，仅去抖状态机使用)' % E0F2)
    print('  FN_HELD   : 0x%08X  (Fn 层激活 = E0F && D7B，本补丁不写)' % FN_HELD)
    print('  强制模式  : %s' % ('--force（掩码+代码点全部忽略）'
                                if args.force else
                                ('--force-mask（仅忽略掩码差异）' if args.force_mask else
                                 '关（不符即中止）')))
    print()

    # ---- 0. RAM 变量选址安全复核 ----
    print('=== 0. 新变量选址复核（E0F2 @ 0x%08X） ===' % E0F2)
    ram_refs = scan_ram_refs(bytes(data))
    ram_refs.discard(E0F2)
    # 新变量所在 256 字节窗口必须完全没有 pc 相对字面量引用
    window = [v for v in ram_refs if E0F2 <= v < E0F2 + 0x100]
    assert not window, 'E0F2 选址窗口 0x%08X-0x%08X 内存在 RAM 引用: %s' % \
        (E0F2, E0F2 + 0x100, [hex(v) for v in sorted(window)])
    # 精确普查（按函数边界反汇编 2434 个函数）实测：661 个 RAM 变量，最高 0x20003928。
    # 下面这个扫描是保守口径（每 2 字节扫一次，会把落在指令中间的半字误当成 ldr），
    # 因此计数略多（665），且最高项可能落在误报上 —— 只用于「窗口内是否有引用」这一判断。
    print('  RAM 变量引用（保守扫描）：%d 个（精确普查为 661 个，含 8 个误报）' % len(ram_refs))
    print('  E0F2 窗口 0x%08X-0x%08X 内引用数: 0  ->  选址安全'
          % (E0F2, E0F2 + 0x100))
    print('  （精确普查参考：按函数边界反汇编实测 661 个 RAM 变量，最高 0x20003928，'
          '本变量在其上方 +3616 字节）')
    print()

    # ---- 0b. 语义自洽检查（不依赖原字节断言，独立验证改造前提成立） ----
    print('=== 0b. 语义自洽检查 ===')

    # (1) HOOK_A 覆盖的是 `ldr r1, [pc, #imm]`（原指令在 HOOK_A+2）。
    #     trampoline A 把它替换成「硬编码 ROWPIN」，因此必须确认原指令的
    #     字面量池槽里存的就是同一个值，否则 r1 变了，后面
    #     `ldrb r2, [r1, r5]`（读行引脚号）会读到错误地址。
    _ldr = HOOK_A + 2
    _hw = struct.unpack('<H', bytes(data[_ldr:_ldr + 2]))[0]
    assert (_hw & 0xF800) == 0x4800 and ((_hw >> 8) & 7) == 1, \
        'HOOK_A+2 处不是预期的 ldr r1,[pc,#imm]（实为 0x%04X）' % _hw
    _pool = ((_ldr + 4) & ~3) + (_hw & 0xFF) * 4
    _val = struct.unpack('<I', bytes(data[_pool:_pool + 4]))[0]
    assert _val == ROWPIN, \
        'HOOK_A 覆盖的 ldr r1,[pc,#%#x] 池槽 0x%06X = 0x%08X，与硬编码 ROWPIN 0x%08X 不一致' \
        % ((_hw & 0xFF) * 4, _pool, _val, ROWPIN)
    print('  HOOK_A 的 ldr r1,[pc,#0x%x] -> 池槽 0x%06X = 0x%08X == ROWPIN  OK'
          % ((_hw & 0xFF) * 4, _pool, _val))

    # (2) r15c0 改成 Fn 之后，Fn 完全依赖该键位被扫描到。
    #     蓝牙掩码高有效：row15 的 bit0 必须为 1；
    #     2.4G 掩码低有效：row15 的 bit0 必须为 0。
    #     若目标固件的掩码表不同导致该位被屏蔽，Fn 将永不触发 —— 必须中止。
    _bt15 = data[OFF_BT_MASK_BASE + 15]
    _g15 = data[OFF_G_MASK_BASE + 15]
    assert (_bt15 & BIT), \
        '蓝牙行掩码 row15 = 0x%02X，bit0(col0) 被屏蔽 —— r15c0 不参与扫描，Fn 将永不触发' % _bt15
    assert not (_g15 & BIT), \
        '2.4G行掩码 row15 = 0x%02X，bit0(col0) 被屏蔽 —— r15c0 不参与扫描，Fn 将永不触发' % _g15
    print('  蓝牙行掩码 row15 = 0x%02X（bit0=1，放行 col0）      OK' % _bt15)
    print('  2.4G行掩码 row15 = 0x%02X（bit0=0，放行 col0）      OK' % _g15)

    # (3) 2.4G 行循环里 `ldrb.w r2, [sl, r4]` 的 sl 基址（0x4A77A）
    #     与蓝牙的 ROWPIN（0x2CBE0）必须是同一张行引脚表的内容，
    #     trampoline B 复原的正是原指令，故只作一致性告知。
    if 0x4A77A + 16 <= len(data) and 0x2CBE0 + 16 <= len(data):
        same = bytes(data[0x2CBE0:0x2CBE0 + 16]) == bytes(data[0x4A77A:0x4A77A + 16])
        print('  蓝牙 ROWPIN(0x2CBE0) 与 2.4G sl(0x4A77A) 行引脚表内容%s'
              % ('一致' if same else '不一致（不影响本补丁，两条路径各自独立）'))
    print()

    # ---- 1. 原字节安全断言 ----
    print('=== 1. 原字节安全断言 ===')

    print('  --- 1a. 钩子代码点 + 键码表条目（不符需 --force） ---')
    code_bad = []
    for addr, want in sorted(ORIG_CODE.items()):
        got = bytes(data[addr:addr + len(want)])
        good = got == want
        if not good:
            code_bad.append((addr, want, got))
        print('  0x%06X  期望 %-40s 实际 %-40s %s'
              % (addr, want.hex(' ').upper(), got.hex(' ').upper(), 'OK' if good else '!! 不符'))

    print('  --- 1b. 字面量池槽（硬约束，不符即中止） ---')
    pool_bad = []
    for addr, want in sorted(ORIG_POOL.items()):
        got = bytes(data[addr:addr + len(want)])
        good = got == want
        if not good:
            pool_bad.append((addr, want, got))
        print('  0x%06X  期望 %-40s 实际 %-40s %s'
              % (addr, want.hex(' ').upper(), got.hex(' ').upper(), 'OK' if good else '!! 不符'))

    print('  --- 1c. 键盘掩码点（不符可 --force-mask 强制修补） ---')
    mask_bad = []
    for addr, want in sorted(ORIG_MASK.items()):
        got = bytes(data[addr:addr + len(want)])
        good = got == want
        if not good:
            mask_bad.append((addr, want, got))
        op, bit = MASK_BIT_OP[addr]
        print('  0x%06X  期望 %-40s 实际 %-40s %s   (目标: %s bit%d)'
              % (addr, want.hex(' ').upper(), got.hex(' ').upper(),
                 'OK' if good else '!! 不符', op, bit.bit_length() - 1))

    # 掩码目标值：由「实际值 + 位操作」推出，绝不套用原版常量。
    mask_target = {}
    for addr, want in ORIG_MASK.items():
        actual = data[addr]
        op, bit = MASK_BIT_OP[addr]
        if op == '置':
            mask_target[addr] = actual | bit
        else:
            mask_target[addr] = actual & (~bit & 0xFF)

    if code_bad:
        if not args.force:
            print()
            print('  !! 钩子代码点/键码表与预期不符（%d 处），已中止。' % len(code_bad))
            print('     这些地址决定补丁的语义落点，强行写入可能破坏其它逻辑。')
            print('     若确认目标固件的该处与本版本语义一致，可用 --force 强制继续。')
            raise SystemExit(2)
        print()
        print('  !! 注意：--force 已启用，钩子代码点的 %d 处字节差异将被忽略：' % len(code_bad))
        for addr, want, got in code_bad:
            print('     0x%06X  期望 %s 实际 %s' % (addr, want.hex(' ').upper(), got.hex(' ').upper()))
        print('     该地址的原始指令将被补丁内容完全覆盖，请自行确认语义落点正确。')

    if pool_bad:
        print()
        print('  !! 字面量池槽与预期不符（%d 处），已中止（该项为硬约束）。' % len(pool_bad))
        for addr, want, got in pool_bad:
            print('     0x%06X  期望 %s 实际 %s' % (addr, want.hex(' ').upper(), got.hex(' ').upper()))
        print('     该池槽必须指向 0x20001E0F（去抖状态机写的变量），否则补丁不成立。')
        raise SystemExit(2)

    if mask_bad:
        if not (args.force_mask or args.force):
            print()
            print('  !! 键盘掩码与预期值不符（%d 处），已中止。' % len(mask_bad))
            for addr, want, got in mask_bad:
                op, bit = MASK_BIT_OP[addr]
                print('     0x%06X  期望 %s 实际 %s' % (addr, want.hex(' ').upper(), got.hex(' ').upper()))
            print('     若这属于同型号的变体固件（掩码表取值不同、语义相同），')
            print('     可加 --force-mask 忽略差异：补丁将按「实际值 + 位操作」强制修补——')
            for addr, want, got in mask_bad:
                op, bit = MASK_BIT_OP[addr]
                print('       0x%06X  实际 0x%02X -> 强制写入 0x%02X（%s bit%d，其余位保留）'
                      % (addr, got[0], mask_target[addr], op, bit.bit_length() - 1))
            print('     不会套用原版常量，因此变体固件掩码表的其余位不会被覆盖。')
            raise SystemExit(2)
        print()
        print('  !! 注意：强制修补已启用，键盘掩码的 %d 处差异将被忽略：' % len(mask_bad))
        for addr, want, got in mask_bad:
            op, bit = MASK_BIT_OP[addr]
            print('     0x%06X  期望 %s 实际 %s -> 强制写入 0x%02X（实际值 %s bit%d，其余位保留）'
                  % (addr, want.hex(' ').upper(), got.hex(' ').upper(),
                     mask_target[addr], op, bit.bit_length() - 1))
    print()

    # ---- 2. 代码空洞校验 ----
    print('=== 2. 代码空洞校验（限定 0x%05X-0x%05X） ===' % CAVE_LIMIT)
    lo_lim, hi_lim = CAVE_LIMIT
    CAVES = [('A', CAVE_A), ('B', CAVE_B), ('C', CAVE_C), ('D', CAVE_D), ('E', CAVE_E)]
    for nm, base in CAVES:
        assert lo_lim <= base < hi_lim, \
            'trampoline %s @0x%06X 越出限定区间 0x%05X-0x%05X' % (nm, base, lo_lim, hi_lim)
        seg = bytes(data[base:base + 0x200])
        assert seg == b'\xff' * 0x200, \
            'trampoline %s @0x%06X 附近 512 字节并非全 0xFF' % (nm, base)
        print('  trampoline %s @0x%06X  区间内 OK，附近 512 字节全为 0xFF OK' % (nm, base))
    print()

    # ---- 3. 汇编 trampoline ----
    print('=== 3. 汇编 5 个 trampoline ===')
    blobs = {}
    for nm, seq, base in [('A', SEQ_A, CAVE_A), ('B', SEQ_B, CAVE_B), ('C', SEQ_C, CAVE_C),
                          ('D', SEQ_D, CAVE_D), ('E', SEQ_E, CAVE_E)]:
        blob, dis, pool, poolvals = build(seq, FMT, base)
        blobs[nm] = (blob, base)
        print('  --- trampoline %s @0x%06X (%d 字节, 池@+0x%X) ---' % (nm, base, len(blob), pool))
        for x in dis:
            if x.address >= base + pool:
                break
            print('     0x%05X: %-26s %-12s %s'
                  % (x.address, x.mnemonic, x.op_str, x.bytes.hex()))
        print('     字面量池: %s' % [hex(v) for v in poolvals])
        print()

    # ---- 4. 写 trampoline 到空洞 ----
    print('=== 4. 写入代码空洞 ===')
    for nm, (blob, base) in blobs.items():
        seg = bytes(data[base:base + len(blob)])
        assert seg == b'\xff' * len(blob), '%s 空洞非空 @0x%06X' % (nm, base)
        data[base:base + len(blob)] = blob
        print('  trampoline %s -> 0x%06X  (%d 字节)' % (nm, base, len(blob)))
    print()

    # ---- 5. 打钩子 ----
    print('=== 5. 打钩子 ===')

    def bl_to(addr, target, size):
        enc, _ = ks.asm('bl 0x%x' % target, addr=addr, as_bytes=False)
        b = bytes(enc)
        assert len(b) == 4, 'bl 编码宽度异常'
        d0 = list(md.disasm(b, addr, 1))
        assert d0 and d0[0].mnemonic == 'bl' and int(d0[0].op_str.lstrip('#'), 0) == target
        data[addr:addr + 4] = b
        rest = b'\x00\xbf' * ((size - 4) // 2)
        if size > 4:
            data[addr + 4:addr + size] = rest
        return b

    b = bl_to(HOOK_A, CAVE_A, 4)
    print('  0x%06X  bl 0x%06X          %s   (蓝牙行循环，覆盖 nop+ldr r1)'
          % (HOOK_A, CAVE_A, b.hex(' ').upper()))

    b = bl_to(HOOK_B, CAVE_B, 4)
    print('  0x%06X  bl 0x%06X          %s   (2.4G 行循环，覆盖 ldrb.w r2,[sl,r4])'
          % (HOOK_B, CAVE_B, b.hex(' ').upper()))

    b = bl_to(HOOK_C, CAVE_C, 18)
    print('  0x%06X  bl 0x%06X + 7*nop  %s   (2.4G P0.6 判定/伪键，18 字节全替换)'
          % (HOOK_C, CAVE_C, b.hex(' ').upper()))

    b = bl_to(HOOK_D, CAVE_D, 22)
    print('  0x%06X  bl 0x%06X + 9*nop  %s   (BT 扫描内联 P0.IN 读，22 字节全替换)'
          % (HOOK_D, CAVE_D, b.hex(' ').upper()))

    b = bl_to(HOOK_E, CAVE_E, 4)
    print('  0x%06X  bl 0x%06X          %s   (BT HID 组装修饰字节清零，4 字节全替换)'
          % (HOOK_E, CAVE_E, b.hex(' ').upper()))
    print()

    # ---- 6. 数据补丁 ----
    print('=== 6. 数据补丁 ===')
    for label, off in (('蓝牙', OFF_BT_MASK), ('2.4G', OFF_G_MASK)):
        old = data[off]
        new = mask_target[off]
        op, bit = MASK_BIT_OP[off]
        data[off] = new
        note = '（与原版目标一致）' if old == ORIG_MASK[off][0] \
            else '（强制修补：按实际值 %s bit%d）' % (op, bit.bit_length() - 1)
        print('  %-4s 0x%06X  0x%02X -> 0x%02X  %s bit%d %s'
              % (label, off, old, new, op, bit.bit_length() - 1, note))
    print('        说明：掩码只改 bit4（col4），使 r12c4 参与扫描；其余位原样保留。')
    print()

    for label, off in (('KEYTBL_BT[100] r12c4', OFF_BT_KEY100),
                       ('KEYTBL_BT[120] r15c0', OFF_BT_KEY120),
                       ('KEYTBL_G [100] r12c4', OFF_G_KEY100),
                       ('KEYTBL_G [120] r15c0', OFF_G_KEY120)):
        old = data[off]
        new = NEW_KEY[off]
        data[off] = new
        print('  %-22s 0x%06X  0x%02X -> 0x%02X' % (label, off, old, new))
    print('        说明：r12c4 -> 0xE0 (Left Ctrl)；r15c0 -> 0x00（不产生键码，改为充当 Fn）。')
    print()

    for addr, new in sorted(NEW_POOL.items()):
        old = struct.unpack('<I', bytes(data[addr:addr + 4]))[0]
        data[addr:addr + 4] = struct.pack('<I', new)
        print('  池槽 0x%06X        0x%08X -> 0x%08X' % (addr, old, new))
    print('        说明：去抖状态机 FUN_0001b75c 的 E0F 池槽改指 E0F2，')
    print('              使 P0.6 去抖照常进行但不再污染 E0F（E0F 改为矩阵 Fn 专用）。')
    print()

    assert len(data) == orig_len, '固件长度被改变'

    # ---- 7. 写入后反汇编复核 ----
    print('=== 7. 写入后反汇编复核 ===')
    for addr, n, label in [(HOOK_A, 0x10, '蓝牙钩子 A'),
                           (HOOK_B, 0x10, '2.4G 钩子 B'),
                           (HOOK_C, 0x18, '2.4G 钩子 C'),
                           (HOOK_D, 0x1C, 'BT 钩子 D'),
                           (HOOK_E, 0x10, 'BT 钩子 E')]:
        print('  --- %s @0x%05X ---' % (label, addr))
        for x in md.disasm(bytes(data[addr:addr + n]), addr):
            print('     0x%05X: %-26s %-12s %s'
                  % (x.address, x.mnemonic, x.op_str, x.bytes.hex()))
        print()

    print('  --- 键码表与池槽复核 ---')
    for label, off in (('KEYTBL_BT[100]', OFF_BT_KEY100), ('KEYTBL_BT[120]', OFF_BT_KEY120),
                       ('KEYTBL_G [100]', OFF_G_KEY100), ('KEYTBL_G [120]', OFF_G_KEY120)):
        print('     %-16s @0x%06X = 0x%02X' % (label, off, data[off]))
    v = struct.unpack('<I', bytes(data[OFF_POOL_E0F:OFF_POOL_E0F + 4]))[0]
    print('     池槽 0x%06X        = 0x%08X  (E0F2)' % (OFF_POOL_E0F, v))
    print()

    # ---- 8. 完整性 ----
    print('=== 8. 完整性 ===')
    src_bytes = open(src, 'rb').read()
    diff = [i for i in range(orig_len) if data[i] != src_bytes[i]]
    print('  改动字节数: %d' % len(diff))
    runs = []
    for k, g in __import__('itertools').groupby(enumerate(diff), lambda t: t[1] - t[0]):
        g = list(g)
        runs.append((g[0][1], g[-1][1]))
    for s, e in runs:
        print('    0x%06X - 0x%06X  (%d 字节)' % (s, e, e - s + 1))
    print('  向量表 Reset_Handler = 0x%08X (应不变)'
          % struct.unpack('<I', bytes(data[4:8]))[0])

    if args.apply:
        bak = out + '.bak'
        if os.path.exists(bak):
            print('  !! 备份已存在，跳过备份（保留原备份）: %s' % bak)
        else:
            open(bak, 'wb').write(open(src, 'rb').read())
            print('  已备份 -> %s' % bak)
        open(out, 'wb').write(bytes(data))
        print('  已写入 -> %s' % out)
    else:
        print('  （干跑模式，未写入。加 --apply 生效）')


if __name__ == '__main__':
    main()
