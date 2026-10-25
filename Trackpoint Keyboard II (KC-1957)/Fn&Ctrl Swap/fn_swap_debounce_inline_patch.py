#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""KC-1957_88.bin  左Ctrl <-> Fn 完全互换改造 —— v8（v7 + E0F 读取点置入行循环内）

直接从**原始固件**（KC-1957_88.bin / KC-1957_88_orig.bin）打补丁，不依赖任何中间版本。

================================================================================
改造目标（相对 v7）
================================================================================
  v7 在 v6 基础上给 P0.6 的 Left Ctrl 注入加了去抖（读 E0F2）。
  但 v6/v7 沿用了「在行循环之前（HOOK_C）一次性把 E0F 读进 r7」的旧结构，
  而 r7 在 2.4G 扫描函数里被**两处**消费：
      · 行循环内  0x41286  `cbz r7`  —— Fn 次级行为
      · 行循环后  0x413D0  `cbz r7`  —— Fn 后置动作
  于是 r7 反映的是「上一轮扫描」的 Fn 状态，相对矩阵扫描最多滞后 1 个扫描周期。

  v8 的改动（仅 2.4G 路径，BT 路径本就正确，见下）：
  1) 删除 HOOK_C（行循环前）里「r7 = E0F」的读取 —— 那里读到的本就是上一轮的值。
  2) 改为在**行循环内**的钩子 B（HOOK_B，每个 row 都执行）末尾刷新 r7 = E0F。
     这样：
       · 行循环内 0x41286 的 cbz 用到的是「本轮已扫过 row15 后的最新 E0F」
         （row15 是最后一行，故对 row0..14 为上一轮、对 row15 为本轮，
           矩阵式 Fn 的固有 1 周期无法消除，但已与 BT 路径对齐）；
       · 行循环后 0x413D0 的 cbz 用到的是「本轮扫得的当前 E0F」（零滞后）。
  3) BT 路径：其 E0F 读取点 HOOK_D 本就位于 BT 行循环**之内**（每个 row 消费前
     即时读 E0F 进 r2），所以 BT 从一开始就没有这个滞后，v8 不再改动 BT 任何字节。

  说明：矩阵式 Fn（r15c0）的 E0F 必须在扫描到 row15 时才确定，而 row15 排在
  最后一行，因此相对「GPIO 直读式 Fn（P0.6）零滞后」必然存在最多 1 个扫描周期
  的固有滞后。v8 的意义是把 2.4G 路径从「用上一轮 Fn 状态」纠正为「用本轮最新
  状态参与行循环后的 Fn 后置动作，并在行循环内尽量贴近最新」，与 BT 路径对齐。

================================================================================
键位事实（同 v6/v7，已逐字节核对）
--------------------------------------------------------------------------------
  矩阵 r15c0 = idx 120 = 0xE0 (Left Ctrl)   BT 表 0x2CBF0 / 2.4G 表 0x4A6FA
  矩阵 r12c4 = idx 100 = 0x00 (空槽)        BT 表 0x2CC54 / 2.4G 表 0x4A75E
  P0.6 = GPIO 低有效 = 旧 Fn 键
       E0E(0x20001E0E) 去抖计数 -> E0F(0x20001E0F) 去抖按下
       -> 2109(0x20002109) Fn 层激活 = E0F && D7B
       v6 起去抖状态机改写 E0F2(0x20004800)，E0F 改为矩阵 r15c0 专用

================================================================================
补丁点清单（相对原始固件；与 v7 完全一致，仅 trampoline B/C 行为不同）
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
  HOOK_B 0x41252  (4B)   2.4G 扫描行循环    -> trampoline B  ★v8 在此刷新 r7=E0F
  HOOK_C 0x411C6  (18B)  2.4G P0.6 判定/伪键 -> trampoline C  ★v8 不再在此读 r7=E0F
  HOOK_D 0x1EB74  (22B)  BT 扫描内联 P0.IN 读 -> trampoline D
  HOOK_E 0x23A76  (4B)   BT HID 组装修饰位   -> trampoline E

命令行
  python fn_swap_debounce_inline_patch.py <in.bin> [--out <out.bin>] [--apply]
                          [--force-mask] [--force]
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
FN_HELD = 0x20002109          # Fn 层激活 = E0F && D7B，由 FUN_00020bd8 计算
D7B = 0x20001D7B              # Fn 档位门控
P0IN = 0x50000510             # P0.IN（bit6 = P0.6，低有效）
ROWPIN = 0x2CBE0              # 蓝牙行引脚表

ROW = 15                     # r15c0 所在行
BIT = 0x01                    # r15c0 所在列 (col0 -> bit0)

# 补丁点
HOOK_A = 0x1E4E4
HOOK_B = 0x41252
HOOK_C = 0x411C6
HOOK_D = 0x1EB74
HOOK_E = 0x23A76

# 代码空洞
CAVE_A = 0x050000
CAVE_B = 0x050100
CAVE_C = 0x050200
CAVE_D = 0x050300
CAVE_E = 0x050400
CAVE_LIMIT = (0x50000, 0x60000)

# 数据补丁
OFF_BT_MASK_BASE = 0x1E840
OFF_G_MASK_BASE = 0x4A6A6
OFF_BT_MASK = OFF_BT_MASK_BASE + 12
OFF_G_MASK = OFF_G_MASK_BASE + 12
OFF_BT_KEY100 = 0x2CC54
OFF_BT_KEY120 = 0x2CC68
OFF_G_KEY100 = 0x4A75E
OFF_G_KEY120 = 0x4A772
OFF_POOL_E0F = 0x1B8A0

MASK_BIT_OP = {
    OFF_BT_MASK: ('置', 0x10),
    OFF_G_MASK: ('清', 0x10),
}

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
    OFF_POOL_E0F: bytes.fromhex('0F1E0020'),
}
ORIG_MASK = {
    OFF_BT_MASK: bytes([0xE7]),
    OFF_G_MASK: bytes([0x1C]),
}
ORIG = dict(ORIG_CODE)
ORIG.update(ORIG_POOL)
ORIG.update(ORIG_MASK)

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
def build(seq, fmt, base):
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

    pad = (-len(code)) % 4
    code.extend(b'\x00\xbf' * (pad // 2))
    pool_off = len(code)
    for off, reg, val in lit_slots:
        code[off:off + 4] = struct.pack('<HH', 0xF8DF, (reg << 12))
        code.extend(struct.pack('<I', val))

    blob = bytes(code)
    for i, (off, reg, val) in enumerate(lit_slots):
        target = base + pool_off + i * 4
        pc = base + off + 4
        delta = target - (pc & ~3)
        assert 0 <= delta <= 4095, '字面量偏移过大: %d' % delta
        struct.pack_into('<HH', code, off, 0xF8DF, (reg << 12) | (delta & 0xFFF))

    blob = bytes(code)
    dis = list(md.disasm(blob, base))

    code_dis = [x for x in dis if x.address < base + pool_off]
    while code_dis and code_dis[-1].mnemonic == 'nop':
        code_dis.pop()
    assert code_dis and code_dis[-1].mnemonic == 'bx' and code_dis[-1].op_str == 'lr', \
        '代码区未以 bx lr 结尾: %s' % (code_dis[-1] if code_dis else '空')
    want_pool = [fmt[it[2]] for it in seq if it[0] == 'LIT']
    got_pool = [struct.unpack('<I', blob[pool_off + i * 4:pool_off + i * 4 + 4])[0]
                for i in range(len(want_pool))]
    assert got_pool == want_pool, '字面量池内容不符: %s != %s' % (got_pool, want_pool)
    return blob, dis, pool_off, want_pool


# ---------------------------------------------------------------- trampoline 定义
# A：蓝牙扫描行循环（HOOK_A）—— 与 v7 完全相同
SEQ_A = [
    ('i', 'cmp r5, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),
    ('i', 'add r1, sp, #{l64}'),
    ('i', 'ldr.w r2, [r1, r5, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r5, lsl #2]'),
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),
    ('L', '.restore'),
    ('LIT', 'r1', 'rowpin'),
    ('i', 'bx lr'),
]

# B：2.4G 扫描行循环（HOOK_B）—— ★v8 关键改动：.restore 处刷新 r7 = E0F
#   原 v7 在「行循环前」一次性把 E0F 读进 r7（HOOK_C），导致 r7 滞后上一轮；
#   v8 改为在「行循环内」（本钩子每个 row 都执行）末尾刷新 r7 = E0F，
#   使行循环内 0x41286 与行循环后 0x413D0 两处 cbz r7 都用到最新 Fn 状态。
SEQ_B = [
    ('i', 'cmp r4, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),                 # E0F = 1（矩阵 Fn 按下）
    ('i', 'bic.w r0, r0, #{mbit}'),         # 清 r0 的 bit0（2.4G 逐位测试用的是 r0）
    ('i', 'add r1, sp, #{l84}'),
    ('i', 'ldr.w r2, [r1, r4, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r4, lsl #2]'),     # 清 local_84[row] 的 bit0
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),                 # E0F = 0（矩阵 Fn 松开）
    ('L', '.restore'),
    # ★v8：行循环内刷新 r7 = E0F（最新 Fn 标志）
    ('LIT', 'r7', 'e0f'),
    ('i', 'ldrb r7, [r7]'),                 # r7 = 当前 E0F（矩阵 Fn，最新）
    ('i', 'ldrb.w r2, [sl, r4]'),           # 复原原指令（r2 = 行掩码字节）
    ('i', 'cmp r0, #0'),                    # 复原标志位（原 beq 依赖 bics 的 Z）
    ('i', 'bx lr'),
]

# C：2.4G 的 P0.6 判定 / 伪键注入（HOOK_C，替换原 18 字节）
#   v8：★删除「r7 = E0F」的读取（改由 trampoline B 在行循环内刷新），
#       仅保留 P0.6 -> Left Ctrl 注入（读去抖 E0F2，与 v7 一致）。
SEQ_C = [
    ('LIT', 'r0', 'e0f2'),
    ('i', 'ldrb r0, [r0]'),                 # r0 = E0F2（去抖后 P0.6）
    ('i', 'cmp r0, #1'),                    # 去抖后按下？
    ('b', 'bne', '.up'),                    # 否 -> 松开
    ('i', 'movs r5, #1'),                   # uVar11 = 1
    ('i', 'movs r1, #0xE0'),
    ('i', 'strb.w r1, [sp, #0x10]'),        # local_98[0] = 0xE0（伪 Left Ctrl 键）
    ('b', 'b', '.done'),
    ('L', '.up'),
    ('i', 'movs r5, #0'),                   # P0.6 松开 -> uVar11 = 0
    ('L', '.done'),
    ('i', 'bx lr'),
]

# D：蓝牙扫描里的内联 P0.IN 读（HOOK_D）—— 与 v7 完全相同
SEQ_D = [
    ('LIT', 'r2', 'e0f'),
    ('i', 'ldrb r2, [r2]'),
    ('i', 'cmp r2, #0'),
    ('b', 'bne', '.held'),
    ('i', 'movs r2, #1'),
    ('i', 'bx lr'),
    ('L', '.held'),
    ('i', 'movs r2, #0'),
    ('i', 'bx lr'),
]

# E：蓝牙 HID 报告组装的修饰字节清零（HOOK_E）—— 与 v7 完全相同
SEQ_E = [
    ('i', 'movs r3, #0'),
    ('i', 'strb r3, [r1]'),
    ('LIT', 'r0', 'e0f2'),
    ('i', 'ldrb r0, [r0]'),
    ('i', 'cmp r0, #1'),
    ('b', 'bne', '.fin'),
    ('i', 'movs r3, #1'),
    ('i', 'strb r3, [r1]'),
    ('L', '.fin'),
    ('i', 'movs r3, #0'),
    ('i', 'bx lr'),
]

FMT = dict(row=ROW, mbit=BIT, l64=0x1C, l84=0x24,
           e0f=E0F, e0f2=E0F2, p0in=P0IN, rowpin=ROWPIN)


# ---------------------------------------------------------------- 工具
def scan_ram_refs(data):
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
        description='KC-1957 左Ctrl <-> Fn 完全互换补丁 v8（v7 + E0F 读取点置入行循环内，直接对原始固件打补丁）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例：\n'
               '  python fn_swap_debounce_inline_patch.py KC-1957_88.bin                  # 干跑，检查\n'
               '  python fn_swap_debounce_inline_patch.py KC-1957_88.bin --apply           # 写出补丁固件\n'
               '  python fn_swap_debounce_inline_patch.py KC-1957_88.bin --force-mask --apply\n')
    ap.add_argument('bin')
    ap.add_argument('--out', default=None)
    ap.add_argument('--apply', action='store_true')
    ap.add_argument('--force-mask', action='store_true')
    ap.add_argument('--force', action='store_true')
    args = ap.parse_args()

    src = args.bin
    out = args.out or src
    data = bytearray(open(src, 'rb').read())
    orig_len = len(data)

    print('=' * 78)
    print('左Ctrl <-> Fn 完全互换改造补丁 v8（v7 + E0F 读取点置入行循环内）')
    print('=' * 78)
    print('  输入      : %s  (%d 字节)' % (src, orig_len))
    print('  E0F       : 0x%08X  (复用为「矩阵 r15c0 Fn 按下」)' % E0F)
    print('  E0F2      : 0x%08X  (P0.6 去抖后状态，仅去抖状态机使用)' % E0F2)
    print('  v8 改动   : 2.4G 钩子 B 行循环内刷新 r7=E0F；钩子 C 不再读 r7=E0F；BT 不变')
    print('  强制模式  : %s' % ('--force' if args.force else
                                ('--force-mask' if args.force_mask else '关（不符即中止）')))
    print()

    # ---- 0. 新变量选址安全复核 ----
    print('=== 0. 新变量选址复核（E0F2 @ 0x%08X） ===' % E0F2)
    ram_refs = scan_ram_refs(bytes(data))
    ram_refs.discard(E0F2)
    window = [v for v in ram_refs if E0F2 <= v < E0F2 + 0x100]
    assert not window, 'E0F2 选址窗口内存在 RAM 引用: %s' % [hex(v) for v in sorted(window)]
    print('  RAM 变量引用（保守扫描）：%d 个' % len(ram_refs))
    print('  E0F2 窗口 0x%08X-0x%08X 内引用数: 0  ->  选址安全' % (E0F2, E0F2 + 0x100))
    print()

    # ---- 0b. 语义自洽检查 ----
    print('=== 0b. 语义自洽检查 ===')
    _ldr = HOOK_A + 2
    _hw = struct.unpack('<H', bytes(data[_ldr:_ldr + 2]))[0]
    assert (_hw & 0xF800) == 0x4800 and ((_hw >> 8) & 7) == 1
    _pool = ((_ldr + 4) & ~3) + (_hw & 0xFF) * 4
    _val = struct.unpack('<I', bytes(data[_pool:_pool + 4]))[0]
    assert _val == ROWPIN
    print('  HOOK_A 的 ldr r1,[pc] -> 池槽 = 0x%08X == ROWPIN  OK' % _val)

    _bt15 = data[OFF_BT_MASK_BASE + 15]
    _g15 = data[OFF_G_MASK_BASE + 15]
    assert (_bt15 & BIT), '蓝牙行掩码 row15 bit0 被屏蔽 —— Fn 将永不触发'
    assert not (_g15 & BIT), '2.4G行掩码 row15 bit0 被屏蔽 —— Fn 将永不触发'
    print('  蓝牙行掩码 row15 = 0x%02X（bit0=1）  OK' % _bt15)
    print('  2.4G行掩码 row15 = 0x%02X（bit0=0）  OK' % _g15)

    # ★v8 专属：确认 2.4G 行循环内 0x41286 与行循环后 0x413D0 两处均消费 r7
    for addr, label in ((0x41286, '行循环内 cbz r7'), (0x413D0, '行循环后 cbz r7')):
        ins = list(md.disasm(bytes(data[addr:addr + 2]), addr, 1))
        ok = bool(ins) and ins[0].mnemonic == 'cbz' and 'r7' in ins[0].op_str
        print('  %s @0x%05X : %s' % (label, addr, 'OK (消费 r7)' if ok else '!! 未找到 cbz r7'))
        assert ok, '%s 未消费 r7，v8 设计前提不成立' % label
    print()

    # ---- 1. 原字节安全断言 ----
    print('=== 1. 原字节安全断言 ===')
    code_bad = []
    for addr, want in sorted(ORIG_CODE.items()):
        got = bytes(data[addr:addr + len(want)])
        good = got == want
        if not good:
            code_bad.append((addr, want, got))
        print('  0x%06X  期望 %-40s 实际 %-40s %s'
              % (addr, want.hex(' ').upper(), got.hex(' ').upper(), 'OK' if good else '!! 不符'))

    pool_bad = []
    for addr, want in sorted(ORIG_POOL.items()):
        got = bytes(data[addr:addr + len(want)])
        good = got == want
        if not good:
            pool_bad.append((addr, want, got))
        print('  0x%06X  期望 %-40s 实际 %-40s %s'
              % (addr, want.hex(' ').upper(), got.hex(' ').upper(), 'OK' if good else '!! 不符'))

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

    mask_target = {}
    for addr, want in ORIG_MASK.items():
        actual = data[addr]
        op, bit = MASK_BIT_OP[addr]
        mask_target[addr] = actual | bit if op == '置' else actual & (~bit & 0xFF)

    if code_bad:
        if not args.force:
            print('\n  !! 钩子代码点/键码表与预期不符（%d 处），已中止。' % len(code_bad))
            raise SystemExit(2)
        print('\n  !! --force 已启用，%d 处字节差异将被忽略。' % len(code_bad))
    if pool_bad:
        print('\n  !! 字面量池槽与预期不符（%d 处），已中止（硬约束）。' % len(pool_bad))
        raise SystemExit(2)
    if mask_bad:
        if not (args.force_mask or args.force):
            print('\n  !! 键盘掩码与预期值不符（%d 处），已中止。' % len(mask_bad))
            raise SystemExit(2)
        print('\n  !! 强制修补已启用。')
    print()

    # ---- 2. 代码空洞校验 ----
    print('=== 2. 代码空洞校验 ===')
    for nm, base in [('A', CAVE_A), ('B', CAVE_B), ('C', CAVE_C), ('D', CAVE_D), ('E', CAVE_E)]:
        assert 0x50000 <= base < 0x60000
        seg = bytes(data[base:base + 0x200])
        assert seg == b'\xff' * 0x200
        print('  trampoline %s @0x%06X  区间内 OK' % (nm, base))
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

    # ---- 4. 写入代码空洞 ----
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
        assert len(b) == 4
        d0 = list(md.disasm(b, addr, 1))
        assert d0 and d0[0].mnemonic == 'bl' and int(d0[0].op_str.lstrip('#'), 0) == target
        data[addr:addr + 4] = b
        rest = b'\x00\xbf' * ((size - 4) // 2)
        if size > 4:
            data[addr + 4:addr + size] = rest
        return b

    b = bl_to(HOOK_A, CAVE_A, 4)
    print('  0x%06X  bl 0x%06X          %s   (蓝牙行循环)' % (HOOK_A, CAVE_A, b.hex(' ').upper()))
    b = bl_to(HOOK_B, CAVE_B, 4)
    print('  0x%06X  bl 0x%06X          %s   (2.4G 行循环，v8 在此刷新 r7=E0F)'
          % (HOOK_B, CAVE_B, b.hex(' ').upper()))
    b = bl_to(HOOK_C, CAVE_C, 18)
    print('  0x%06X  bl 0x%06X + 7*nop  %s   (2.4G P0.6 判定/伪键，v8 不再读 r7=E0F)'
          % (HOOK_C, CAVE_C, b.hex(' ').upper()))
    b = bl_to(HOOK_D, CAVE_D, 22)
    print('  0x%06X  bl 0x%06X + 9*nop  %s   (BT 扫描内联 P0.IN 读)' % (HOOK_D, CAVE_D, b.hex(' ').upper()))
    b = bl_to(HOOK_E, CAVE_E, 4)
    print('  0x%06X  bl 0x%06X          %s   (BT HID 组装修饰字节清零)' % (HOOK_E, CAVE_E, b.hex(' ').upper()))
    print()

    # ---- 6. 数据补丁 ----
    print('=== 6. 数据补丁 ===')
    for label, off in (('蓝牙', OFF_BT_MASK), ('2.4G', OFF_G_MASK)):
        old = data[off]
        new = mask_target[off]
        op, bit = MASK_BIT_OP[off]
        data[off] = new
        print('  %-4s 0x%06X  0x%02X -> 0x%02X  %s bit%d' % (label, off, old, new, op, bit.bit_length() - 1))
    print('        说明：掩码只改 bit4（col4），使 r12c4 参与扫描。')
    print()
    for label, off in (('KEYTBL_BT[100] r12c4', OFF_BT_KEY100),
                       ('KEYTBL_BT[120] r15c0', OFF_BT_KEY120),
                       ('KEYTBL_G [100] r12c4', OFF_G_KEY100),
                       ('KEYTBL_G [120] r15c0', OFF_G_KEY120)):
        old = data[off]
        new = NEW_KEY[off]
        data[off] = new
        print('  %-22s 0x%06X  0x%02X -> 0x%02X' % (label, off, old, new))
    print('        说明：r12c4 -> 0xE0 (Left Ctrl)；r15c0 -> 0x00（充当 Fn）。')
    print()
    for addr, new in sorted(NEW_POOL.items()):
        old = struct.unpack('<I', bytes(data[addr:addr + 4]))[0]
        data[addr:addr + 4] = struct.pack('<I', new)
        print('  池槽 0x%06X        0x%08X -> 0x%08X  (E0F2)' % (addr, old, new))
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
    print('  --- trampoline B（v8 刷新 r7=E0F）---')
    for x in md.disasm(bytes(data[CAVE_B:CAVE_B + 80]), CAVE_B):
        if x.address >= CAVE_B + 72:
            break
        print('     0x%05X: %-26s %-12s %s'
              % (x.address, x.mnemonic, x.op_str, x.bytes.hex()))
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
    print('  向量表 Reset_Handler = 0x%08X (应不变)' % struct.unpack('<I', bytes(data[4:8]))[0])

    if args.apply:
        bak = out + '.bak'
        if os.path.exists(bak):
            print('  !! 备份已存在，跳过备份: %s' % bak)
        else:
            open(bak, 'wb').write(open(src, 'rb').read())
            print('  已备份 -> %s' % bak)
        open(out, 'wb').write(bytes(data))
        print('  已写入 -> %s' % out)
    else:
        print('  （干跑模式，未写入。加 --apply 生效）')


if __name__ == '__main__':
    main()
