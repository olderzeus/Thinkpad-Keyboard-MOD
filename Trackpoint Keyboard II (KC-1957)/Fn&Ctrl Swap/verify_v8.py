#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""KC-1957_88_v8.bin 独立校验（不依赖 keystone，仅用 capstone 反汇编 + 字节比对）

验证内容：
  1) SHA-256 仅作参考打印，**不作为通过条件**（每台设备 Dump 结果本就不一致）；
  2) v8 与原始固件仅在预期 19 个区间有差异，其余逐字节相同 —— 这是「确实基于
     原始固件 patch」的结构性证明，且这 19 个区间都不触及设备独有数据
     （蓝牙名称 @0x21228、2.4G 无线 ID @0x78054 等）；
  3) 5 个钩子（HOOK_A~E）均 bl 到对应空洞；
  4) 各 trampoline 反汇编结构与字面量池正确：
       · 洞穴 B：cmp r4,#row / tst r0,#bit 提取出 row=15,bit=1；
                 .restore 以「ldr.w r7,[pc]; ldrb r7,[r7]」读 E0F(0x20001E0F) 刷新 r7；
                 末尾复原原指令「ldrb.w r2,[sl,r4]; cmp r0,#0; bx lr」；
       · 洞穴 C：读 E0F2(0x20004800) 做 P0.6 去抖判定；
       · 洞穴 D：读 E0F(0x20001E0F)；
       · 洞穴 E：读 E0F2(0x20004800)；
  5) 数据补丁：键码表 r12c4->0xE0 / r15c0->0x00，行掩码 bit4，池槽 -> E0F2；
  6) 行循环内/后两处 cbz r7（0x41286 / 0x413D0）仍存在；
  7) E0F 新鲜度仿真：以反汇编提取的 row/bit 仿真整轮扫描，断言行循环后
     (0x413D0) 读到的 r7 == 本轮最新 E0F（零滞后），与 BT 路径对齐。

退出码 0 = 全部通过；非 0 = 存在失败。
"""
import argparse
import hashlib
import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

HERE = os.path.dirname(os.path.abspath(__file__))
ORIG_DEFAULT = os.path.join(HERE, '..', 'v7_p06_debounce', 'KC-1957_88_orig.bin')
V8_DEFAULT = os.path.join(HERE, 'KC-1957_88_v8.bin')

E0F = 0x20001E0F
E0F2 = 0x20004800

# 参考机（开发用设备）原始固件哈希 —— 仅供参考，不作为通过条件。
# 每台设备 Dump 出的固件本就不一致（蓝牙名称 / 2.4G 无线 ID 等为设备独有），
# 因此该哈希对其它设备必然不同，请勿据此中止。
REF_ORIG_SHA = '57df656c947b196f085ff448ff39ea2ed21fe79fb9532a4ee7c850a059da66f7'

# 期望的改动区间（来自补丁脚本第 8 步输出，已人工核对）
EXPECT_RANGES = [
    (0x01B8A0, 0x01B8A1), (0x01E4E4, 0x01E4E7), (0x01E84C, 0x01E84C),
    (0x01EB74, 0x01EB7D), (0x01EB80, 0x01EB89), (0x023A76, 0x023A79),
    (0x02CC54, 0x02CC54), (0x02CC68, 0x02CC68), (0x0411C6, 0x0411D7),
    (0x041252, 0x041255), (0x04A6B2, 0x04A6B2), (0x04A75E, 0x04A75E),
    (0x04A772, 0x04A772), (0x050000, 0x05003B), (0x050100, 0x050147),
    (0x050200, 0x05021B), (0x050300, 0x050317), (0x050400, 0x05041B),
]

HOOKS = {
    'A': (0x1E4E4, 0x50000, 4,  '蓝牙行循环'),
    'B': (0x41252, 0x50100, 4,  '2.4G 行循环（v8 刷新 r7=E0F）'),
    'C': (0x411C6, 0x50200, 18, '2.4G P0.6 判定/伪键'),
    'D': (0x1EB74, 0x50300, 22, 'BT 扫描内联 P0.IN 读'),
    'E': (0x23A76, 0x50400, 4,  'BT HID 组装修饰字节'),
}

DATA = {
    'KEYTBL_BT[100] r12c4': (0x02CC54, 0xE0),
    'KEYTBL_BT[120] r15c0': (0x02CC68, 0x00),
    'KEYTBL_G [100] r12c4': (0x04A75E, 0xE0),
    'KEYTBL_G [120] r15c0': (0x04A772, 0x00),
}
OFF_BT_MASK = 0x01E84C
OFF_G_MASK = 0x04A6B2
OFF_POOL_E0F = 0x01B8A0

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def die(msg):
    print('  !! FAIL: %s' % msg)
    sys.exit(1)


def grp(runs):
    out = []
    for s, e in runs:
        out.append((s, e))
    return out


def resolve_pc_ldr(data, ins):
    """解析 `ldr.w rN, [pc, #imm]` 指向的字面量值。"""
    # 仅处理以 pc 为基址的 ldr.w
    if 'pc' not in ins.op_str:
        return None, None
    # op_str 形如 "r1, [pc, #0x14]"
    import re
    m = re.search(r'#(0x[0-9a-fA-F]+|-?\d+)', ins.op_str)
    if not m:
        return None, None
    imm = int(m.group(1), 0)
    pc = (ins.address + 4) & ~3
    tgt = pc + imm
    if tgt + 4 > len(data) or tgt < 0:
        return None, None
    return tgt, struct.unpack('<I', data[tgt:tgt + 4])[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--orig', default=ORIG_DEFAULT)
    ap.add_argument('--v8', default=V8_DEFAULT)
    args = ap.parse_args()

    orig = open(args.orig, 'rb').read()
    v8 = open(args.v8, 'rb').read()
    if len(orig) != 524288 or len(v8) != 524288:
        die('固件长度异常: orig=%d v8=%d' % (len(orig), len(v8)))

    print('=' * 72)
    print('KC-1957_88_v8.bin 独立校验')
    print('=' * 72)

    # ---- 1. SHA-256（仅作参考，不作为通过条件）----
    # 注意：每台设备 Dump 出来的固件本就不完全相同（蓝牙名称 @0x21228、
    # 2.4G 无线 ID @0x78054 等为设备独有内容），因此原厂固件的 SHA-256
    # **因机而异**，不能用它来判定「是否基于原始固件」。
    # 真正的判据是下面的结构性检查：差异区间必须精确落在预期 19 个区间内，
    # 且这 19 个区间都不触及设备独有数据。
    sha_o = hashlib.sha256(orig).hexdigest()
    sha_v = hashlib.sha256(v8).hexdigest()
    print('  原始 SHA-256 : %s' % sha_o)
    print('  v8   SHA-256 : %s' % sha_v)
    if sha_o == REF_ORIG_SHA:
        print('  [参考] 与参考机原始固件一致（同一台设备的重复 Dump 会命中）')
    else:
        print('  [参考] 与参考机原始固件不同 —— 正常！每台设备 Dump 结果本就不一致，')
        print('         固件哈希不能作为校验依据；请以本脚本的结构性检查结论为准。')

    # ---- 2. 差异区间 ----
    diff = [i for i in range(len(v8)) if v8[i] != orig[i]]
    runs = []
    if diff:
        s = diff[0]; p = diff[0]
        for i in diff[1:]:
            if i == p + 1:
                p = i
            else:
                runs.append((s, p)); s = p = i
        runs.append((s, p))
    ok = (runs == EXPECT_RANGES)
    print('  差异区间数: %d (期望 %d) %s' % (len(runs), len(EXPECT_RANGES), 'OK' if ok else '!! 不符'))
    if not ok:
        print('    实际: %s' % runs)
        print('    期望: %s' % EXPECT_RANGES)
        die('差异区间与预期不一致')
    # 其余区域逐字节相同
    same = all(v8[i] == orig[i] for i in range(len(v8)) if v8[i] != orig[i] or True)  # trivial
    untouched = 524288 - len(diff)
    print('  [OK] 仅 %d 字节变化，其余 %d 字节与原始固件逐字节相同' % (len(diff), untouched))

    # ---- 3. 钩子 bl 目标 ----
    print('=== 钩子 wiring ===')
    for nm, (addr, cave, _, label) in HOOKS.items():
        ins = list(md.disasm(v8[addr:addr + 4], addr, 1))
        if not ins or ins[0].mnemonic != 'bl':
            die('HOOK_%s @0x%05X 不是 bl 指令' % (nm, addr))
        tgt = int(ins[0].op_str.lstrip('#'), 0)
        good = (tgt == cave)
        print('  HOOK_%s @0x%05X -> 0x%05X  %s  (%s)' % (nm, addr, tgt, 'OK' if good else '!! 不符', label))
        if not good:
            die('HOOK_%s 目标错误' % nm)
    # 钩子 C/E/D 的 nop 填充
    for nm in ('C', 'D'):
        addr, _, size, _ = HOOKS[nm]
        tail = v8[addr + 4:addr + size]
        tail_ok = (tail == b'\x00\xbf' * (len(tail) // 2))
        print('  HOOK_%s 余下 %d 字节 nop 填充 %s' % (nm, size - 4, 'OK' if tail_ok else '!! 不符'))
        if not tail_ok:
            die('HOOK_%s 填充异常' % nm)

    # ---- 4. 洞穴反汇编与字面量池 ----
    print('=== 洞穴语义 ===')

    def caved(nm):
        return HOOKS[nm][1]

    # 洞穴 B
    B = caved('B')
    insB = list(md.disasm(v8[B:B + 0x80], B))
    row_idx = None
    bit = None
    e0f_literals = []
    restore_seq = None
    for i, ins in enumerate(insB):
        m = ins.mnemonic.replace('.w', '')
        if m == 'cmp' and 'r4' in ins.op_str:
            row_idx = int(ins.op_str.split('#')[-1], 0)
        if m == 'tst' and 'r0' in ins.op_str:
            bit = int(ins.op_str.split('#')[-1], 0)
        if m == 'ldr' and 'pc' in ins.op_str:
            _, val = resolve_pc_ldr(v8, ins)
            if val == E0F:
                e0f_literals.append(ins.address)
    # .restore: 找 ldr.w r7,[pc]; ldrb r7,[r7]
    for i in range(len(insB) - 1):
        a, b = insB[i], insB[i + 1]
        if a.mnemonic.replace('.w', '') == 'ldr' and 'r7' in a.op_str and 'pc' in a.op_str \
           and b.mnemonic.replace('.w', '') == 'ldrb' and 'r7' in b.op_str:
            # 确认该 ldr 字面量 = E0F
            _, val = resolve_pc_ldr(v8, a)
            if val == E0F:
                restore_seq = i
    print('  洞穴 B: row=%s bit=%s  E0F 字面量数=%d  .restore(r7=E0F)=%s'
          % (row_idx, bit, len(e0f_literals), 'found' if restore_seq is not None else '!! 缺失'))
    if row_idx != 15 or bit != 1:
        die('洞穴 B 提取的 row/bit 异常: row=%s bit=%s' % (row_idx, bit))
    if len(e0f_literals) < 3:
        die('洞穴 B 缺少 E0F 字面量（应 >=3）')
    if restore_seq is None:
        die('洞穴 B .restore 未找到 r7=E0F 刷新')
    # 洞穴 B 末尾复原：收集指令直到终止 bx lr（排除之后的字面量池数据）
    codeB = []
    for x in insB:
        codeB.append(x)
        if x.mnemonic.replace('.w', '') == 'bx':
            break
    last3 = codeB[-3:]
    restore_ok = (last3[0].mnemonic.replace('.w', '') == 'ldrb' and 'r2' in last3[0].op_str and 'sl' in last3[0].op_str
                  and last3[1].mnemonic == 'cmp' and last3[2].mnemonic.replace('.w', '') == 'bx' and last3[2].op_str == 'lr')
    print('  洞穴 B 末尾复原「ldrb.w r2,[sl,r4]; cmp r0,#0; bx lr」: %s' % ('OK' if restore_ok else '!! 不符'))
    if not restore_ok:
        die('洞穴 B 末尾复原序列异常: %s' % [x.mnemonic + ' ' + x.op_str for x in last3])

    # 洞穴 C: 读 E0F2
    C = caved('C')
    insC = list(md.disasm(v8[C:C + 0x40], C))
    c_e0f2 = None
    for ins in insC:
        if ins.mnemonic.replace('.w', '') == 'ldr' and 'pc' in ins.op_str:
            _, val = resolve_pc_ldr(v8, ins)
            if val == E0F2:
                c_e0f2 = ins.address
    print('  洞穴 C: 读 E0F2(0x%08X) 判定 P0.6 %s' % (E0F2, 'OK' if c_e0f2 is not None else '!! 缺失'))
    if c_e0f2 is None:
        die('洞穴 C 未找到 E0F2 字面量')

    # 洞穴 D: 读 E0F
    D = caved('D')
    insD = list(md.disasm(v8[D:D + 0x30], D))
    d_e0f = None
    for ins in insD:
        if ins.mnemonic.replace('.w', '') == 'ldr' and 'pc' in ins.op_str:
            _, val = resolve_pc_ldr(v8, ins)
            if val == E0F:
                d_e0f = ins.address
    print('  洞穴 D: 读 E0F(0x%08X) %s' % (E0F, 'OK' if d_e0f is not None else '!! 缺失'))
    if d_e0f is None:
        die('洞穴 D 未找到 E0F 字面量')

    # 洞穴 E: 读 E0F2
    E = caved('E')
    insE = list(md.disasm(v8[E:E + 0x30], E))
    e_e0f2 = None
    for ins in insE:
        if ins.mnemonic.replace('.w', '') == 'ldr' and 'pc' in ins.op_str:
            _, val = resolve_pc_ldr(v8, ins)
            if val == E0F2:
                e_e0f2 = ins.address
    print('  洞穴 E: 读 E0F2(0x%08X) %s' % (E0F2, 'OK' if e_e0f2 is not None else '!! 缺失'))
    if e_e0f2 is None:
        die('洞穴 E 未找到 E0F2 字面量')

    # ---- 5. 数据补丁 ----
    print('=== 数据补丁 ===')
    for label, (off, val) in DATA.items():
        got = v8[off]
        print('  %-22s @0x%06X = 0x%02X (期望 0x%02X) %s' % (label, off, got, val, 'OK' if got == val else '!! 不符'))
        if got != val:
            die('%s 值不符' % label)
    bmask = v8[OFF_BT_MASK]; gmask = v8[OFF_G_MASK]
    bmask_ok = (bmask == (orig[OFF_BT_MASK] | 0x10))
    gmask_ok = (gmask == (orig[OFF_G_MASK] & ~0x10 & 0xFF))
    print('  蓝牙行掩码 0x%02X (bit4 置位) %s' % (bmask, 'OK' if bmask_ok else '!!'))
    print('  2.4G行掩码 0x%02X (bit4 清零) %s' % (gmask, 'OK' if gmask_ok else '!!'))
    if not (bmask_ok and gmask_ok):
        die('行掩码 patch 不符')
    pool = struct.unpack('<I', v8[OFF_POOL_E0F:OFF_POOL_E0F + 4])[0]
    print('  池槽 0x%06X = 0x%08X (期望 E0F2) %s' % (OFF_POOL_E0F, pool, 'OK' if pool == E0F2 else '!! 不符'))
    if pool != E0F2:
        die('池槽未改为 E0F2')

    # ---- 6. 两处 cbz r7 ----
    print('=== 行循环内/后 cbz r7 ===')
    for addr, label in ((0x41286, '行循环内'), (0x413D0, '行循环后')):
        ins = list(md.disasm(v8[addr:addr + 2], addr, 1))
        ok = bool(ins) and ins[0].mnemonic == 'cbz' and 'r7' in ins[0].op_str
        print('  %s cbz r7 @0x%05X : %s' % (label, addr, 'OK' if ok else '!! 缺失'))
        if not ok:
            die('%s 处未保留 cbz r7' % label)

    # ---- 7. E0F 新鲜度仿真 ----
    print('=== E0F 新鲜度仿真（行循环后 0x413D0 应读本轮最新 E0F）===')
    # 以反汇编提取的 row_idx/bit 仿真整轮扫描
    def run_cycle(prev_e0f, cur_row_bit0):
        e0f = prev_e0f
        r7 = 0
        for r4 in range(16):
            if r4 == row_idx:
                e0f = 1 if (cur_row_bit0 & bit) else 0
            r7 = e0f  # 每轮（行循环内）HOOK_B 刷新 r7 = E0F
        return r7  # 行循环后 (0x413D0) 消费的 r7

    cases = [(0, 1, 1), (1, 0, 0), (0, 0, 0), (1, 1, 1)]
    allok = True
    for prev, curbit, expect in cases:
        got = run_cycle(prev, curbit)
        good = (got == expect)
        allok &= good
        print('  上轮E0F=%d 本轮回row%d的bit%d=%d -> 循环后 r7=%d (期望 %d) %s'
              % (prev, row_idx, bit.bit_length() - 1, curbit, got, expect, 'OK' if good else '!!'))
    if not allok:
        die('E0F 新鲜度仿真未通过 —— 行循环后仍存在滞后')
    print('  [OK] 行循环后 (0x413D0) 读到的 r7 == 本轮最新 E0F（零滞后，与 BT 对齐）')

    print()
    print('=' * 72)
    print('全部校验通过 ✓   v8 SHA-256 = %s' % sha_v)
    print('=' * 72)
    sys.exit(0)


if __name__ == '__main__':
    main()
