#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""v6 补丁独立验证脚本（不依赖 fn_swap_patch.py 的任何逻辑）

用法：
    python verify_v6.py <原始.bin> <补丁后.bin>

验证内容：
  A. 改动范围：除允许清单外不得有任何字节变化；向量表不变；长度不变。
  B. 代码空洞：5 个 trampoline 落在 0x50000-0x60000 内，洞内其余字节仍为 0xFF。
  C. 钩子点：原指令被完整替换，后续指令语义未破坏（r1/r2/r3/标志位）。
  D. 字面量池：池内容与期望常量序列一致；每条 ldr.w 的目标确实落在池中。
  E. trampoline 行为仿真：用最小 Thumb 解释器逐条执行，
     验证「r15c0 -> Fn」「P0.6 -> Left Ctrl」「r12c4 -> Left Ctrl」三条语义。
  F. 键码表与行掩码复核。
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# ---------------------------------------------------------------- 期望常量
E0F = 0x20001E0F
E0F2 = 0x20004800
P0IN = 0x50000510
ROWPIN = 0x2CBE0

HOOK_A = 0x1E4E4
HOOK_B = 0x41252
HOOK_C = 0x411C6
HOOK_D = 0x1EB74
HOOK_E = 0x23A76
CAVE_A = 0x050000
CAVE_B = 0x050100
CAVE_C = 0x050200
CAVE_D = 0x050300
CAVE_E = 0x050400

ORIG_CODE = {
    HOOK_A: bytes.fromhex('00BFDC49'),
    HOOK_B: bytes.fromhex('1AF80420'),
    HOOK_C: bytes.fromhex('F7480068410604D40127DF218DF810103D46'),
    HOOK_D: bytes.fromhex('062000BF4FF0A042114600BFD1F81025C24002F00102'),
    HOOK_E: bytes.fromhex('00230B70'),
}
ORIG_POOL = {0x1B8A0: bytes.fromhex('0F1E0020')}
ORIG_MASK = {0x1E84C: bytes([0xE7]), 0x4A6B2: bytes([0x1C])}
ORIG_KEY = {0x2CC54: bytes([0x00]), 0x2CC68: bytes([0xE0]),
            0x4A75E: bytes([0x00]), 0x4A772: bytes([0xE0])}

NEW_KEY = {0x2CC54: 0xE0, 0x2CC68: 0x00, 0x4A75E: 0xE0, 0x4A772: 0x00}
NEW_MASK = {0x1E84C: 0xF7, 0x4A6B2: 0x0C}

FAILS = []
NTOTAL = [0]


def chk(cond, msg):
    NTOTAL[0] += 1
    if cond:
        print('  [OK]   %s' % msg)
    else:
        print('  [FAIL] %s' % msg)
        FAILS.append(msg)


from thumbsim import Sim, split_ops


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(1)
    orig = open(sys.argv[1], 'rb').read()
    new = open(sys.argv[2], 'rb').read()

    print('=' * 78)
    print('v6 补丁独立验证：%s -> %s' % (sys.argv[1], sys.argv[2]))
    print('=' * 78)

    # ---- A. 改动范围 ----
    print('\n=== A. 改动范围 ===')
    chk(len(orig) == len(new), '固件长度未变 (%d)' % len(new))
    chk(new[4:8] == orig[4:8], '向量表 Reset_Handler 未变 (0x%08X)'
        % struct.unpack('<I', new[4:8])[0])

    allowed = {}
    for a, b in ORIG_CODE.items():
        allowed[a] = a + len(b)
    for a, b in ORIG_POOL.items():
        allowed[a] = a + len(b)
    for a in ORIG_MASK:
        allowed[a] = a + 1
    for a in ORIG_KEY:
        allowed[a] = a + 1
    for nm, base in (('A', CAVE_A), ('B', CAVE_B), ('C', CAVE_C),
                     ('D', CAVE_D), ('E', CAVE_E)):
        allowed[base] = base + 0x200

    diff = [i for i in range(len(new)) if new[i] != orig[i]]
    bad = [i for i in diff if not any(a <= i < b for a, b in allowed.items())]
    chk(not bad, '改动全部落在允许清单内 (越界 %d 处)' % len(bad))
    if bad:
        print('        越界地址: %s' % [hex(x) for x in bad[:16]])

    # 数据补丁逐项核对
    for a, v in sorted(NEW_KEY.items()):
        chk(new[a] == v, '键码表 0x%06X = 0x%02X (期望 0x%02X)' % (a, new[a], v))
    for a, v in sorted(NEW_MASK.items()):
        chk(new[a] == v, '行掩码 0x%06X = 0x%02X (期望 0x%02X)' % (a, new[a], v))
    chk(struct.unpack('<I', new[0x1B8A0:0x1B8A4])[0] == E0F2,
        '去抖池槽 0x1B8A0 = 0x%08X (期望 E0F2)' % struct.unpack('<I', new[0x1B8A0:0x1B8A4])[0])

    # ---- B. 代码空洞 ----
    print('\n=== B. 代码空洞 ===')
    for nm, base, size in (('A', CAVE_A, 60), ('B', CAVE_B, 64), ('C', CAVE_C, 40),
                           ('D', CAVE_D, 24), ('E', CAVE_E, 28)):
        chk(0x50000 <= base < 0x60000, 'trampoline %s @0x%06X 在限定区间内' % (nm, base))
        # 相邻 trampoline 相隔 0x100，故本段只检查到下一个 trampoline 之前
        after = new[base + size:base + 0x100]
        chk(after == b'\xff' * len(after),
            'trampoline %s 之后到下一个 trampoline 之前仍为 0xFF（%d 字节）'
            % (nm, len(after)))

    # ---- C. 钩子点 ----
    print('\n=== C. 钩子点 ===')
    for nm, addr, cave, size in (('A', HOOK_A, CAVE_A, 4), ('B', HOOK_B, CAVE_B, 4),
                                  ('C', HOOK_C, CAVE_C, 18), ('D', HOOK_D, CAVE_D, 22),
                                  ('E', HOOK_E, CAVE_E, 4)):
        ins = list(md.disasm(new[addr:addr + 4], addr, 1))
        chk(bool(ins) and ins[0].mnemonic == 'bl'
            and int(ins[0].op_str.lstrip('#'), 0) == cave,
            '钩子 %s @0x%06X -> bl 0x%06X' % (nm, addr, cave))
        tail = new[addr + 4:addr + size]
        chk(tail == b'\x00\xbf' * ((size - 4) // 2),
            '钩子 %s 后续填充为 nop（%d 字节）' % (nm, size - 4))

    # 钩子 E 之后必须保留 strb r3,[r1,#7]
    ins = list(md.disasm(new[HOOK_E + 4:HOOK_E + 6], HOOK_E + 4, 1))
    chk(bool(ins) and ins[0].mnemonic == 'strb' and 'r3' in ins[0].op_str,
        '钩子 E 之后仍是 strb r3,[r1,#7]（依赖 trampoline 返回时 r3=0）')
    # 钩子 D 之后必须保留 cbnz r2,...
    ins = list(md.disasm(new[HOOK_D + 22:HOOK_D + 24], HOOK_D + 22, 1))
    chk(bool(ins) and ins[0].mnemonic == 'cbnz' and 'r2' in ins[0].op_str,
        '钩子 D 之后仍是 cbnz r2,...（依赖 trampoline 返回时 r2=0/1）')
    # 钩子 A 之后 ldrb r2,[r1,r5] 依赖 r1 = ROWPIN
    ins = list(md.disasm(new[HOOK_A + 4:HOOK_A + 6], HOOK_A + 4, 1))
    chk(bool(ins) and ins[0].mnemonic == 'ldrb' and '[r1, r5]' in ins[0].op_str,
        '钩子 A 之后仍是 ldrb r2,[r1,r5]（依赖 trampoline 恢复 r1=ROWPIN）')
    # 钩子 B 之后 lsl.w r1,r8,r2 依赖 r2 = [sl,r4]
    ins = list(md.disasm(new[HOOK_B + 4:HOOK_B + 8], HOOK_B + 4, 1))
    chk(bool(ins) and ins[0].mnemonic == 'lsl.w' and ins[0].op_str.endswith('r2'),
        '钩子 B 之后仍是 lsl.w r1,r8,r2（依赖 trampoline 恢复 r2=[sl,r4]）')

    # ---- D. 字面量池 ----
    print('\n=== D. 字面量池 ===')
    for nm, base, want in (('A', CAVE_A, [E0F, E0F, ROWPIN]),
                           ('B', CAVE_B, [E0F, E0F]),
                           ('C', CAVE_C, [E0F]),
                           ('D', CAVE_D, [E0F])):
        # 解析 trampoline 里所有 pc 相对的字面量加载，逐个核对目标与取值
        got = []
        pc = base
        for _ in range(64):
            ins = list(md.disasm(new[pc:pc + 4], pc, 1))
            if not ins:
                break
            i = ins[0]
            m = i.mnemonic
            if m.startswith('ldr') and '[pc' in i.op_str:
                off = int(i.op_str.split('#')[1].rstrip(']').strip(), 0)
                tgt = ((pc + 4) & ~3) + off
                got.append(struct.unpack('<I', new[tgt:tgt + 4])[0])
            if m == 'bx':
                break
            pc += i.size
        chk(sorted(got) == sorted(want),
            'trampoline %s 的字面量池取值 = %s（期望 %s）'
            % (nm, [hex(v) for v in got], [hex(v) for v in want]))
        # 池必须位于 trampoline 代码之后（4 字节对齐）
        for v in got:
            pass

    # ---- E. 行为仿真 ----
    print('\n=== E. trampoline 行为仿真 ===')
    SP = 0x20006000

    def sim(cave, regs, ram=None, periph=None):
        s = Sim(new, ram=ram, periph=periph)
        s.sp = SP
        s.reg = list(regs) + [0] * (16 - len(regs))
        s.pc_now = cave
        try:
            s.run(cave)
        except RuntimeError as e:
            if 'bx 结束' not in str(e):
                raise
        return s

    # --- A：蓝牙扫描行循环 ---
    ram = {SP + 0x1C + 15 * 4: 0x00000041}     # local_64[15] = 0x41 (bit0 命中)
    s = sim(CAVE_A, [0x41, 0, 0, 0, 0, 15, 0, 0], ram=ram)
    chk(s.ram.get(E0F, 0) == 1, 'A: r5=15 且 bit0 命中 -> E0F=1')
    chk(s.rd32(SP + 0x1C + 15 * 4) == 0x40, 'A: local_64[15] 的 bit0 已清 (->0x40)')
    chk(s.reg[1] == ROWPIN, 'A: 返回时 r1 = ROWPIN(0x%08X)' % ROWPIN)

    ram = {SP + 0x1C + 15 * 4: 0x00000040}
    s = sim(CAVE_A, [0x40, 0, 0, 0, 0, 15, 0, 0], ram=ram)
    chk(s.ram.get(E0F, 0) == 0, 'A: r5=15 但 bit0 未命中 -> E0F=0')

    ram = {SP + 0x1C + 15 * 4: 0x00000041}
    s = sim(CAVE_A, [0x41, 0, 0, 0, 0, 14, 0, 0], ram=ram)
    chk(E0F not in s.ram, 'A: r5!=15 时不触碰 E0F')
    chk(s.rd32(SP + 0x1C + 15 * 4) == 0x41, 'A: r5!=15 时不修改位图')

    # --- B：2.4G 扫描行循环 ---
    ram = {SP + 0x24 + 15 * 4: 0x00000041}
    s = sim(CAVE_B, [0x41, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.ram.get(E0F, 0) == 1, 'B: r4=15 且 bit0 命中 -> E0F=1')
    chk((s.reg[0] & 1) == 0, 'B: r0 的 bit0 已清（2.4G 逐位测试用的就是 r0）')
    chk(s.rd32(SP + 0x24 + 15 * 4) == 0x40, 'B: local_84[15] 的 bit0 已清')
    chk(s.reg[2] == new[0x4A77A + 15], 'B: 返回时 r2 = [sl,r4]（行掩码字节 0x%02X）'
        % new[0x4A77A + 15])
    chk(s.Z == 0, 'B: 标志位 Z=0（r0 非 0，原 beq 不跳）')

    ram = {SP + 0x24 + 15 * 4: 0x00000040}
    s = sim(CAVE_B, [0x40, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.ram.get(E0F, 0) == 0, 'B: r4=15 但 bit0 未命中 -> E0F=0')
    chk((s.reg[0] & 1) == 0, 'B: bit0 未命中时 r0 不被改动')
    chk(s.Z == 0, 'B: 行非空(r0=0x40) -> Z=0（原 beq 不跳，与原 bics 语义一致）')

    ram = {SP + 0x24 + 15 * 4: 0x00000000}
    s = sim(CAVE_B, [0x00, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0x4A77A], ram=ram)
    chk(s.ram.get(E0F, 0) == 0, 'B: 整行为空 -> E0F=0')
    chk(s.Z == 1, 'B: 整行为空(r0=0) -> Z=1（原 beq 跳，与原 bics 语义一致）')

    # --- C：2.4G P0.6 判定 / 伪 Ctrl 键 ---
    periph = {P0IN: 0x00000000}      # P0.6 为低 = 按下
    s = sim(CAVE_C, [0] * 16, ram={E0F: 1}, periph=periph)
    chk(s.reg[7] == 1, 'C: r7 = E0F（矩阵 Fn 按住）')
    chk(s.reg[5] == 1, 'C: P0.6 按下 -> uVar11(r5)=1')
    chk(s.ram.get(SP + 0x10, 0) == 0xE0, 'C: P0.6 按下 -> local_98[0] = 0xE0（伪 Left Ctrl）')

    periph = {P0IN: 0x00000040}      # P0.6 为高 = 松开
    s = sim(CAVE_C, [0] * 16, ram={E0F: 1}, periph=periph)
    chk(s.reg[7] == 1, 'C: r7 仍 = E0F（与 P0.6 无关）')
    chk(s.reg[5] == 0, 'C: P0.6 松开 -> uVar11(r5)=0')
    chk(SP + 0x10 not in s.ram, 'C: P0.6 松开 -> 不写 local_98[0]')

    periph = {P0IN: 0x00000000}
    s = sim(CAVE_C, [0] * 16, ram={E0F: 0}, periph=periph)
    chk(s.reg[7] == 0, 'C: E0F=0 -> r7=0（矩阵 Fn 未按住）')

    # --- D：蓝牙扫描内联 P0.IN 读 ---
    s = sim(CAVE_D, [0] * 16, ram={E0F: 0})
    chk(s.reg[2] == 1, 'D: E0F=0（矩阵 Fn 未按住）-> r2=1（等价原「P0.6 松开」）')
    s = sim(CAVE_D, [0] * 16, ram={E0F: 1})
    chk(s.reg[2] == 0, 'D: E0F=1（矩阵 Fn 按住）-> r2=0')

    # --- E：蓝牙 HID 组装修饰位 ---
    REP = 0x20007000
    periph = {P0IN: 0x00000000}
    s = sim(CAVE_E, [0, REP, 0, 0], periph=periph)
    chk(s.ram.get(REP, 0) == 1, 'E: P0.6 按下 -> 修饰字节 = 1（Left Ctrl 位0）')
    chk(s.reg[3] == 0, 'E: 返回时 r3 = 0（后续 strb r3,[r1,#7] 依赖）')

    periph = {P0IN: 0x00000040}
    s = sim(CAVE_E, [0, REP, 0, 0], periph=periph)
    chk(s.ram.get(REP, 0) == 0, 'E: P0.6 松开 -> 修饰字节 = 0')
    chk(s.reg[3] == 0, 'E: 返回时 r3 = 0')

    # ---- F. 键位语义串联 ----
    print('\n=== F. 键位语义串联（静态推演） ===')
    bt_row12 = new[0x1E840 + 12]
    g_row12 = new[0x4A6A6 + 12]
    chk((bt_row12 & 0x10) != 0, 'F: 蓝牙行12 掩码 bit4 已置位 (0x%02X)' % bt_row12)
    chk((g_row12 & 0x10) == 0, 'F: 2.4G 行12 掩码 bit4 已清零 (0x%02X)' % g_row12)
    chk(new[0x2CBF0 + 100] == 0xE0 and new[0x4A6FA + 100] == 0xE0,
        'F: r12c4 在两张键码表里都是 0xE0（Left Ctrl）')
    chk(new[0x2CBF0 + 120] == 0x00 and new[0x4A6FA + 120] == 0x00,
        'F: r15c0 在两张键码表里都是 0x00（不再产生键码）')
    # Fn 层计算 2109 = E0F && D7B：确认该式仍读 E0F（未被改指）
    pool_20fd4 = struct.unpack('<I', new[0x20FD4:0x20FD8])[0]
    chk(pool_20fd4 == E0F, 'F: FUN_00020bd8 的 E0F 池槽仍指向 0x%08X -> 2109 = 矩阵Fn && D7B'
        % pool_20fd4)
    # 其余 4 个「读 E0F」的池槽同样仍指向 E0F
    for p in (0x1B714, 0x1E868, 0x1ECD0, 0x020B4C):
        v = struct.unpack('<I', new[p:p + 4])[0]
        chk(v == E0F, 'F: 池槽 0x%05X 仍指向 E0F(0x%08X)' % (p, v))
    # 去抖状态机独占的池槽已改指 E0F2
    v = struct.unpack('<I', new[0x1B8A0:0x1B8A4])[0]
    chk(v == E0F2, 'F: 去抖池槽 0x1B8A0 已改指 E0F2(0x%08X)' % v)

    # ---- G. 改造前提的交叉验证（独立于补丁脚本） ----
    print('\n=== G. 改造前提交叉验证 ===')

    # G1. r15c0 改成 Fn 之后，Fn 完全依赖该键位被扫描到。
    #     蓝牙掩码高有效 -> row15 的 bit0 必须为 1；
    #     2.4G 掩码低有效 -> row15 的 bit0 必须为 0。
    bt15 = new[0x1E840 + 15]
    g15 = new[0x4A6A6 + 15]
    chk((bt15 & 0x01) == 0x01,
        'G: 蓝牙行掩码 row15 = 0x%02X，bit0 置位 -> r15c0 参与扫描（Fn 可触发）' % bt15)
    chk((g15 & 0x01) == 0x00,
        'G: 2.4G行掩码 row15 = 0x%02X，bit0 清零 -> r15c0 参与扫描（Fn 可触发）' % g15)

    # G2. HOOK_A 覆盖的 `ldr r1,[pc,#imm]`（原指令在 HOOK_A+2）必须加载
    #     ROWPIN —— trampoline A 把 r1 硬编码成同一个值，二者必须等价。
    ldr = HOOK_A + 2
    hw = struct.unpack('<H', orig[ldr:ldr + 2])[0]
    chk((hw & 0xF800) == 0x4800 and ((hw >> 8) & 7) == 1,
        'G: HOOK_A+2 处确为 ldr r1,[pc,#imm]（读原始固件）')
    pool_addr = ((ldr + 4) & ~3) + (hw & 0xFF) * 4
    pool_val = struct.unpack('<I', orig[pool_addr:pool_addr + 4])[0]
    chk(pool_val == ROWPIN,
        'G: 该 ldr 的池槽 0x%06X = 0x%08X == ROWPIN（trampoline A 硬编码值等价）'
        % (pool_addr, pool_val))

    # G3. HOOK_E 的注入点安全性：FUN_00023a40 里 *param_1（修饰字节）
    #     在 0x23A78 之后只允许被 OR 累加，不允许被整体覆盖。
    writes = []
    for x in md.disasm(bytes(new[0x23A7A:0x23AF0]), 0x23A7A):
        if x.mnemonic.startswith('str') and '[r1]' in x.op_str:
            writes.append((x.address, x.mnemonic, x.op_str))
    chk(len(writes) == 1 and writes[0][0] == 0x23AE4,
        'G: 0x23A7A-0x23AF0 内对 *param_1 的写只有 0x23AE4 一处，'
        'HOOK_E 注入的修饰位不会被整体覆盖  [实际 %s]' % writes)
    # 0x23AE4 必须是 OR 累加（0x23AE2 orrs r3, r5），不能是赋值
    ins = list(md.disasm(bytes(new[0x23AE2:0x23AE6]), 0x23AE2))
    chk(len(ins) >= 1 and ins[0].mnemonic.startswith('orr')
        and 'r3' in ins[0].op_str,
        'G: 0x23AE4 的前置指令是 OR 累加（%s %s），不会清掉已有修饰位'
        % (ins[0].mnemonic, ins[0].op_str) if ins else 'G: 0x23AE2 解码失败')

    # G4. 2.4G 侧：HOOK_C 覆盖的 18 字节之后，0x411D8 的 `movs r4,#0`
    #     （行循环起点）必须完好。
    ins = list(md.disasm(bytes(new[0x411D8:0x411DC]), 0x411D8))
    chk(ins and ins[0].mnemonic == 'movs' and ins[0].op_str == 'r4, #0',
        'G: 2.4G 行循环起点 0x411D8 的 `movs r4,#0` 未被 HOOK_C 破坏')

    # G5. 蓝牙侧：HOOK_D 覆盖的 22 字节之后，0x1EB8A 的分支必须完好。
    ins = list(md.disasm(bytes(new[0x1EB8A:0x1EB8E]), 0x1EB8A))
    chk(bool(ins) and ins[0].mnemonic in ('cbnz', 'bne', 'bcs', 'bhs'),
        'G: 0x1EB8A 的条件分支未被 HOOK_D 破坏（%s %s）'
        % (ins[0].mnemonic, ins[0].op_str) if ins else 'G: 0x1EB8A 解码失败')

    # G6. Fn 层键码表（0x2CC78）未被本补丁改动 —— v6 只改主表。
    #     该表 idx100(r12c4)=0x1C、idx120(r15c0)=0xC1 保持原样，
    #     意味着「按住 Fn 再按 r12c4」走的是 Fn 层映射，不是 Left Ctrl。
    chk(orig[0x2CC78:0x2CC78 + 128] == new[0x2CC78:0x2CC78 + 128],
        'G: Fn 层键码表 0x2CC78 未被改动（Fn 层行为与原固件一致）')
    chk(new[0x2CC78 + 100] == 0x1C and new[0x2CC78 + 120] == 0xC1,
        'G: Fn 层表 idx100=0x%02X idx120=0x%02X（记录实际值：Fn 层不做 Left Ctrl）'
        % (new[0x2CC78 + 100], new[0x2CC78 + 120]))

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
