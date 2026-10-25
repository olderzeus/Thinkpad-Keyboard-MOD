#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""KC-1957_88.bin  Fn 键矩阵化改造 —— v5.1（v5 逻辑 + 2.4G 路径两处修正）

v5.1 相对 v5 的唯一变化：**修正 2.4G 路径 trampoline_B 的两处缺陷**。
  缺陷 1（屏蔽失效）：v5 只清 `local_84[row]` 的 bit4，但 2.4G 路径在钩子之后
        逐位测试用的是**寄存器 r0**（`tst.w r0, ip` @0x4126C），r0 才是被测对象，
        因此 v5 在 2.4G 模式下**根本没有屏蔽住 r12c4**。
        v5.1 同时清 r0 的 bit4 与 local_84[row] 的 bit4。
  缺陷 2（整行丢键）：v5 的 trampoline_B 里 cmp/tst/movs 都会改写 NZCV，
        而钩子返回后 `0x4125E` 的 `beq #0x4133E` 依赖 `0x4124C` 的 `bics` 产生的 Z 位。
        当第 12 行按下了**其它**键（r12c4 未按）时，v5 走 .zero 分支把 Z 置 1，
        `beq` 成立 -> **整行 r12 的其它键全部丢失**。
        v5.1 在返回前用 `cmp r0,#0` 复原标志位，语义与原 `bics` 完全一致。
  对照：蓝牙路径不受影响 —— BT 的逐位测试读的是**数组** `local_64[row]`
        （`ldr.w r0,[r0,r5,lsl #2]` @0x1E67A），v5 清 local_64 的做法本来就是对的。
        这正是两条路径的行为不对称根源。

v5 相对 v4 的唯一变化：**放宽「键盘掩码与预期值不符」时的中止行为**。
  v4：掩码字节不是预期值即整体中止。
  v5：新增 --force-mask（只放宽掩码）与 --force（放宽掩码 + hook 代码点）；
      放宽后掩码按「实际值 + 位操作」写入，而不是套用原版常量，
      因此变体固件里掩码表的其它位不会被误覆盖。
  hook 代码点、代码空洞（必须全 0xFF）、固件长度、向量表仍为硬约束。

设计目标（v4 起严格遵循，本版不变）：
  仅把 Fn 的判定从「P0.6 单一 GPIO」扩展为「P0.6 拉低 **或** 矩阵 r12c4 按下」，
  除此之外不改变任何其它判定逻辑。为此：

  * 不新增既有状态变量的写入方，不复制既有的计算式；
  * 不去抖的变量不被原始电平覆盖（否则 P0.6 会丧失去抖）；
  * 含档位门控（D7B）的派生量交还原主计算，不在 trampoline 里重算。

与 v1/v2 的关键差异（v1/v2 有实质错误）：
  v1/v2 把矩阵 Fn 写入了 RAM_20001D7B —— 那是主机 HID 输出报告(0xAA/0xBB)下发的
  「Fn 档位/模式」标志，会被 FUN_00022e38 覆盖，语义也不是「按下」。

与 v3 的差异（v3 仍有两处越界改动，v4 起已剔除）：
  v3 的 trampoline A 在「松开」分支里写了 E0F = 原始 P0.IN bit6，
  这会把 FUN_0001b75c 维护的去抖值覆盖掉，使 P0.6 丧失去抖；
  还写了 2109 = *E0F，丢掉了原式里的 && D7B 档位门控。
  现版：trampoline A 只做「矩阵 Fn 按下 → 强制 E0F=1」，
  松开时只撤 FN_MATRIX，E0F 归还去抖状态机、2109 归还 FUN_00020bd8。

v4 架构：
  新 RAM 字节 FN_MATRIX @0x20004800  —— 「矩阵 Fn 按下」(1/0)
  选址在全部已引用 RAM 变量之上，详见变量常量处注释。
  两条扫描路径的行循环各挂一个 trampoline 写 FN_MATRIX，
  并把该行位图中 Fn 对应的 bit 清掉（使该槽不产生键码，无需占用键码表值）。
  蓝牙侧 trampoline_A 仅额外驱动 E0F（0x20001E0F，去抖后的 P0.6 按下状态），
    这是扫描函数真正当作 Fn 修饰键读取的变量；
  2.4G 侧 trampoline_C 在原有的内联 P0.IN bit6 判定点上做 OR；
  trampoline_D 保护 FUN_0001b75c 的 E0F 清零点，防止去抖状态机在两次扫描之间
    把矩阵写入的 E0F=1 清掉（矩阵 Fn 按住期间 P0.6 仍为高）。

命令行：
  python fn_matrix_patch3.py <in.bin> [--out <out.bin>] [--apply]
                              [--force-mask] [--force]
  默认干跑（只报告不写盘）；--apply 才写出文件。
  --force-mask：键盘掩码与预期值不符时，仍按「实际值 + 位操作」强制修补。
  --force     ：在 --force-mask 基础上，连 hook 代码点的字节差异也一并忽略
                （该地址代码将被完全替换，需自行确认语义位置正确）。
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
FN_MATRIX = 0x20004800        # 新变量：矩阵 Fn 按下（本补丁新增的唯一 RAM 字节）
                              # 选址依据（按函数边界精确普查 2434 个函数实测）：
                              # 全映像 pc 相对字面量引用的 RAM 变量共 661 个，
                              # 最高只到 0x20003928；0x20003928 之上零引用，
                              # 故取最高引用 +3616 字节处，既避开数组延伸风险，
                              # 又距 RAM 顶端仍有 28KB（即便栈在顶端也够）。
                              # 注：早期版本注释里的「最高引用 0x20004138 / 654 个地址」
                              # 是宽松扫描（每 2 字节扫一次）的误报——候选半字落在指令
                              # 中间；按函数边界精确普查后已更正。
E0F = 0x20001E0F              # P0.6 去抖后按下（FUN_0001b75c 独占写入）
                              # 扫描函数真正当作 Fn 修饰键读取的变量；
                              # 本补丁仅在其「按下」分支强制置 1（与 P0.6 并联），
                              # 「松开」分支不写，交还去抖状态机
FN_HELD = 0x20002109          # Fn 层激活状态 = (E0F && D7B)，由 FUN_00020bd8 /
                              # FUN_00026ec4 写。本补丁【不】写它，以保留 D7B 档位门控
E09 = 0x20001E09              # Fn 锁定标志（本补丁不使用）
P0IN = 0x50000510
ROWPIN = 0x2CBE0              # 蓝牙行引脚表

ROW = 12                      # Home/End 所在行
BIT = 0x10                    # ASD 所在列 (bit4)

# 补丁点
HOOK_A = 0x1E4E4              # 蓝牙扫描行循环（原 nop + ldr r1,[pc,#0x370]）
HOOK_B = 0x41252              # 2.4G 扫描行循环（原 ldrb.w r2,[sl,r4]）
HOOK_C = 0x411C6              # 2.4G 内联 P0.IN bit6 判定（18 字节）
HOOK_D = 0x1B7C0              # FUN_0001b75c 的 E0F 清零点（6 字节）

# 代码空洞（限定在 0x50000-0x60000，该 128KB 全区为擦除态 0xFF，
# 且静态不可达：代码最高 0x04A9A3，pc 相对 ldr 最远只到 0x04B9A2；
# 全映像 0 处 movw/movt 构造该区间地址，0/6236 条 pc 相对 ldr 指向该区间）
CAVE_A = 0x050000             # trampoline A（蓝牙扫描）
CAVE_B = 0x050100             # trampoline B（2.4G 扫描）
CAVE_C = 0x050200             # trampoline C（2.4G Fn 判定）
CAVE_D = 0x050300             # trampoline D（FUN_0001b75c 的 E0F 清除保护）
CAVE_LIMIT = (0x50000, 0x60000)

# 数据补丁
OFF_BT_MASK = 0x1E84C         # 蓝牙行掩码 r12 : E7 -> F7
OFF_G_MASK = 0x4A6B2          # 2.4G 行掩码 r12 : 1C -> 0C

# 掩码的位语义（用于「实际值 + 位操作」的强制修补，不套用原版常量）：
#   蓝牙掩码为高有效（&= mask）：把 bit4 置 1 即让 r12 的 col4 参与扫描
#   2.4G 掩码为低有效（&= ~mask）：把 bit4 清 0 即让 r12 的 col4 参与扫描
#   两者都只改 bit4，其余位保留变体固件自身的值。
MASK_BIT_OP = {
    OFF_BT_MASK: ('置', 0x10),   # | 0x10
    OFF_G_MASK: ('清', 0x10),    # & ~0x10
}

# 期望原字节（安全断言）
#   ORIG_CODE：hook 代码点 —— 语义位置，必须逐字节吻合（除非 --force）
#   ORIG_MASK：键盘掩码点 —— 允许不符后按位强制修补（--force-mask / --force）
ORIG_CODE = {
    HOOK_A: bytes.fromhex('00BFDC49'),
    HOOK_B: bytes.fromhex('1AF80420'),
    HOOK_C: bytes.fromhex('F7480068410604D40127DF218DF810103D46'),
    HOOK_D: bytes.fromhex('002037490870'),
}
ORIG_MASK = {
    OFF_BT_MASK: bytes([0xE7]),
    OFF_G_MASK: bytes([0x1C]),
}
ORIG = dict(ORIG_CODE)
ORIG.update(ORIG_MASK)


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
    """返回 (blob, disasm_list)。fmt 提供 {row},{bit} 等替换。"""
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
    # 解码消耗 + 被 pop 掉的对齐 nop 必须正好等于 pool_off
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
SEQ_A = [
    ('i', 'cmp r5, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    # ---- 矩阵 Fn 按下：把 E0F 强制为 1（与 P0.6 去抖值并联）----
    # 只动 E0F 与 FN_MATRIX；2109 交给 FUN_00020bd8 按原式 (E0F && D7B) 计算，
    # 以保留 D7B 档位门控，不新增 2109 的写入方。
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'strb r2, [r1]'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'strb r2, [r1]'),
    # ---- 清掉 local_64[12] 的 bit4，避免伪键码进入 HID 报告 ----
    ('i', 'add r1, sp, #{l64}'),
    ('i', 'ldr.w r2, [r1, r5, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r5, lsl #2]'),
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    # ---- 矩阵 Fn 松开：只撤 FN_MATRIX，E0F 归还去抖状态机 ----
    # 不写 E0F（否则会用原始 P0.IN 覆盖去抖值，使 P0.6 丧失去抖）；
    # 不写 2109（原式含 && D7B，且已有两个写入方）。
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'strb r2, [r1]'),
    ('L', '.restore'),
    ('LIT', 'r1', 'rowpin'),
    ('i', 'bx lr'),
]

# B：2.4G 扫描行循环（HOOK_B）
#   与 A 同义，但 2.4G 路径在钩子之后**用寄存器 r0** 逐位测试行位图
#   （0x4126C: tst.w r0, ip），r0 才是被测对象 —— 只清 local_84[row] 是无效的。
#   故 v5.1 同时清 r0 与 local_84[row]。
#   另外：钩子返回后 0x4125E 的 beq 依赖 0x4124C 的 bics 产生的 Z 位，
#   而 cmp/tst/movs 都会改写 NZCV，故返回前用 cmp r0,#0 复原标志位。
SEQ_B = [
    ('i', 'cmp r4, #{row}'),
    ('b', 'bne', '.restore'),
    ('i', 'tst.w r0, #{mbit}'),
    ('b', 'beq', '.zero'),
    ('i', 'movs r2, #1'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'strb r2, [r1]'),
    ('i', 'bic.w r0, r0, #{mbit}'),        # 清寄存器 r0（2.4G 逐位测试用的就是 r0）
    ('i', 'add r1, sp, #{l84}'),
    ('i', 'ldr.w r2, [r1, r4, lsl #2]'),
    ('i', 'bic.w r2, r2, #{mbit}'),
    ('i', 'str.w r2, [r1, r4, lsl #2]'),    # 清 local_84[row] 的 bit
    ('b', 'b', '.restore'),
    ('L', '.zero'),
    ('i', 'movs r2, #0'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'strb r2, [r1]'),
    ('L', '.restore'),
    ('i', 'ldrb.w r2, [sl, r4]'),          # 复原原指令（r2 = 行掩码字节）
    ('i', 'cmp r0, #0'),                   # 复原标志位：Z = (r0 == 0)，与原 bics 一致
    ('i', 'bx lr'),
]

SEQ_C = [
    ('LIT', 'r0', 'p0in'),
    ('i', 'ldr r0, [r0]'),
    ('i', 'lsls r1, r0, #0x19'),
    ('b', 'bmi', '.chk'),
    ('b', 'b', '.act'),
    ('L', '.chk'),
    ('LIT', 'r1', 'fnmat'),
    ('i', 'ldrb r1, [r1]'),
    ('i', 'cmp r1, #1'),
    ('b', 'beq', '.act'),
    ('b', 'b', '.done'),
    ('L', '.act'),
    ('i', 'movs r7, #1'),
    ('i', 'movs r1, #0xdf'),
    ('i', 'strb.w r1, [sp, #0x10]'),
    ('i', 'mov r5, r7'),
    ('L', '.done'),
    ('i', 'bx lr'),
]

# trampoline D：保护 FUN_0001b75c 的 E0F 清零点。
# 原逻辑：P0.6 稳定为高 && 去抖定时器归零 && E0F==1  ->  E0F = 0
# 矩阵 Fn 按下时 P0.6 仍为高，该分支会把 trampoline A 写入的 E0F=1 清掉，
# 故改为：若 FN_MATRIX != 0（矩阵 Fn 仍按住）则跳过清除，保留矩阵写入的值。
# 调用约定：r0/r1 在返回后均于 0x1B7E4 被重新装载（死值），不破坏调用者。
SEQ_D = [
    ('LIT', 'r1', 'fnmat'),
    ('i', 'ldrb r1, [r1]'),
    ('i', 'cmp r1, #0'),
    ('b', 'beq', '.clr'),
    ('i', 'bx lr'),                 # FN_MATRIX != 0 -> 不清 E0F
    ('L', '.clr'),
    ('LIT', 'r1', 'e0f'),
    ('i', 'movs r0, #0'),
    ('i', 'strb r0, [r1]'),         # 复原原指令：E0F = 0
    ('i', 'bx lr'),
]

FMT = dict(row=ROW, mbit=BIT, l64=0x1C, l84=0x24,
           fnmat=FN_MATRIX, fnheld=FN_HELD, e0f=E0F, e09=E09,
           p0in=P0IN, rowpin=ROWPIN, p06=0x40)


# ---------------------------------------------------------------- 工具
def scan_ram_refs(data):
    """扫描全映像里所有 pc 相对字面量，返回落在 RAM 区的地址集合。

    保守口径：每 2 字节扫一次（不区分指令边界），会把落在指令中间的半字
    误当成 ldr，因此结果可能略多（偏保守，用于选址复核是安全方向）。
    """
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
        description='KC-1957 Fn 键矩阵化补丁 v5.1（支持掩码不符时强制修补；'
                    '修正 2.4G 路径 trampoline_B 的两处缺陷）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例：\n'
               '  python fn_matrix_patch3.py KC-1957_88.bin                     # 干跑，检查\n'
               '  python fn_matrix_patch3.py KC-1957_88.bin --apply              # 写出补丁固件\n'
               '  python fn_matrix_patch3.py KC-1957_88.bin --force-mask --apply # 掩码不符仍强制修补\n')
    ap.add_argument('bin')
    ap.add_argument('--out', default=None,
                    help='输出文件（默认与输入同名）')
    ap.add_argument('--apply', action='store_true',
                    help='实际写盘（缺省为干跑，只报告不修改）')
    ap.add_argument('--force-mask', action='store_true',
                    help='键盘掩码与预期值不符时忽略警告，按「实际值+位操作」强制修补')
    ap.add_argument('--force', action='store_true',
                    help='在 --force-mask 基础上，连 hook 代码点的字节差异也一并忽略')
    args = ap.parse_args()

    src = args.bin
    out = args.out or src
    data = bytearray(open(src, 'rb').read())
    orig_len = len(data)

    print('=' * 78)
    print('Fn 键矩阵化改造补丁 v5.1（严格限定为「Fn 判定并联」）')
    print('  v5.1 修正 : 2.4G trampoline_B 清 r0 的 bit + 复原标志位（见文件头说明）')
    print('=' * 78)
    print('  输入      : %s  (%d 字节)' % (src, orig_len))
    print('  FN_MATRIX : 0x%08X  (新变量，矩阵 Fn 按下)' % FN_MATRIX)
    print('  E0F       : 0x%08X  (去抖后 P0.6 按下；本补丁仅在其按下分支强制置 1)' % E0F)
    print('  FN_HELD   : 0x%08X  (Fn 层激活 = E0F && D7B；本补丁不写，保留档位门控)' % FN_HELD)
    print('  强制模式  : %s' % ('--force（掩码+代码点全部忽略）'
                                if args.force else
                                ('--force-mask（仅忽略掩码差异）' if args.force_mask else
                                 '关（不符即中止）')))
    print()

    # ---- 0a. 新变量选址安全复核 ----
    # FN_MATRIX 必须落在一片「没有任何 pc 相对字面量引用」的 RAM 上。
    # 扫描采用保守口径（每 2 字节扫一次，会把落在指令中间的半字误当成 ldr），
    # 因此个别变体固件可能出现误报；命中窗口即中止，需人工复核。
    print('=== 0a. 新变量选址复核（FN_MATRIX @ 0x%08X） ===' % FN_MATRIX)
    ram_refs = scan_ram_refs(bytes(data))
    ram_refs.discard(FN_MATRIX)
    window = [v for v in ram_refs if FN_MATRIX <= v < FN_MATRIX + 0x100]
    assert not window, \
        'FN_MATRIX 选址窗口 0x%08X-0x%08X 内存在 RAM 引用: %s（该固件 RAM 布局不同，需重新选址）' % \
        (FN_MATRIX, FN_MATRIX + 0x100, [hex(v) for v in sorted(window)])
    print('  全映像 pc 相对字面量引用的 RAM 变量：%d 个（保守扫描，含极少量误报）' % len(ram_refs))
    print('  FN_MATRIX 窗口 0x%08X-0x%08X 内引用数: 0  ->  选址安全'
          % (FN_MATRIX, FN_MATRIX + 0x100))
    print('  （精确普查参考：按函数边界反汇编实测 661 个 RAM 变量，最高 0x20003928，'
          '本变量在其上方 +3616 字节）')
    print()

    # ---- 0b. 原字节安全断言 ----
    # 分两类处理：
    #   (a) hook 代码点 —— 补丁依赖「该地址的指令语义」，字节不符意味着打错位置，
    #       默认硬中止；仅 --force 才放行（此时该地址原指令被完全替换，风险自担）。
    #   (b) 键盘掩码点 —— 数据字节，不符通常只是变体固件的掩码表取值不同，
    #       仍可安全地按「实际值 + 位操作」强制修补；--force-mask / --force 放行。
    print('=== 0b. 原字节安全断言 ===')

    print('  --- 0b-1. hook 代码点（语义位置；不符需 --force） ---')
    code_bad = []
    for addr, want in sorted(ORIG_CODE.items()):
        got = bytes(data[addr:addr + len(want)])
        good = got == want
        if not good:
            code_bad.append((addr, want, got))
        print('  0x%06X  期望 %-40s 实际 %-40s %s'
              % (addr, want.hex(' ').upper(), got.hex(' ').upper(), 'OK' if good else '!! 不符'))

    print('  --- 0b-2. 键盘掩码点（不符可 --force-mask 强制修补） ---')
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

    # 掩码目标值：由「实际值 + 位操作」推出，绝不套用原版常量，
    # 保证变体固码的掩码表其余位不被误覆盖。
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
            print('  !! hook 代码点与预期不符（%d 处），已中止。' % len(code_bad))
            print('     这些地址决定补丁的语义落点，强行写入可能破坏其它逻辑。')
            print('     若确认目标固件的该处代码与本版本语义一致，可用 --force 强制继续。')
            raise SystemExit(2)
        print()
        print('  !! 注意：--force 已启用，hook 代码点的 %d 处字节差异将被忽略：' % len(code_bad))
        for addr, want, got in code_bad:
            print('     0x%06X  期望 %s 实际 %s' % (addr, want.hex(' ').upper(), got.hex(' ').upper()))
        print('     该地址的原始指令将被补丁内容完全覆盖，请自行确认语义落点正确。')

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

    # ---- 0. 代码空洞校验：必须在限定区间内，且原为全 0xFF ----
    print('=== 0. 代码空洞校验（限定 0x%05X-0x%05X） ===' % CAVE_LIMIT)
    lo_lim, hi_lim = CAVE_LIMIT
    CAVES = [('A', CAVE_A), ('B', CAVE_B), ('C', CAVE_C), ('D', CAVE_D)]
    for nm, base in CAVES:
        assert lo_lim <= base < hi_lim, \
            'trampoline %s @0x%06X 越出限定区间 0x%05X-0x%05X' % (nm, base, lo_lim, hi_lim)
        seg = bytes(data[base:base + 0x200])
        assert seg == b'\xff' * 0x200, \
            'trampoline %s @0x%06X 附近 512 字节并非全 0xFF' % (nm, base)
        print('  trampoline %s @0x%06X  区间内 OK，附近 512 字节全为 0xFF OK' % (nm, base))
    print()

    # ---- 1. 汇编 trampoline ----
    print('=== 1. 汇编 4 个 trampoline ===')
    a_blob, a_dis, a_pool, a_poolvals = build(SEQ_A, FMT, CAVE_A)
    b_blob, b_dis, b_pool, b_poolvals = build(SEQ_B, FMT, CAVE_B)
    c_blob, c_dis, c_pool, c_poolvals = build(SEQ_C, FMT, CAVE_C)
    d_blob, d_dis, d_pool, d_poolvals = build(SEQ_D, FMT, CAVE_D)

    for nm, blob, dis, base, pool, poolvals in [
        ('A 蓝牙扫描', a_blob, a_dis, CAVE_A, a_pool, a_poolvals),
        ('B 2.4G扫描', b_blob, b_dis, CAVE_B, b_pool, b_poolvals),
        ('C 2.4G判定', c_blob, c_dis, CAVE_C, c_pool, c_poolvals),
        ('D 去抖保护', d_blob, d_dis, CAVE_D, d_pool, d_poolvals),
    ]:
        print('  --- trampoline %s @0x%06X (%d 字节, 池@+0x%X) ---'
              % (nm, base, len(blob), pool))
        for x in dis:
            if x.address >= base + pool:
                break
            print('     0x%05X: %-26s %-12s %s'
                  % (x.address, x.mnemonic, x.op_str, x.bytes.hex()))
        print('     字面量池: %s' % [hex(v) for v in poolvals])
        print()

    # ---- 2. 写 trampoline 到空洞 ----
    print('=== 2. 写入代码空洞 ===')
    for nm, blob, base in [('A', a_blob, CAVE_A), ('B', b_blob, CAVE_B),
                           ('C', c_blob, CAVE_C), ('D', d_blob, CAVE_D)]:
        # 空洞必须全 FF
        seg = bytes(data[base:base + len(blob)])
        assert seg == b'\xff' * len(blob), '%s 空洞非空 @0x%06X' % (nm, base)
        data[base:base + len(blob)] = blob
        print('  trampoline %s -> 0x%06X  (%d 字节)' % (nm, base, len(blob)))
    print()

    # ---- 3. 打 hook ----
    print('=== 3. 打 hook ===')

    # 3a. 蓝牙扫描行循环
    enc, _ = ks.asm('bl 0x%x' % CAVE_A, addr=HOOK_A, as_bytes=False)
    bl = bytes(enc)
    assert len(bl) == 4
    d0 = list(md.disasm(bl, HOOK_A, 1))
    assert d0 and d0[0].mnemonic == 'bl' and int(d0[0].op_str.lstrip('#'), 0) == CAVE_A
    data[HOOK_A:HOOK_A + 4] = bl
    print('  0x%06X  bl 0x%06X          %s   (蓝牙行循环，覆盖 nop+ldr r1)'
          % (HOOK_A, CAVE_A, bl.hex(' ').upper()))

    # 3b. 2.4G 扫描行循环
    enc, _ = ks.asm('bl 0x%x' % CAVE_B, addr=HOOK_B, as_bytes=False)
    bl = bytes(enc)
    assert len(bl) == 4
    d0 = list(md.disasm(bl, HOOK_B, 1))
    assert d0 and d0[0].mnemonic == 'bl' and int(d0[0].op_str.lstrip('#'), 0) == CAVE_B
    data[HOOK_B:HOOK_B + 4] = bl
    print('  0x%06X  bl 0x%06X          %s   (2.4G 行循环，覆盖 ldrb.w r2,[sl,r4])'
          % (HOOK_B, CAVE_B, bl.hex(' ').upper()))

    # 3c. 2.4G 内联 P0.IN 判定
    enc, _ = ks.asm('bl 0x%x' % (CAVE_C), addr=HOOK_C, as_bytes=False)
    bl = bytes(enc)
    assert len(bl) == 4
    data[HOOK_C:HOOK_C + 4] = bl
    nops = b'\x00\xbf' * 7
    data[HOOK_C + 4:HOOK_C + 18] = nops
    print('  0x%06X  bl 0x%06X + 7*nop  %s   (2.4G P0.IN bit6 判定，18 字节全替换)'
          % (HOOK_C, CAVE_C, bl.hex(' ').upper()))

    # 3d. FUN_0001b75c 的 E0F 清除保护
    enc, _ = ks.asm('bl 0x%x' % (CAVE_D), addr=HOOK_D, as_bytes=False)
    bl = bytes(enc)
    assert len(bl) == 4
    data[HOOK_D:HOOK_D + 4] = bl
    # 原序列 6 字节 = movs r0,#0 ; ldr r1,[pc,#..] ; strb r0,[r1]
    # 替换为 bl trampoline_D (4B) + nop (2B)，trampoline 内复原这三条语义
    data[HOOK_D + 4:HOOK_D + 6] = b'\x00\xbf'
    print('  0x%06X  bl 0x%06X          %s   (E0F 清零点，6 字节改造)'
          % (HOOK_D, CAVE_D, bl.hex(' ').upper()))
    print('  0x%06X  nop                          00 BF   (补齐 6 字节)'
          % (HOOK_D + 4))
    print()

    # ---- 4. 数据补丁 ----
    print('=== 4. 数据补丁（掩码） ===')
    for label, off in (('蓝牙', OFF_BT_MASK), ('2.4G', OFF_G_MASK)):
        old = data[off]
        new = mask_target[off]
        op, bit = MASK_BIT_OP[off]
        data[off] = new
        if old == ORIG_MASK[off][0]:
            note = '（与原版目标一致）'
        else:
            note = '（强制修补：按实际值 %s bit%d）' % (op, bit.bit_length() - 1)
        print('  %-4s 0x%06X  0x%02X -> 0x%02X  %s bit%d %s'
              % (label, off, old, new, op, bit.bit_length() - 1, note))
    print('  说明：掩码只改 bit4（col4/ASD 列），使 r12c4 参与扫描；其余位原样保留。')
    print()

    assert len(data) == orig_len, '固件长度被改变'

    # ---- 5. 写入后反汇编复核 ----
    print('=== 5. 写入后反汇编复核 ===')
    for addr, n, label in [(HOOK_A, 0x14, '蓝牙 hook'),
                           (HOOK_B, 0x12, '2.4G hook B'),
                           (HOOK_C, 0x18, '2.4G hook C'),
                           (HOOK_D, 0x10, '去抖 hook D')]:
        print('  --- %s @0x%05X ---' % (label, addr))
        for x in md.disasm(bytes(data[addr:addr + n]), addr):
            print('     0x%05X: %-26s %-12s %s'
                  % (x.address, x.mnemonic, x.op_str, x.bytes.hex()))
        print()

    # ---- 6. 完整性 ----
    print('=== 6. 完整性 ===')
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
