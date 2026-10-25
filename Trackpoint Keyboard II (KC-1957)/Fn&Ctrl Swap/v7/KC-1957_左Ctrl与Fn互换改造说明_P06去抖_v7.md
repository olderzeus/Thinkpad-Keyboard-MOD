# KC-1957（nRF52832）左 Ctrl 与 Fn 完全互换改造说明 —— v7（P0.6 去抖）

> 补丁脚本 `fn_swap_debounce_patch.py`（v7）　独立验证脚本 `verify_v7.py`　补丁产物 `KC-1957_88_v7.bin`（274 字节 / 18 区域）
>
> **本版 = v6 + P0.6 去抖**。在 v6「左 Ctrl 与 Fn 完全互换」的基础上，把 P0.6 发 Left Ctrl 的判定由「原始 P0.IN bit6」改为「去抖后的 E0F2」，消除按键抖动导致的 Left Ctrl 误触发。
>
> **v7 与 v6 的差异严格限定在 trampoline C（0x50200 区）与 trampoline E（0x50400 区）**，共 50 字节；hook 点、键码表、行掩码、trampoline A/B/D 全部与 v6 逐字节一致。

---

## 一、改造背景与目标

v6 已实现「左 Ctrl 与 Fn 完全互换」：矩阵 r15c0 当 Fn、r12c4 与 GPIO P0.6 发 Left Ctrl。v6 的已知边界之一是——**P0.6 的 Left Ctrl 注入用的是原始电平（P0.IN bit6），未额外去抖**。

机械按键在按下/松开的瞬间会产生数十毫秒的抖动，若直接读原始电平，一次按键可能被识别为多次「按下→松开→按下」，导致 Left Ctrl 误触发（例如复制粘贴时 Ctrl 粘连、组合键误判）。

**v7 目标**：让 P0.6 发 Left Ctrl 也走**去抖**，与原始固件里 Fn（P0.6）的去抖一致。

---

## 二、关键机制：复用原始去抖状态机的输出 E0F2

原始固件里，P0.6 的去抖由状态机 `FUN_0001b75c` 负责：

```text
P0.6 原始电平  →  FUN_0001b75c（去抖状态机）  →  E0F（去抖后按下）
                （周期调用，经 0x2B950 回调表调度）
```

- `E0E @0x20001E0E`：去抖计数器；
- `E0F @0x20001E0F`：去抖后「P0.6 按下」（1=按下，0=松开）。

v6 改造时，为把 Fn 判定源从 P0.6 换到矩阵 r15c0，已把去抖状态机的**池槽 `0x1B8A0` 由 E0F 改指新变量 E0F2(0x20004800)**——于是去抖状态机现在把「P0.6 去抖后按下」写到 E0F2，E0F 则改为矩阵 r15c0 专用。

> **这意味着 E0F2 已经是现成的「P0.6 去抖后按下」信号**，只是 v6 里没有用它做任何事（纯隔离桶）。v7 只需让 P0.6 的 Left Ctrl 注入去读 E0F2 即可，**无需新增任何变量、钩子或去抖逻辑**。

```text
P0.6 原始电平  →  FUN_0001b75c（去抖状态机）  →  E0F2（去抖后按下）
                                                     │
                          v7 起：trampoline C / E 读 E0F2（替代读 P0.IN）
```

---

## 三、v7 的两处改动（相对 v6）

### 3.1 Trampoline C（2.4G P0.6 判定 / 伪键注入）

v6 读原始 `P0.IN` bit6 判断 P0.6 是否按下；v7 改为读 E0F2：

```text
v6：  mov.w r0,#0x50000000
      ldr.w r0,[r0,#0x510]      ; r0 = P0.IN（原始电平）
      lsls  r0,r0,#0x19         ; bit6 → bit31
      bpl   .pressed            ; P0.6 为低 → 按下

v7：  ldr.w r0,[pc,#e0f2]       ; r0 = &E0F2
      ldrb  r0,[r0]             ; r0 = E0F2（去抖后）
      cmp   r0,#1               ; 去抖后按下？
      bne   .up                 ; 否 → 松开
```

### 3.2 Trampoline E（蓝牙 HID 组装修饰位）

v6 读原始 `P0.IN` bit6 决定 `*param_1`；v7 改为读 E0F2：

```text
v6：  mov.w r0,#0x50000000
      ldr.w r0,[r0,#0x510]      ; r0 = P0.IN（原始电平）
      lsls  r0,r0,#0x19
      bpl   .pressed

v7：  ldr.w r0,[pc,#e0f2]       ; r0 = &E0F2
      ldrb  r0,[r0]             ; r0 = E0F2（去抖后）
      cmp   r0,#1
      bne   .fin                ; 未按下 → *param_1 保持 0
```

> 两处改动把「3 条指令读 P0.IN」换成「LIT + ldrb + cmp」共 8 字节，长度恰好相同，因此 trampoline 总长度与布局不变，其余补丁点零影响。

---

## 四、Trampoline C / E 完整代码（v7，真实二进制）

### Trampoline C（@0x50200，40 字节）

```text
0x50200  DF F8 1C 00  ldr.w  r0, [pc, #0x1c]   ; r0 = &E0F
0x50204  00 78        ldrb   r0, [r0]          ; r0 = E0F（矩阵 Fn）
0x50206  07 46        mov    r7, r0            ; r7 = 矩阵 Fn
0x50208  DF F8 18 00  ldr.w  r0, [pc, #0x18]   ; r0 = &E0F2
0x5020C  00 78        ldrb   r0, [r0]          ; r0 = E0F2（去抖后 P0.6）
0x5020E  01 28        cmp    r0, #1            ; 去抖后按下？
0x50210  04 D1        bne    #0x5021c          ; 否 → .up
0x50212  01 25        movs   r5, #1            ; uVar11 = 1
0x50214  E0 21        movs   r1, #0xe0         ; 伪 Left Ctrl 键
0x50216  8D F8 10 10  strb.w r1, [sp, #0x10]   ; local_98[0] = 0xE0
0x5021A  00 E0        b      #0x5021e
0x5021C  00 25        movs   r5, #0            ; .up: uVar11 = 0
0x5021E  70 47        bx     lr
```

字面量池：`0x20001E0F`（E0F）、`0x20004800`（E0F2）

### Trampoline E（@0x50400，28 字节）

```text
0x50400  00 23        movs   r3, #0
0x50402  0B 70        strb   r3, [r1]          ; *param_1 = 0
0x50404  DF F8 10 00  ldr.w  r0, [pc, #0x10]   ; r0 = &E0F2
0x50408  00 78        ldrb   r0, [r0]          ; r0 = E0F2（去抖后 P0.6）
0x5040A  01 28        cmp    r0, #1            ; 去抖后按下？
0x5040C  01 D1        bne    #0x50412          ; 否 → .fin
0x5040E  01 23        movs   r3, #1
0x50410  0B 70        strb   r3, [r1]          ; *param_1 = 1（Left Ctrl 位0）
0x50412  00 23        movs   r3, #0            ; 返回时 r3=0（后续 strb r3,[r1,#7] 依赖）
0x50414  70 47        bx     lr
```

字面量池：`0x20004800`（E0F2）

---

## 五、预期运行结果（v7）

| 物理键位 | 行为 | 说明 |
|---|---|---|
| 矩阵 r12c4 | 发 Left Ctrl | 与 v6 一致（键码表 0xE0 + 行掩码放行） |
| 矩阵 r15c0 | 充当 Fn（本身不发码） | 与 v6 一致（键码表 0x00 + 扫描钩子写 E0F） |
| GPIO P0.6 | 发 Left Ctrl | **v7 新增去抖**：读 E0F2 而非原始 P0.IN |

**去抖效果**：P0.6 按下/松开的抖动会被 `FUN_0001b75c` 状态机滤除，只有当去抖确认「按下」后 E0F2 才置 1，Left Ctrl 才会注入；松开的抖动同理。一次物理按键对应一次干净的 Left Ctrl 通断，与原始 Fn 键的去抖行为一致。

---

## 六、补丁清单与改动范围

数据补丁与 hook 点与 v6 完全相同：

| 类别 | 地址 | 原始 | 补丁后 | 作用 |
|---|---|---|---|---|
| 键码表 BT[100] | 0x2CC54 | 0x00 | 0xE0 | r12c4 → Left Ctrl |
| 键码表 BT[120] | 0x2CC68 | 0xE0 | 0x00 | r15c0 → 不发码（当 Fn） |
| 键码表 G[100] | 0x4A75E | 0x00 | 0xE0 | r12c4 → Left Ctrl |
| 键码表 G[120] | 0x4A772 | 0xE0 | 0x00 | r15c0 → 不发码（当 Fn） |
| 行掩码 BT r12 | 0x1E84C | 0xE7 | 0xF7 | 放行 col4 |
| 行掩码 G r12 | 0x4A6B2 | 0x1C | 0x0C | 放行 col4 |
| 去抖池槽 | 0x1B8A0 | 0x20001E0F | 0x20004800 | E0F → E0F2（解耦） |
| HOOK A | 0x1E4E4 | nop+ldr | bl 0x50000 | BT 扫描写 E0F |
| HOOK B | 0x41252 | ldrb.w | bl 0x50100 | 2.4G 扫描写 E0F |
| HOOK C | 0x411C6 | 18 字节 | bl 0x50200 | 2.4G 伪键（**v7 读 E0F2**） |
| HOOK D | 0x1EB74 | 22 字节 | bl 0x50300 | BT 判定换 E0F |
| HOOK E | 0x23A76 | movs+strb | bl 0x50400 | BT 注入修饰位（**v7 读 E0F2**） |

- 改动范围：274 字节 / 18 区域，全部落在 0x50000–0x60000 擦除空洞（静态不可达），向量表 Reset_Handler（0x00000A81）不变。
- **v7 相对 v6 仅差 trampoline C / E 两段（共 50 字节）**，其余逐字节一致。
- 独立验证脚本 `verify_v7.py` 共 **89 项检查全部通过**（含行为仿真验证「P0.6 → Left Ctrl 走 E0F2 去抖」）。

---

## 七、验证结论

- `verify_v7.py KC-1957_88_orig.bin KC-1957_88_v7.bin` → 89 项全部通过。
- 行为仿真确认：trampoline C / E 读 E0F2（而非 P0.IN），E0F2=1（去抖按下）→ 注入 Left Ctrl，E0F2=0（去抖松开）→ 不注入。
- 与 v6 逐字节比对：差异仅 trampoline C / E 两段，无越界。

> **结论**：v7 在 v6 基础上为 P0.6 的 Left Ctrl 注入增加去抖，语义正确、改动最小、可独立刷写验证。

---

> 本文档以 Markdown 为单一事实源。固件哈希（SHA-256）：`orig = 57df656c…`、`v7 = 3f68e61b…`。
