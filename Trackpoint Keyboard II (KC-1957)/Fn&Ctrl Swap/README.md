# KC-1957 左 Ctrl 与 Fn 完全互换改造 —— v8（E0F 读取点后置）

本目录为 v8 版本产物。v8 = v7 + **2.4G 路径 E0F 读取点后置**。

## 一句话说明

v7 在 2.4G 扫描函数里「于**行循环之前**一次性把 E0F 读进 `r7`」，而 `r7` 被行循环内 `0x41286` 与行循环后 `0x413D0` 两处 `cbz r7` 消费 → 用的是上一轮扫描的 Fn 状态，**滞后 1 个扫描周期**。BT 路径因为是「使用点即时读取」而没有这个问题。

v8 把这次读取挪进**行循环内**（trampoline B 的 `.restore` 每个 row 刷新一次 `r7 = E0F`），并删除 trampoline C 里对应的赋值，使行循环后的 `0x413D0` 读到**本轮最新**的 E0F —— **与 BT 路径完全对齐，零滞后**。

**v8 不改变任何键位输出**，只改变 2.4G 通道对 Fn 状态的取样时刻。

## ⚠️ 使用前必读

1. **硬件版本**：本补丁只适用于 **V2 及以上**硬件。V1 等低版本固件布局不同，注入地址与键位表假设不成立，**不要尝试**；低版本设备需自行向持有 V2+ 固件的人索取一份 V2+ 固件。
2. **不要用哈希校验固件**：每台设备 Dump 出来的固件本来就不完全一样（蓝牙名称 `@0x21228`、2.4G 无线 ID `@0x78054` 为设备独有），所以**原厂固件和补丁产物的 SHA-256 都因机而异**。
3. **正确判据**：以**补丁脚本的前置检查**（干跑）和**验证脚本的结构性检查**为准 —— 前者会校验键位表特征、ROWPIN 表、行掩码位、代码空洞、选址窗口；后者会校验差异区间精确落在预期 18 个区间、其余 524018 字节逐字节相同、5 个钩子与各 trampoline 语义正确。`verify_v8.py` 打印的哈希仅供参考，不参与通过判定。
4. **`--out` 必须显式指定**：不指定时会回退到输入路径，配合 `--apply` 会**覆盖你的原始固件**。

## 文件清单

| 文件 | 说明 |
|---|---|
| `fn_swap_debounce_inline_patch.py` | 补丁脚本（v8，**直接对原始固件打补丁**） |
| `verify_v8.py` | 独立验证脚本（capstone 反汇编 + 字节比对 + E0F 新鲜度仿真，全项通过） |
| `KC-1957_左Ctrl与Fn互换改造说明_P06去抖_E0F后置_v8.md` | 完整说明文档（单一事实源，13 章） |
| `KC-1957_左Ctrl与Fn互换改造说明_P06去抖_E0F后置_v8.html` | 执行原理（框图模式，3 张 SVG 对比图） |
| `SHA256SUMS.txt` | 文件校验和 |
| `README.md` | 本文件 |
| `disasm*.py` / `disasm_*.txt` | 反汇编分析中间产物（保留作证据） |

**未随仓库分发**（原因见顶层 README「为什么不提供 .bin」）：

| 文件 | 说明 |
|---|---|
| `KC-1957_88_v8.bin` | **补丁后固件**（270 字节 / 18 区域）—— 自行打补丁生成，哈希见 `SHA256SUMS.txt` |
| `KC-1957_88_v8.bin.bak` | 应用补丁时自动备份的原始内容 |
| `KC-1957_88_orig.bin` | 原始固件（补丁输入 / 回滚基线）—— 自行 J-Link Dump |

## 用法

```text
# 干跑检查（只报告，不写盘）
python fn_swap_debounce_inline_patch.py KC-1957_88_orig.bin

# 写出补丁固件（--out 必须显式指定，否则会覆盖输入固件）
python fn_swap_debounce_inline_patch.py KC-1957_88_orig.bin --out KC-1957_88_v8.bin --apply

# 独立验证（--orig / --v8 需显式指定）
python verify_v8.py --orig KC-1957_88_orig.bin --v8 KC-1957_88_v8.bin
```

Windows 本机（原始固件在 `..\v7_p06_debounce\KC-1957_88_orig.bin`）：

```powershell
$env:PYTHONPATH = "C:/Users/older/AppData/Roaming/Python/Python314/site-packages"
$STORE = "C:/Users/older/AppData/Local/Microsoft/WindowsApps/PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0/python.exe"

& $STORE fn_swap_debounce_inline_patch.py ..\v7_p06_debounce\KC-1957_88_orig.bin --out KC-1957_88_v8.bin --apply
& $STORE verify_v8.py --orig ..\v7_p06_debounce\KC-1957_88_orig.bin --v8 KC-1957_88_v8.bin
```

> `verify_v8.py` 的 `--orig` / `--v8` 默认值指向仓库外的本地路径，在克隆下来的仓库中不适用，**请显式指定**。

## v8 相对 v7 的变化

仅两处 trampoline 改动，净 −4 字节：

| 区段 | v7 | v8 | 变化 |
|---|---|---|---|
| Trampoline B（0x50100） | 64B | 72B | `.restore` 处新增 `ldr.w r7,[pc]` + `ldrb r7,[r7]`（每 row 刷新 r7） |
| Trampoline C（0x50200） | 40B | 28B | 删除行循环前的「读 E0F → `mov r7,r0`」 |
| 其余全部 | — | — | 逐字节一致（数据补丁、HOOK_A/D/E、trampoline A/D/E） |

固件总改动：v7 = 274B/18 区域 → v8 = **270B/18 区域**。

## 关键结论速览

- 2.4G 路径 `r7` 语义：v7「循环前快照」→ v8「当前 E0F（实时镜像）」；BT 始终是「当前 E0F」。
- 行循环后 `0x413D0 cbz r7` 读到的值 = **本轮最新 E0F**（零滞后）。
- 矩阵式 Fn 的**固有** 1 周期滞后（row15 最后一行决定）依旧存在，且 BT 同样存在——两条路径现已一致。
- BT 路径**零字节改动**。

## 关于 SHA256SUMS.txt 里的 .bin 哈希

`SHA256SUMS.txt` 中的 `.bin` 条目是**参考机**的产物指纹：

- **同一台设备**重复 Dump 并打补丁 → 哈希一致，可用于确认 Dump 是否稳定；
- **不同设备** → 哈希**必然不同**（原厂固件本就因机而异），**属正常现象**，不要据此怀疑补丁。

判断补丁是否正确，请以**补丁脚本的前置检查**与**验证脚本的结构性检查**为准，不要用哈希。

详见 `KC-1957_左Ctrl与Fn互换改造说明_P06去抖_E0F后置_v8.md`。
