import re

# ============================================================
# 00 手动输入：新IAT表的地址范围（左闭右开区间，按4字节一个槽位）
# ============================================================
new_iat_start = 0x0041B004
new_iat_end   = 0x0041B118   # 按你实际写了多少条目改这个值

# ============================================================
# 01 未修复的指令列表（地址 + 反汇编文本）
# ============================================================
unfixed_instructions = [
    [0x004010AF, "mov esi,dword ptr ds:[<&_GetDlgItemTextA@16>]"],
    [0x00401317, "mov esi,dword ptr ds:[<&GetModuleHandleW>]"],
    [0x004024EC, "mov esi,dword ptr ds:[<&RtlDecodePointer>]"],
    [0x00402542, "mov esi,dword ptr ds:[<&RtlDecodePointer>]"],
    [0x004030AD, "mov esi,dword ptr ds:[<&GetProcAddress>]"],
    [0x004045DA, "mov esi,dword ptr ds:[<&RtlDecodePointer>]"],
    [0x00404EAE, "mov ebx,dword ptr ds:[<&RtlEncodePointer>]"],
    [0x00404FCC, "mov ebx,dword ptr ds:[<&RtlDecodePointer>]"],
]

pattern = re.compile(r'<&([A-Za-z0-9_@]+)>')

# ============================================================
# 02 遍历新IAT表区间，构建 { 真实API地址 : 新槽地址 } 映射
# ============================================================
addr_to_new_slot = {}
slot = new_iat_start
while slot < new_iat_end:
    val = dbg.read_dword(slot)
    if val != 0:
        addr_to_new_slot[val] = slot
    slot += 4

print(f"[+] 新IAT表扫描完成: 区间[{hex(new_iat_start)}, {hex(new_iat_end)})  有效条目={len(addr_to_new_slot)}")

# ============================================================
# 03 遍历未修复指令，逐条修复
# ============================================================
patched, failed = 0, 0
for instr_addr, text in unfixed_instructions:
    m = pattern.search(text)
    api_name = m.group(1) if m else "?"

    next_addr = dbg.eval_sync(f"dis.next({hex(instr_addr)})")[0]
    operand_addr = next_addr - 4                  # 指令当前引用的原IAT槽地址

    orig_slot_val = dbg.read_dword(operand_addr)   # = 原始IAT槽地址
    real_api_addr = dbg.read_dword(orig_slot_val)  # = 真实函数地址

    if real_api_addr in addr_to_new_slot:
        new_slot_addr = addr_to_new_slot[real_api_addr]
        ret = dbg.cmd_sync(f"4:[{hex(operand_addr)}]={hex(new_slot_addr)}")
        if ret:
            patched += 1
            print(f"[fix] {hex(instr_addr)}  {api_name:25s} real_api={hex(real_api_addr)} -> new_slot={hex(new_slot_addr)}")
        else:
            failed += 1
            print(f"[FAIL-write] {hex(instr_addr)}  {api_name}")
    else:
        failed += 1
        print(f"[FAIL-notfound] {hex(instr_addr)}  {api_name}  real_api={hex(real_api_addr)} 不在新表里，需要先补充到新表")

print(f"[+] 完成: patched={patched}  failed={failed}")