from z3 import *

# 1. 创建 4 个 8 位的位向量变量（代表 4 个字节的字符/Flag）
x0 = BitVec('x0', 8)
x1 = BitVec('x1', 8)
x2 = BitVec('x2', 8)
x3 = BitVec('x3', 8)

# 2. 创建求解器对象
solver = Solver()

# 3. 原封不动地照抄程序的验证条件（正向逻辑）
solver.add((x0 ^ 0x55) + (x1 << 2) == 0x123)
solver.add((x1 * 3) - (x2 ^ x0) == 0x45)
solver.add((x2 >> 1) + (x3 * 7) == 0x289)
solver.add((x3 ^ x0) + (x1 & x2) == 0x9F)

# 4. 添加可打印字符的范围约束 (ASCII 32 ~ 126)
solver.add(UGT(x0, 31), ULT(x0, 127))  # UGT: 无符号大于, ULT: 无符号小于
solver.add(UGT(x1, 31), ULT(x1, 127))
solver.add(UGT(x2, 31), ULT(x2, 127))
solver.add(UGT(x3, 31), ULT(x3, 127))

# 5. 求解并拼接 Flag
if solver.check() == sat:
    model = solver.model()
    # 提取每个变量的值（转为整数）
    v0 = model[x0].as_long()
    v1 = model[x1].as_long()
    v2 = model[x2].as_long()
    v3 = model[x3].as_long()
    
    # 拼成最终的 Flag 字符串
    flag = "".join(chr(v) for v in [v0, v1, v2, v3])
    print(f"[+] 求解成功！Flag 是: {flag}")
    print(f"[+] 对应的 ASCII 码: x0={v0}, x1={v1}, x2={v2}, x3={v3}")
else:
    print("[-] 无解 (UNSAT)")