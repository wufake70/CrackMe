#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CCG Crypto Crackme v1.0 Keygen
输入 Name(用户名)，生成正确的 Serial(注册码/序列号)

用法: python keygen.py [Name]
示例: python keygen.py KCTF
"""

import hashlib
import base64
import random
import sys


# =============================================================
# 1. 算法常量 (从逆向二进制中提取的硬编码值)
# =============================================================

# RC4 加密密钥 (8 字节)
# 在二进制 dump.exe 的 0x158A0 偏移处确认: 29 47 07 85 87 33 25 44
RC4_KEY = bytes([0x29, 0x47, 0x07, 0x85, 0x87, 0x33, 0x25, 0x44])

# RSA 公钥参数 (二进制字符串 "B80A90BF53C6C979")
# e = 65537 是标准 RSA 公钥指数 (a65537 变量)
RSA_N = 0xB80A90BF53C6C979   # 模数 (modulus)，大小: 64-bit
RSA_E = 65537                # 公钥指数 (public exponent)


# =============================================================
# 2. 辅助函数: 素性检测 + 因数分解
# =============================================================

def gcd(a, b):
    """最大公约数 Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a


def is_prime(n):
    """Miller-Rabin 素性检测
    (判断一个数是否大概率是素数，避免暴力试除太慢)
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    # 将 n-1 写成 2^r * d 的形式
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    # 用多个证据 a 来验证
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n):
    """Pollard's Rho 因数分解算法
    (针对半素数 p*q 形式的快速分解方法，比暴力快得多)
    """
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    while True:
        c = random.randint(1, n - 1)
        f = lambda x: (x * x + c) % n
        x = random.randint(2, n - 1)
        y = x
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
        if d != n:
            return d


def factor(n):
    """完整因数分解: 返回素因子列表 (从小到大)"""
    factors = []
    # 第一步: 小素数试除 (2 ~ 100000)
    for p in range(2, 100000):
        while n % p == 0:
            factors.append(p)
            n //= p
        if p * p > n:
            break
    if n == 1:
        return factors
    if is_prime(n):
        factors.append(n)
        return factors
    # 第二步: 剩余大数用 Pollard's Rho
    d = pollard_rho(n)
    factors.extend(factor(d))
    factors.extend(factor(n // d))
    return sorted(factors)


# =============================================================
# 3. 密码学核心算法实现
# =============================================================

def rc4_encrypt(key, data):
    """RC4 流加密/解密算法 (完全对称)

    原理:
      - KSA (Key Scheduling Algorithm): 用密钥打乱 0..255 的 S 盒
      - PRGA (Pseudo-Random Generation Algorithm): 输出密钥流，与明文异或得密文
    """
    # 初始化 S 盒: S[i] = i
    S = list(range(256))
    j = 0
    key_len = len(key)
    # ---------- KSA ----------
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) & 0xFF
        S[i], S[j] = S[j], S[i]        # 交换
    # ---------- PRGA ----------
    i = 0
    j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]        # 再次打乱
        keystream_byte = S[(S[i] + S[j]) & 0xFF]
        result.append(byte ^ keystream_byte)   # 异或 = 加/解密
    return bytes(result)


def compute_rsa_private_key(N, e):
    """从公钥 (N, e) 推导出私钥 d
    前提条件: N 必须能被成功分解为 p * q
    """
    factors = factor(N)
    if len(factors) != 2:
        raise ValueError(f"N 不是半素数(两个大素数乘积)，实际因子: {factors}")
    p, q = factors
    phi = (p - 1) * (q - 1)          # 欧拉函数 φ(N)
    # d ≡ e^{-1} mod φ(N)  (模逆运算，费马小定理/扩展欧几里得)
    d = pow(e, -1, phi)
    print(f"  [RSA分解] p = {p}")
    print(f"  [RSA分解] q = {q}")
    print(f"  [RSA分解] φ(N) = {phi}")
    print(f"  [RSA分解] d (私钥) = {d}")
    assert (e * d) % phi == 1, "私钥推导错误！"
    return d


# =============================================================
# 4. Keygen 主流程
# =============================================================

def generate_serial(name_str: str) -> str:
    """根据用户名生成注册码

    算法步骤 (完全对应程序中的 sub_401610):
      1. 计算 MD5(name) 得到 16 字节哈希值 h
      2. Part1 = RC4(h[0:8], RC4_KEY)   取前 8 字节哈希做 RC4 加密
      3. Part2 = (h[8:16])^d mod N      后 8 字节哈希做 RSA 签名 (转十进制字符串)
      4. raw_bytes = Part1 + ascii_bytes(Part2)
      5. serial = Base64(raw_bytes)
    """
    name_bytes = name_str.encode('utf-8')

    # ----- 步骤 1: MD5 哈希 -----
    h = hashlib.md5(name_bytes).digest()
    print(f"  [MD5] name = {name_str!r}")
    print(f"  [MD5] hash[:8] = {h[:8].hex()}")
    print(f"  [MD5] hash[8:] = {h[8:].hex()}")

    # ----- 步骤 2: RC4 加密前 8 字节 -----
    part1 = rc4_encrypt(RC4_KEY, h[:8])
    print(f"  [RC4] Part1(8 bytes) = {part1.hex()}")

    # ----- 步骤 3: RSA 签名后 8 字节 -----
    # 把后 8 字节哈希解释为一个大整数 (大端序 Big-Endian)
    expected_hash = int.from_bytes(h[8:16], 'big')
    print(f"  [RSA] expected_hash = {expected_hash}  (0x{expected_hash:016X})")

    # 计算/缓存私钥 d (因 N 固定，这个值每次一样)
    global _cached_d
    if _cached_d is None:
        _cached_d = compute_rsa_private_key(RSA_N, RSA_E)
    d = _cached_d

    # 签名: s = expected_hash^d mod N
    signature = pow(expected_hash, d, RSA_N)
    sig_str = str(signature)
    print(f"  [RSA] signature = {sig_str}")

    # 反向验证: signature^e mod N == expected_hash ?
    verify = pow(signature, RSA_E, RSA_N)
    if verify == expected_hash:
        print(f"  [RSA] 签名验证: ✅ 通过")
    else:
        print(f"  [RSA] 签名验证: ❌ 失败！verify={verify}  expected={expected_hash}")
        raise RuntimeError("RSA 签名验证失败")

    # ----- 步骤 4+5: 拼接 + Base64 -----
    part2_bytes = sig_str.encode('ascii')
    raw = part1 + part2_bytes

    # 检查 part2 是否全是数字 (程序 sub_401610 的 digit check)
    for b in part2_bytes:
        if not (0x30 <= b <= 0x39):
            raise RuntimeError(f"Part2 包含非数字字符: byte={b:#x}")
    print(f"  [验证] 第 8 字节起全为数字: ✅ 通过")

    serial = base64.b64encode(raw).decode('ascii')
    print(f"  [Base64] raw ({len(raw)} bytes) = {raw.hex()}")
    print(f"  [Base64] serial = {serial}")
    return serial


# RSA 私钥缓存 (避免每次重新分解)
_cached_d = None


# =============================================================
# 5. 命令行入口
# =============================================================

def main():
    if len(sys.argv) >= 2:
        name = sys.argv[1]
    else:
        name = input("请输入 Name (用户名): ").strip()

    if not name:
        print("❌ 错误: Name 不能为空")
        sys.exit(1)

    print("=" * 60)
    print(f"CCG Crypto Crackme v1.0 Keygen")
    print("=" * 60)
    print()

    try:
        serial = generate_serial(name)
    except Exception as e:
        print(f"\n❌ 生成失败: {e}")
        sys.exit(1)

    print()
    print("=" * 60)
    print("✅ 生成成功！")
    print(f"   Name:   {name}")
    print(f"   Serial: {serial}")
    print("=" * 60)
    print()
    print("在程序中:")
    print("  1. Name 输入框粘贴/输入上面的用户名")
    print("  2. Serial 输入框粘贴上面的序列号")
    print("  3. 点击 [Register] 按钮")
    print("  4. 应该弹出 'Successfully Registered!' 对话框")


if __name__ == '__main__':
    main()
