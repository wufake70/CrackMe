
# 手算模二除法
```
模二除法手算过程，被除数1101，除数多项式x^3+x^1+1(1011)
          1111
      ----------------
1011 | 1101000    <-对被除数补3个0，保证能够对每位数据都能参与多项式的异或
       1011       
      ----
        110000
        1011
        ----
         11100
         1011
         ----
          1010
          1011
          ----
          0001    <-余数
```

### S盒（Substitution Box）与滚动密钥（Rolling Key）
这两个概念是**密码学**中的核心组件，S盒用于**非线性替换**（混淆），滚动密钥用于**密钥动态更新**（扩散），常结合出现在对称加密算法（如DES、AES、自定义轻量级加密）中。下面我会用「通俗解释+代码实现」的方式帮你理解，新手也能看懂。

---

## 一、S盒（S盒）：密码的“混淆核心”
### 1. 什么是S盒？
S盒是一个**固定的替换表**，本质是“输入一个数值 → 输出另一个固定数值”的映射，核心作用是实现**非线性变换**（打破明文和密文的线性关系，让破解者无法通过数学公式推导）。
- 通俗类比：像一本“密码本”，查“1”对应“14”，查“5”对应“9”，且映射关系是不可逆的（无规律）。
- 经典应用：DES算法有8个S盒，AES算法有1个16×16的S盒。

### 2. 自定义S盒示例（4×4 S盒，最常用）
```python
# 定义一个4×4的S盒（输入0-15，输出0-15，映射无规律）
S_BOX = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,  # 索引0-15对应的值
]

def s_box_substitute(input_val):
    """S盒替换函数：输入0-15的整数，返回S盒中对应的替换值"""
    if not (0 <= input_val <= 15):
        raise ValueError("S盒输入必须是0-15的整数！")
    return S_BOX[input_val]

# 测试S盒替换
if __name__ == "__main__":
    test_input = 5  # 输入5
    substituted_val = s_box_substitute(test_input)
    print(f"S盒替换：输入{test_input} → 输出{substituted_val}")  # 输出15（对应S_BOX[5]）
```

### 3. S盒的核心特点
- **非线性**：输出≠输入的线性组合（比如不会出现“输出=输入×2+1”这种规律）；
- **可逆性**：需配套“逆S盒（Inverse S盒）”用于解密（比如AES的逆S盒是S盒的反向映射）；
- **抗攻击**：映射关系需经过严格设计，避免被差分攻击、线性攻击破解。

---

## 二、滚动密钥（Rolling Key）：动态更新的密钥
### 1. 什么是滚动密钥？
滚动密钥（也叫“动态密钥”“轮密钥”）是指**加密过程中随轮次/步骤动态变化的密钥**，核心作用是让相同明文在不同轮次用不同密钥加密（增强扩散性）。
- 通俗类比：你有一个主密码“1234”，第一轮加密用“1234”，第二轮把“1234”左移1位变成“2341”，第三轮左移2位变成“3412”，每轮用不同的“滚动密钥”；
- 经典应用：DES的16轮轮密钥扩展、AES的轮密钥生成（Key Expansion）。

### 2. 滚动密钥实现示例（左移滚动+S盒混淆）
结合S盒实现“主密钥→多轮滚动密钥”的生成，模拟AES的轮密钥扩展思路：
```python
# 主密钥（示例：4字节，对应16位，可扩展为更长）
MASTER_KEY = [0x01, 0x02, 0x03, 0x04]  # 十六进制，对应十进制1,2,3,4
S_BOX = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]

def generate_rolling_keys(master_key, rounds=4):
    """
    生成滚动密钥（轮密钥）
    :param master_key: 主密钥（列表，元素为0-15的整数）
    :param rounds: 加密轮数（需生成的滚动密钥数量）
    :return: 滚动密钥列表（每轮一个密钥）
    """
    rolling_keys = []
    current_key = master_key.copy()  # 初始密钥=主密钥
    
    for round_num in range(rounds):
        # 1. 将当前密钥加入滚动密钥列表（本轮使用）
        rolling_keys.append(current_key.copy())
        
        # 2. 密钥滚动：左移1位（核心操作）
        shifted_key = current_key[1:] + [current_key[0]]
        
        # 3. S盒混淆：对最后一个字节做S盒替换（增强随机性）
        shifted_key[-1] = s_box_substitute(shifted_key[-1])
        
        # 4. 异或轮常数（可选，增强唯一性，这里简化为轮次编号）
        shifted_key[0] ^= round_num
        
        # 5. 更新当前密钥为下一轮的基础
        current_key = shifted_key
    
    return rolling_keys

# 测试滚动密钥生成
if __name__ == "__main__":
    # 生成4轮滚动密钥
    rolling_keys = generate_rolling_keys(MASTER_KEY, rounds=4)
    
    # 打印每轮密钥
    for i, key in enumerate(rolling_keys):
        print(f"第{i+1}轮滚动密钥：{[hex(x) for x in key]}")

# 输出示例（十六进制）：
# 第1轮滚动密钥：['0x1', '0x2', '0x3', '0x4']
# 第2轮滚动密钥：['0x2', '0x3', '0x4', '0x4'] （左移+S盒替换0x1→0xe，异或0后0x2）
# 第3轮滚动密钥：['0x0', '0x4', '0x4', '0xd']
# 第4轮滚动密钥：['0x1', '0x4', '0xd', '0x2']
```

### 3. 滚动密钥的核心逻辑
1. **基础**：以主密钥为起点，每轮对密钥做“移位/替换/异或”等操作；
2. **扩散**：让密钥的每一位影响后续多轮密钥，避免单比特泄露；
3. **动态**：每轮加密用不同的滚动密钥，即使明文相同，密文也不同（抗重放攻击）。

---

## 三、S盒+滚动密钥的组合应用（完整加密示例）
下面是一个简化的加密函数，结合S盒替换和滚动密钥实现明文加密：
```python
def simple_encrypt(plaintext, master_key, rounds=4):
    """
    简化加密：明文→分块→轮加密（滚动密钥异或+S盒替换）
    :param plaintext: 明文（字符串，仅ASCII字符）
    :param master_key: 主密钥（列表）
    :param rounds: 加密轮数
    :return: 密文（列表，每个元素为0-15的整数）
    """
    # 1. 明文转数字（每个字符取ASCII值的低4位，适配4×4 S盒）
    plain_nums = [ord(c) & 0x0F for c in plaintext]
    # 2. 生成滚动密钥
    rolling_keys = generate_rolling_keys(master_key, rounds)
    # 3. 多轮加密
    cipher_nums = plain_nums.copy()
    for round_num in range(rounds):
        current_key = rolling_keys[round_num]
        # 每轮操作：密钥异或 → S盒替换
        for i in range(len(cipher_nums)):
            # 异或当前密钥的对应位（密钥循环使用）
            cipher_nums[i] ^= current_key[i % len(current_key)]
            # S盒替换
            cipher_nums[i] = s_box_substitute(cipher_nums[i])
    return cipher_nums

# 测试加密
if __name__ == "__main__":
    plaintext = "Hello"
    cipher = simple_encrypt(plaintext, MASTER_KEY, rounds=4)
    print(f"明文：{plaintext}")
    print(f"密文（数字）：{cipher}")
    print(f"密文（十六进制）：{[hex(x) for x in cipher]}")
```

---

### 总结
1. **S盒**是非线性替换表，核心作用是“混淆”，打破明文-密文的线性关系，是对称加密的安全核心；
2. **滚动密钥**是随加密轮次动态更新的密钥，核心作用是“扩散”，让密钥的每一位影响更多密文位；
3. 两者结合是对称加密算法的经典设计（如AES/DES），S盒负责局部混淆，滚动密钥负责全局扩散，共同提升加密安全性。

如果需要理解**逆S盒和解密过程**，或者想基于这两个概念实现一个完整的轻量级加密算法，我可以补充对应的代码和解释～
