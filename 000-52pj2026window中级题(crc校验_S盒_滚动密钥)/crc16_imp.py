# 比特反转
def bit_reverse(num, bit_width):
    result = 0
    for i in range(bit_width):
        # 取出第 i 位（从低位开始数，i=0 是最低位）
        bit = (num >> i) & 1
        # 把它放到对称位置：第 (bit_width-1-i) 位
        result |= bit << (bit_width - 1 - i)
    return result

'''
参数名称			取值
生成多项式			0x11021
初始值			    0xFFFF
结果异或值			0x0000
输入反转			false
输出反转			false
'''
def crc16_ccitt(data):
    
    # 如果是字符串，转成 bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # 初始值（最常见的 CCITT 版本是 0xFFFF）
    crc = 0xFFFF
    
    for byte in data:            
        # 把当前字节左移 8 位异或进 CRC（高字节对齐）,保证之前的数据的crc参与计算
        crc ^= (byte << 8)
        
        # 循环左移和异或均为线性操作，意味着可以查表计算
        # 对这个字节做 8 次移位 + 条件异或(模二除法，连续没有借位减法)
        '''
        for _ in range(8):
            crc<<=1 # ***先左移在异或***
            if crc & 0x10000:           # 最高位是 1
                crc ^=0x11021
                
            crc &= 0xFFFF              # 保持 16 位
        '''
        for _ in range(8):
            # 先判断当前最高位（bit15）是不是 1
            if crc & 0x8000:
            # 最高位是 1 → 先左移 1 位（相当于 ×x），再异或多项式
                crc = (crc << 1) ^ 0x1021 # ***先左移在异或***
            else:
                # 最高位是 0 → 只左移 1 位
                crc = crc << 1
                
            # 强制保持 16 位（Python 整数无限位，必须截断）
            crc &= 0xFFFF
    return crc

def crc16_ccitt_lookup(data):
    # 如果是字符串，转成 bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # 预计算 256 项表（512 字节）
    table = [0] * 256
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
        table[i] = crc
    
    # 计算 CRC
    crc = 0xFFFF
    for byte in data:
        # 高 8 位与当前字节异或 → 查表
        index = (crc >> 8) ^ byte
        crc = ((crc << 8) ^ table[index]) & 0xFFFF
    
    return crc


# 测试用例（经典测试向量）
if __name__ == "__main__":
	print(hex(crc16_ccitt("\1")))           # 0xf1d1
	print(hex(crc16_ccitt("hello world")))  # 0xefeb
	print(hex(crc16_ccitt_lookup("\1")))           # 0xf1d1
	print(hex(crc16_ccitt_lookup("hello world")))  # 0xefeb


    