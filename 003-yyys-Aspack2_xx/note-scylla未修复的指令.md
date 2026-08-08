# x32dbg scylla未修复的指令
## 原理
```
这两条指令引用同一张iat表，但是Scylla在重建iat时，只会处理第一条指令，
第二条指令不会修改为新的iat slot地址，
dump后的PE 仅当前系统可用，重启失效、换个系统也无效
```
![alt text](.\img\image.png)

![alt text](.\img\image-1.png)

## x64dbg-aotumeta 脚本修复
### 连接插件
```python
import time
import sys
import enum

# 如果当前 Python 版本没有 StrEnum，我们手动伪造一个
if not hasattr(enum, 'StrEnum'):
    class StrEnum(str, enum.Enum):
        pass
    enum.StrEnum = StrEnum

from x64dbg_automate.models import ReferenceViewRef
from x64dbg_automate import X64DbgClient

dbg = X64DbgClient(x64dbg_path=r"C:\SoftWare\x64dbg_2025-08-19_19-40\release\x32\x32dbg.exe")
# x64dbg窗口出现
# dbg.start_session(target_exe="")

# 附加到已启动dbg中
dbg.attach_session(session_pid=7644)
# dbg.go()
```
### 脚本
```python
见 fixup_iat.py
```
输出
```
[+] 新IAT表扫描完成: 区间[0x41b004, 0x41b118)  有效条目=69
[fix] 0x4010af  _GetDlgItemTextA@16       real_api=0x74c6f4c0 -> new_slot=0x41b114
[fix] 0x401317  GetModuleHandleW          real_api=0x75b7c760 -> new_slot=0x41b004
[fix] 0x4024ec  RtlDecodePointer          real_api=0x771bb630 -> new_slot=0x41b034
[fix] 0x402542  RtlDecodePointer          real_api=0x771bb630 -> new_slot=0x41b034
[fix] 0x4030ad  GetProcAddress            real_api=0x75b76780 -> new_slot=0x41b04c
[fix] 0x4045da  RtlDecodePointer          real_api=0x771bb630 -> new_slot=0x41b034
[fix] 0x404eae  RtlEncodePointer          real_api=0x771bb540 -> new_slot=0x41b030
[fix] 0x404fcc  RtlDecodePointer          real_api=0x771bb630 -> new_slot=0x41b034
[+] 完成: patched=8  failed=0
```
### `打补丁进行文件保存`
