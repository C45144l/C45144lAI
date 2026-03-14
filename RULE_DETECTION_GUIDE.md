# 規則檢測指南 (Rule-Based Detection Guide)

## 概述 (Overview)

規則檢測是多層威脅防禦系統的優先級最高的防禦層。它允許安全團隊通過自定義正則表達式模式來檢測特定威脅，無需修改核心代碼。

## 核心特性 (Key Features)

### ✅ 優勢
- **高優先級**: 自定義規則在所有威脅檢測中優先返回
- **靈活的模式**: 支持正則表達式（Regex）進行複雜的模式匹配
- **不區分大小寫**: 默認使用 `re.IGNORECASE` 進行模式匹配
- **錯誤容忍**: 無效的正則表達式被自動跳過
- **批量檢測**: 支持對多個有效負載進行高效批量分析
- **運行時修改**: 可在程序執行期間動態添加和修改規則

## 使用示例 (Usage Examples)

### 基本使用 (Basic Usage)

```python
from src.defense_system import LurRenJiaDefenseSystem

# 初始化防禦系統
system = LurRenJiaDefenseSystem()

# 方法 1: 添加自定義威脅規則
system.threat_patterns['custom_attacks'] = [
    r'vulnerable_endpoint',
    r'admin_panel',
    r'backup\.sql',
    r'config\.php',
    r'\.env',
]

# 進行規則檢測
is_threat, threat_name, matched_patterns = system.rule_based_check('GET /admin_panel')

# 結果:
# is_threat: True
# threat_name: 'custom_attacks'
# matched_patterns: [r'admin_panel']
```

### 高級規則 (Advanced Patterns)

```python
# SQL 注入攻擊檢測
system.threat_patterns['sql_injection'] = [
    r"'\s*or\s*'1'\s*=\s*'1",
    r'union.*select.*from',
    r'drop\s+table',
    r'delete\s+from',
    r'exec\s*\(',
]

# XSS 攻擊檢測
system.threat_patterns['xss_attacks'] = [
    r'<script[^>]*>',
    r'javascript\s*:',
    r'onerror\s*=',
    r'onload\s*=',
]

# API 濫用檢測
system.threat_patterns['api_abuse'] = [
    r'/api/.*?/admin',
    r'/api/.*?/debug',
    r'/api/.*?/backup',
    r'/admin.*',
    r'/config\.php',
]

# 遠端代碼執行 (RCE) 檢測
system.threat_patterns['rce_patterns'] = [
    r'cat\s+/etc/passwd',
    r'whoami',
    r'bash\s+-i',
    r'nc\s+-l',
    r'/dev/tcp',
]
```

### 批量檢測 (Batch Detection)

```python
# 對多個有效負載進行批量檢測
payloads = [
    'GET /admin_panel',
    'SELECT * FROM users WHERE id=1',
    'GET /normal_page',
    '<script>alert("XSS")</script>',
]

results = system.batch_rule_check(payloads)

# 結果格式:
# [
#     {
#         'payload': 'GET /admin_panel',
#         'is_threat': True,
#         'threat_type': 'custom_attacks',
#         'matched_patterns': [r'admin_panel']
#     },
#     ...
# ]
```

### 與主分析流程集成 (Integration with Main Analysis)

```python
# 訓練系統
import numpy as np
training_data = np.array([
    [100, 50],   # 正常流量
    [110, 55],
    [105, 52],
])
system.train_ai_baseline(training_data)

# 添加自定義規則
system.threat_patterns['critical_endpoints'] = [
    r'/admin',
    r'/backup',
    r'/config',
]

# 使用主分析方法
result = system.analyze_incoming_traffic(
    ip='192.168.1.100',
    payload='GET /admin/panel',
    traffic_features=[100, 50]
)

# 規則檢測優先級最高，會立即返回：
# result['threat_type'] = 'critical_endpoints'
# result['action'] = 'blocked'
```

### 動態修改規則 (Dynamic Rule Modification)

```python
# 在運行時添加新規則
system.threat_patterns['new_threats'] = [r'new_pattern']

# 修改現有規則
system.threat_patterns['custom_attacks'].append(r'new_payload')

# 清除所有規則（回到默認規則）
system.threat_patterns.clear()
system._initialize_threat_patterns()

# 替換所有規則
system.threat_patterns = {
    'critical': [r'critical_pattern'],
    'high': [r'high_pattern'],
}
```

## 防禦層級架構 (Defense Layer Architecture)

規則檢測系統採用多層防禦架構，優先級從高到低：

```
優先級 0 (最高): 🔴 規則檢測 (Rule-Based Detection)
├─ 自定義威脅模式
└─ 立即返回匹配的威脅名稱

優先級 1: 🟠 關鍵威脅 (Critical Threats)
├─ SQL 注入 (SQL_INJECTION)
├─ 命令注入 (COMMAND_INJECTION)
└─ APT 數據竊取 (APT_EXFILTRATION)

優先級 2: 🟡 高風險威脅 (High-Risk Threats)
├─ XSS 攻擊 (XSS)
└─ 暴力破解 (BRUTE_FORCE)

優先級 3: 🟢 中風險威脅 (Medium-Risk Threats)
├─ 惡意程式 (MALWARE)
└─ 異常流量 (ABNORMAL_TRAFFIC)

優先級 4 (最低): 🔵 AI 異常檢測 (AI Baseline)
```

## 正則表達式模式參考 (Regex Pattern Reference)

### 常用威脅模式

| 威脅類型 | 正則表達式示例 | 描述 |
|---------|-------------|------|
| SQL 注入 | `union.*select` | 檢測 UNION 聯合查詢 |
| SQL 注入 | `drop\s+table` | 檢測刪除表操作 |
| XSS | `<script[^>]*>` | 檢測內聯 script 標籤 |
| XSS | `onerror\s*=` | 檢測 onerror 事件 |
| RCE | `bash\s+-i` | 檢測交互式 shell |
| 路徑遍歷 | `\.\.\/` | 檢測相對路徑遍歷 |
| 敏感文件 | `\.env\|config\.php` | 檢測敏感配置文件 |

### 正則表達式語法

```python
# 基本匹配
r'literal_string'          # 精確匹配
r'pattern1|pattern2'       # 或操作

# 量詞
r'a+'                      # 一個或多個 'a'
r'b*'                      # 零個或多個 'b'
r'c?'                      # 零個或一個 'c'
r'd{2,4}'                  # 2-4 個 'd'

# 字符類
r'[abc]'                   # 匹配 a、b 或 c
r'[^abc]'                  # 不匹配 a、b 或 c
r'\d'                      # 任何數字
r'\w'                      # 任何單詞字符

# 邊界
r'^start'                  # 字符串開始
r'end$'                    # 字符串結尾
r'\badmin\b'               # 單詞邊界

# 特殊字符轉義
r'\.'                      # 字面意思的點 (.)
r'\/'                      # 字面意思的斜杠 (/)
r'\\'                      # 字面意思的反斜杠 (\)
```

## 性能考慮 (Performance Considerations)

### ⚡ 性能特性

- **單次檢測**: ~0.001ms per payload
- **批量檢測**: 1000 個有效負載 < 1 秒
- **內存使用**: 每個模式 ~100 字節
- **CPU 使用**: 最多 O(n*m)，其中 n=有效負載長度，m=模式數量

### 優化建議

```python
# ✅ 好的做法
# 1. 使用更具體的模式
system.threat_patterns['sql'] = [r'^(SELECT|INSERT|UPDATE|DELETE)']

# 2. 避免過度的量詞
# ❌ 避免: r'.*admin.*'
# ✅ 使用: r'admin'

# 3. 使用字符類而不是選擇
# ❌ 避免: r'(a|b|c|d|e)'
# ✅ 使用: r'[abcde]'

# 4. 批量檢測 vs 單個
# 大量檢測時使用 batch_rule_check()
results = system.batch_rule_check(payloads_list)
```

## 集成示例 (Integration Examples)

### Web 框架集成 (Flask)

```python
from flask import Flask, request
from src.defense_system import LurRenJiaDefenseSystem

app = Flask(__name__)
defense_system = LurRenJiaDefenseSystem()

# 設置規則
defense_system.threat_patterns['web_attacks'] = [
    r'<script.*?>',
    r'javascript:',
    r'union.*select',
]

@app.before_request
def check_threat():
    # 獲取請求信息
    payload = request.full_path
    ip = request.remote_addr
    
    # 檢測威脅
    is_threat, threat_name, patterns = defense_system.rule_based_check(payload)
    
    if is_threat:
        return {'error': 'Threat detected', 'threat': threat_name}, 403
```

### 日誌分析

```python
# 分析歷史日誌
import pandas as pd

logs = pd.read_csv('access_logs.csv')
suspicious_payloads = logs['request_payload'].tolist()

results = defense_system.batch_rule_check(suspicious_payloads)

# 統計結果
for threat_type in set(r['threat_type'] for r in results):
    count = sum(1 for r in results if r['threat_type'] == threat_type)
    print(f"{threat_type}: {count} 次檢測")
```

## 測試與驗證 (Testing & Validation)

### 測試套件

規則檢測功能包含 26 個全面的測試：

```bash
# 運行規則檢測測試
pytest tests/test_rule_based_detection.py -v

# 運行特定測試
pytest tests/test_rule_based_detection.py::TestRuleBasedDetection::test_rule_check_simple_pattern -v

# 運行所有測試
pytest tests/ -v
```

### 測試覆蓋範圍

- ✅ 基本模式匹配
- ✅ 不區分大小寫
- ✅ 正則表達式支持
- ✅ 批量檢測
- ✅ 無效正則表達式處理
- ✅ 集成與優先級
- ✅ 性能基準測試

## 故障排除 (Troubleshooting)

### 常見問題

| 問題 | 原因 | 解決方案 |
|------|------|--------|
| 規則未匹配 | 模式不正確 | 使用正則表達式測試工具驗證 |
| 性能下降 | 規則過多或複雜 | 簡化模式或減少規則數量 |
| 無效的正則表達式 | 語法錯誤 | 檢查目標正則表達式的返回值 |
| 誤報/漏報 | 規則不夠精確 | 調整模式的具體性 |

### 調試技巧

```python
# 查看所有威脅模式
print(system.get_threat_patterns())

# 測試特定模式
is_threat, threat_name, patterns = system.rule_based_check('test_payload')
print(f"Threat: {is_threat}, Type: {threat_name}, Patterns: {patterns}")

# 檢查規則的匹配情況
import re
payload = "GET /admin_panel"
pattern = r'admin_panel'
match = re.search(pattern, payload, re.IGNORECASE)
print(f"Match: {match}")
```

## 最佳實踐 (Best Practices)

### ✅ 推薦做法

1. **模式組織**: 按威脅類型組織規則
2. **命名規範**: 使用清晰的威脅名稱
3. **文檔記錄**: 記錄每個規則的目的
4. **定期審查**: 定期檢查和更新規則
5. **測試前部署**: 新規則部署前進行測試
6. **性能監控**: 監控規則檢測性能

### ❌ 應避免

1. **過於寬泛的模式**: 可能導致誤報
2. **複雜的嵌套模式**: 降低性能
3. **未測試的規則**: 可能產生意外結果
4. **過多規則**: 消耗系統資源
5. **硬編碼路徑**: 應使用配置文件

## 技術細節 (Technical Details)

### 方法簽名

```python
# 單個檢測
def rule_based_check(self, payload: str) -> Tuple[bool, str, List[str]]:
    """
    Args:
        payload: 要檢測的有效負載
    
    Returns:
        (is_threat, threat_name, matched_patterns)
    """

# 批量檢測
def batch_rule_check(self, payloads: List[str]) -> List[Dict]:
    """
    Args:
        payloads: 有效負載列表
    
    Returns:
        [
            {'payload': str, 'is_threat': bool, 'threat_type': str, 'matched_patterns': list},
            ...
        ]
    """
```

### 內部實現

- 威脅模式存儲在 `self.threat_patterns` 字典中
- 每個威脅類型映射到正則表達式列表
- 使用 `re.search()` 與 `re.IGNORECASE` 進行匹配
- 在第一個匹配時返回結果

## 更新日誌 (Changelog)

### v1.0.0 (當前)
- ✅ 實現 `rule_based_check()` 方法
- ✅ 實現 `batch_rule_check()` 方法
- ✅ 集成規則檢測到主防禦流程
- ✅ 添加 26 個全面測試
- ✅ 完整文檔

## 相關資源 (Related Resources)

- [Python 正則表達式文檔](https://docs.python.org/3/library/re.html)
- [正則表達式測試工具](https://regex101.com/)
- [OWASP 安全規則庫](https://owasp.org/)
- [Snort 簽名規則](https://www.snort.org/profiles)

---

**上次更新**: 2024-12-19
**版本**: 1.0.0
**維護者**: C45144lAI Defense System Team
