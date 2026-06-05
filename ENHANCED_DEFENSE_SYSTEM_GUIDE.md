# 增強型防禦系統指南 (Enhanced Defense System Guide)

## 📖 概述

增強型防禦系統是基於 `LurRenJiaDefenseSystem` 的擴展，添加了行業特定的威脅檢測規則和加權風險評分功能。它可以檢測針對不同行業的特定威脅，並提供詳細的風險評估。

## ✨ 核心特性

### 🏭 行業特定威脅檢測

系統內置 4 個主要行業的威脅規則：

#### 1. 金融行業威脅 (`financial_threats`)
- 信用卡信息
- 銀行帳戶
- 銀行路由號碼
- SWIFT 代碼
- IBAN

#### 2. 醫療行業威脅 (`healthcare_threats`)
- 患者 ID
- 醫療記錄
- 處方信息
- HIPAA 違規
- 受保護健康信息

#### 3. 政府機構威脅 (`government_threats`)
- 機密信息
- 絕密文件
- 社會安全號 (SSN)
- 護照
- 國家身份證

#### 4. 加密貨幣威脅 (`crypto_threats`)
- 私鑰
- 種子短語 (Seed Phrase)
- 錢包地址
- 加密貨幣
- 比特幣/以太坊相關信息

### 🎯 加權風險評分

系統不僅計算基礎風險分數，還包括多個維度的評分：

```
加權風險分數 = 
    基礎風險 (40%) +
    有效負載複雜度 (20%) +
    特徵異常度 (20%) +
    威脅嚴重程度 (20%)
```

## 🚀 快速開始

### 基本使用

```python
from src.enhanced_defense_system import EnhancedDefenseSystem
import numpy as np

# 初始化系統
system = EnhancedDefenseSystem()

# 訓練 AI 模型
normal_data = np.random.randn(1000, 2) * 10 + 50
system.train_ai_baseline(normal_data)

# 進行分析
result = system.analyze_with_scoring(
    ip="192.168.1.100",
    payload="GET /admin/credit_card_list",
    traffic_features=np.array([100, 50])
)

# 查看結果
print(f"加權風險: {result['weighted_risk_score']:.2%}")
print(f"詳細評分: {result['detailed_scores']}")
```

### 添加自定義規則

```python
# 添加內部威脅規則
system.add_custom_pattern('internal_threats', [
    r'confidential_data',
    r'employee_records',
    r'business_strategy',
    r'proprietary_algorithm'
])

# 檢測內部威脅
result = system.analyze_with_scoring(
    ip="192.168.1.1",
    payload="SELECT confidential_data FROM employees",
    traffic_features=np.array([52, 12])
)
```

## 📊 詳細評分系統

### 評分組件

#### 1. 基礎風險 (Base Risk) - 40 權重
由 AI 異常檢測引擎計算
- 範圍: 0-1
- 基於流量特徵的正常性分析

#### 2. 有效負載複雜度 (Payload Complexity) - 20 權重
基於有效負載的大小和複雜性
- 公式: min(payload_length / 1000, 1.0)
- 更長的有效負載通常表示更複雜的攻擊

#### 3. 特徵異常度 (Feature Anomaly) - 20 權重
基於流量特徵的標準差
- 公式: min(traffic_features.std() / 100, 1.0)
- 衡量流量特徵的變異性

#### 4. 威脅嚴重程度 (Threat Severity) - 20 權重
根據檢測到的威脅類型
- 命令注入: 0.99 (最高)
- SQL 注入: 0.95
- 金融威脅: 0.92
- XSS: 0.85 (最低)

### 嚴重程度映射

| 威脅類型 | 嚴重程度 | 描述 |
|---------|--------|------|
| COMMAND_INJECTION | 0.99 | 遠端代碼執行 - 最高危險 |
| government_threats | 0.99 | 政府數據竊取 - 最高危險 |
| SQL_INJECTION | 0.95 | 數據庫攻擊 |
| healthcare_threats | 0.94 | 醫療數據洩露 |
| MALWARE | 0.90 | 惡意程式 |
| financial_threats | 0.92 | 金融信息竊取 |
| crypto_threats | 0.91 | 加密資產威脅 |
| APT_EXFILTRATION | 0.98 | APT 級別威脅 |
| PATH_TRAVERSAL | 0.80 | 路徑遍歷 |
| BRUTE_FORCE | 0.75 | 暴力破解 |
| XSS | 0.85 | 跨站指令碼 |
| UNKNOWN | 0.0 | 未知威脅 |

## 📈 使用示例

### 示例 1: 檢測金融欺詐

```python
system = EnhancedDefenseSystem()
system.train_ai_baseline(normal_data)

result = system.analyze_with_scoring(
    ip="192.168.0.50",
    payload="cc_number=4532-1488-0343-6467&amount=10000",
    traffic_features=np.array([500, 150])
)

if result['weighted_risk_score'] > 0.8:
    print("🚨 高風險金融欺詐檢測!")
    print(f"威脅類型: {result['threat_type']}")
    print(f"風險分數: {result['weighted_risk_score']:.2%}")
```

### 示例 2: 批量分析

```python
payloads = [
    "SELECT * FROM users",
    "GET /api/patient/12345",
    "<script>alert('XSS')</script>",
    "private_key: 0xaf...",
]

results = system.batch_analyze_with_scoring(payloads)

for i, result in enumerate(results):
    print(f"Payload {i+1}:")
    print(f"  威脅: {result['threat_type']}")
    print(f"  風險: {result['weighted_risk_score']:.2%}")
```

### 示例 3: 系統信息查詢

```python
# 打印系統信息
system.print_system_info()

# 獲取統計信息
stats = system.get_threat_statistics()
print(f"阻止率: {stats['block_rate']:.2f}%")
print(f"異常率: {stats['anomaly_rate']:.2f}%")
```

## 🔍 API 參考

### 主要方法

```python
# 初始化增強型系統
system = EnhancedDefenseSystem()

# 訓練模型
system.train_ai_baseline(normal_data: np.ndarray)

# 分析帶詳細評分
result = system.analyze_with_scoring(
    ip: str,
    payload: str,
    traffic_features: np.ndarray
) -> dict

# 批量分析
results = system.batch_analyze_with_scoring(
    payloads: list,
    ip: str = "127.0.0.1",
    traffic_features: np.ndarray = None
) -> list

# 添加自定義規則
system.add_custom_pattern(
    category: str,
    patterns: list
)

# 獲取統計信息
stats = system.get_threat_statistics() -> dict

# 打印系統信息
system.print_system_info()
```

### 分析結果結構

```python
{
    'ip': str,                    # 源 IP
    'action': str,                # 'blocked' 或 'allowed'
    'payload': str,               # 分析的有效負載
    'anomaly_score': float,       # AI 異常得分
    'threat_type': str,           # 檢測到的威脅類型
    'risk_score': float,          # 基礎風險分數
    'reason': str,                # 決定原因
    'severity': str,              # 嚴重程度等級
    'detailed_scores': {          # 詳細評分
        'base_risk': float,
        'payload_complexity': float,
        'feature_anomaly': float,
        'threat_severity': float
    },
    'weighted_risk_score': float, # 加權風險分數
    'risk_breakdown': dict        # 權重分解
}
```

## 💡 最佳實踐

### 1. 定期更新規則

```python
# 根據新發現的威脅添加規則
system.add_custom_pattern('new_threats', [
    r'new_malware_signature',
    r'new_exploit_pattern'
])
```

### 2. 監控性能

```python
stats = system.get_threat_statistics()

if stats['block_rate'] > 50:
    print("⚠️ 高阻止率 - 檢查誤報")

if stats['anomaly_rate'] > 10:
    print("⚠️ 高異常率 - 檢查系統狀態")
```

### 3. 調整權重

根據組織優先級調整評分權重（需修改 `analyze_with_scoring` 方法）：

```python
# 如果金融安全更重要
weights = {
    'base_risk': 0.5,         # 增加基礎風險權重
    'payload_complexity': 0.1,
    'feature_anomaly': 0.1,
    'threat_severity': 0.3    # 增加威脅嚴重程度
}
```

### 4. 集成到生產環境

```python
# 使用日誌記錄
import logging

logging.basicConfig(level=logging.INFO)
system = EnhancedDefenseSystem()

# 系統自動記錄所有活動
# 2026-03-14 09:26:55 - EnhancedDefenseSystem - INFO - ✅ 已載入特定行業威脅規則
```

## 🔧 配置和自定義

### 修改威脅嚴重程度

在 `_calculate_severity()` 方法中編輯 severity_map：

```python
def _calculate_severity(self, threat_type: str) -> float:
    severity_map = {
        'your_custom_threat': 0.99,
        # ... 其他威脅
    }
    return severity_map.get(threat_type, 0.5)
```

### 調整正規化參數

在 `analyze_with_scoring()` 方法中修改：

```python
'payload_complexity': min(len(payload) / 500, 1.0),  # 改為 500 而非 1000
'feature_anomaly': min(float(traffic_features.std()) / 50, 1.0),  # 改為 50
```

## 📊 測試和驗證

### 運行單元測試

```bash
# 運行增強型系統測試
pytest tests/test_enhanced_defense_system.py -v

# 운행 특정 測試
pytest tests/test_enhanced_defense_system.py::TestEnhancedAnalysis -v
```

### 運行演示

```bash
# 執行完整演示
python -m src.enhanced_defense_system
```

## 🐛 故障排除

### 問題 1: 加權風險分數總是 100%

**原因**: 流量特徵異常度過大

**解決方案**, 调整正規化系数:
```python
'feature_anomaly': min(float(traffic_features.std()) / 200, 1.0)
```

### 問題 2: 誤報率高

**原因**: 規則過於寬泛或權重不適當

**解決方案**:
- 改進規則的特異性
- 調整 `threat_severity` 映射
- 提供更多訓練數據

### 問題 3: 檢測率低

**原因**: 規則不夠全面或訓練數據不足

**解決方案**:
- 添加更多威脅規則
- 擴展訓練數據集
- 降低 contamination 參數

## 📚 相關文檔

- [RULE_DETECTION_GUIDE.md](RULE_DETECTION_GUIDE.md) - 規則檢測系統
- [MODEL_TUNING_GUIDE.md](MODEL_TUNING_GUIDE.md) - AI 模型調優
- [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) - 項目概覽

## 📝 版本信息

- **版本**: 1.0.0
- **發布日期**: 2026-03-14
- **基礎系統**: LurRenJiaDefenseSystem v1.0
- **Python**: 3.12.1+
- **依賴**: scikit-learn, numpy

## 🌟 主要改進點

vs 基礎系統:
- ✅ 行業特定威脅檢測
- ✅ 加權風險評分
- ✅ 詳細分析報告
- ✅ 日誌支持
- ✅ 批量分析
- ✅ 統計信息
- ✅ 可擴展的自定義規則系統

## 📞 支持

如需幫助或報告問題，請查看代碼中的註釋或提交 Issue。

---

**最後更新**: 2026-03-14
**版本**: 1.0.0
**維護者**: C45144lAI Defense System Team
