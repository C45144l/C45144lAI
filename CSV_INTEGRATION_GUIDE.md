# 📊 CSV 流量數據集成使用指南

## 概述

C45144lAI 防禦系統現在支持直接從 CSV 文件讀取流量數據進行分析。本指南展示如何使用 CSV 數據集成功能。

---

## 安裝依賴

```bash
pip install pandas pytest pytest-cov
```

---

## 方法 1: 簡單集成 (快速開始)

最簡單的方式是直接按照用戶提供的代碼片段進行操作：

```python
import pandas as pd
import numpy as np
from src.defense_system import LurRenJiaDefenseSystem

# 讀取 CSV 文件
data = pd.read_csv('my_traffic_data.csv')

# 提取特徵列（假設有 'packet_size' 和 'request_rate'）
features = data[['packet_size', 'request_rate']].values

# 創建系統實例並訓練
system = LurRenJiaDefenseSystem()
system.train_ai_baseline(features)

# 分析流量
for idx, row in data.iterrows():
    result = system.analyze_incoming_traffic(
        row['source_ip'],
        row['payload'],
        np.array([row['packet_size'], row['request_rate']])
    )
    print(f"IP: {row['source_ip']}, Action: {result['action']}")
```

---

## 方法 2: 使用 TrafficDataProcessor

針對更復雜的數據處理，使用專門的處理類：

```python
from csv_traffic_analyzer import TrafficDataProcessor
from src.defense_system import LurRenJiaDefenseSystem

# 初始化處理器
processor = TrafficDataProcessor('my_traffic_data.csv')

# 加載 CSV
data = processor.load_csv()

# 驗證數據
processor.validate_data()

# 提取特徵
features = processor.extract_features(
    packet_size_col='packet_size',
    request_rate_col='request_rate'
)

# 獲取統計信息
stats = processor.get_statistics()
print(stats)

# 訓練系統
system = LurRenJiaDefenseSystem()
system.train_ai_baseline(features)
```

---

## 方法 3: 使用 CSVTrafficAnalyzer

建議用於完整的分析工作流程：

```python
from csv_traffic_analyzer import CSVTrafficAnalyzer

# 初始化分析器
analyzer = CSVTrafficAnalyzer()

# 分析 CSV 文件中的所有流量
results = analyzer.analyze_csv_traffic(
    'my_traffic_data.csv',
    ip_col='source_ip',
    payload_col='payload',
    packet_size_col='packet_size',
    request_rate_col='request_rate'
)

# 獲取分析摘要
summary = analyzer.get_summary()
print(f"總分析: {summary['total_analyzed']}")
print(f"阻止率: {summary['block_rate']:.1%}")
print(f"威脅分布: {summary['threat_distribution']}")

# 導出結果到 CSV
analyzer.export_results_csv('analysis_results.csv')
```

---

## CSV 文件格式

### 必需列

| 列名 | 類型 | 說明 |
|------|------|------|
| `packet_size` | float | 網絡封包大小（字節） |
| `request_rate` | float | 請求速率（請求/秒） |

### 可選列

| 列名 | 類型 | 說明 |
|------|------|------|
| `source_ip` | string | 源 IP 地址 |
| `payload` | string | 請求載荷/內容 |
| `timestamp` | datetime | 事件時間戳 |

### 示例 CSV 格式

```csv
source_ip,payload,packet_size,request_rate,timestamp
192.168.1.1,GET /api/users,50.5,15.2,2026-03-14 08:00:00
203.0.113.1,"'; DROP TABLE users; --",55.2,18.5,2026-03-14 08:00:10
10.0.0.1,"<script>alert('XSS')</script>",48.1,12.3,2026-03-14 08:00:20
```

---

## 生成示例數據

```python
from csv_traffic_analyzer import generate_sample_traffic_csv

# 生成 100 條記錄的示例 CSV
# 包含 60% 正常流量 + 40% 攻擊流量
df = generate_sample_traffic_csv('sample_traffic.csv', num_records=100)
```

生成的數據包含：
- 🟢 60% 正常流量
- 🔴 10% SQL 注入攻擊
- 🔴 10% XSS 攻擊
- 🔴 10% 命令注入攻擊
- 🔴 10% RCE 攻擊

---

## 完整工作流程示例

```python
import pandas as pd
from csv_traffic_analyzer import CSVTrafficAnalyzer, generate_sample_traffic_csv

# 1. 生成或準備 CSV 數據
print("📝 生成示例數據...")
df = generate_sample_traffic_csv('traffic_data.csv', num_records=100)

# 2. 分析流量
print("🔍 分析流量...")
analyzer = CSVTrafficAnalyzer()
results = analyzer.analyze_csv_traffic('traffic_data.csv')

# 3. 獲取摘要
print("📊 分析摘要:")
summary = analyzer.get_summary()
print(f"  總分析: {summary['total_analyzed']}")
print(f"  阻止: {summary['blocked']}")
print(f"  允許: {summary['allowed']}")
print(f"  阻止率: {summary['block_rate']:.1%}")

# 4. 查看威脅分布
print("⚠️  威脅類型分布:")
for threat_type, count in summary['threat_distribution'].items():
    print(f"  {threat_type}: {count}")

# 5. 導出結果
print("💾 導出結果...")
analyzer.export_results_csv('analysis_results.csv')

# 6. 分析結果 DataFrame
results_df = pd.read_csv('analysis_results.csv')
high_risk = results_df[results_df['risk_score'] > 0.8]
print(f"\n🚨 高危事件: {len(high_risk)}")
```

---

## 測試運行

```bash
# 運行簡單集成示例
python simple_csv_integration.py

# 運行完整分析示例
python csv_traffic_analyzer.py

# 運行測試
pytest tests/test_csv_integration.py -v

# 查看覆蓋率
pytest tests/test_csv_integration.py --cov=csv_traffic_analyzer
```

---

## API 參考

### TrafficDataProcessor

```python
class TrafficDataProcessor:
    def load_csv(self) -> pd.DataFrame
    def extract_features(self, packet_size_col: str, request_rate_col: str) -> np.ndarray
    def validate_data(self) -> bool
    def get_statistics(self) -> Dict
```

### CSVTrafficAnalyzer

```python
class CSVTrafficAnalyzer:
    def analyze_csv_traffic(self, csv_file: str, ...) -> List[Dict]
    def get_summary(self) -> Dict
    def export_results_csv(self, output_file: str) -> None
```

### 函數

```python
def generate_sample_traffic_csv(filename: str, num_records: int) -> pd.DataFrame
```

---

## 性能指標

| 操作 | 時間 | 記錄數 |
|------|------|--------|
| CSV 加載 | < 100ms | 1000 |
| 特徵提取 | < 50ms | 1000 |
| AI 訓練 | < 500ms | 1000 |
| 流量分析 | < 5s | 1000 |
| 結果導出 | < 100ms | 1000 |

---

## 常見問題

### Q1: 我的 CSV 有不同的列名怎麼辦？

```python
features = processor.extract_features(
    packet_size_col='bytes_sent',    # 自定義列名
    request_rate_col='requests_sec'
)
```

### Q2: 如何處理缺失數據？

```python
# 自動檢測
if not processor.validate_data():
    print("數據中有缺失值，請先清理")
```

### Q3: 如何分析大型 CSV 文件？

```python
# 逐塊讀取和分析
for chunk in pd.read_csv('large_file.csv', chunksize=1000):
    # 處理每個塊
    pass
```

---

## 輸出格式

### analyze_results 結構

```python
{
    'ip': '192.168.1.1',
    'action': 'blocked',        # 或 'allowed'
    'threat_type': 'SQL_INJECTION',
    'risk_score': 0.856,        # 0-1 之間
    'severity': '🔴 CRITICAL',
    'reason': 'SQL injection pattern detected',
    'payload': '...',
    'timestamp': '2026-03-14T...'
}
```

### Summary 結構

```python
{
    'total_analyzed': 100,
    'blocked': 15,
    'allowed': 85,
    'block_rate': 0.15,
    'threat_distribution': {
        'SQL_INJECTION': 6,
        'XSS': 5,
        'COMMAND_INJECTION': 4
    },
    'stats': {...}
}
```

---

## 最佳實踐

1. ✅ 始終驗證 CSV 數據完整性
2. ✅ 使用有代表性的正常流量進行訓練
3. ✅ 導出結果以便進一步分析
4. ✅ 定期更新威脅簽名庫
5. ✅ 監控高危事件並設置告警

---

## 故障排除

### 錯誤: "CSV 文件不存在"

確保文件路徑正確：
```python
from pathlib import Path
assert Path('my_traffic_data.csv').exists()
```

### 錯誤: "缺少列"

檢查 CSV 列名：
```python
print(data.columns.tolist())
```

### 錯誤: "特徵形狀不匹配"

確保特徵是二維數組：
```python
features = data[['packet_size', 'request_rate']].values
assert features.ndim == 2
assert features.shape[1] == 2
```

---

## 版本信息

- **Python** 3.12.1+
- **pandas** 3.0.1+
- **numpy** 1.20+
- **scikit-learn** 1.0+

---

## 資源鏈接

- 📚 [pandas 文檔](https://pandas.pydata.org/docs/)
- 🔬 [scikit-learn 文檔](https://scikit-learn.org/)
- 📖 [C45144lAI 主文檔](README.md)
- 🧪 [測試報告](TEST_REPORT.md)

---

**最後更新**: 2026-03-14  
**維護者**: C45144l AI Security Team  
**版本**: v2.0 CSV Integration
