"""
Simple CSV Data Integration Example
簡單 CSV 數據整合示例

演示如何按照用户提供的代码片段进行操作
"""

import pandas as pd
import numpy as np
from src.defense_system import LurRenJiaDefenseSystem

# ===== 方法 1: 簡單整合 (按照用戶代碼) =====

print("=" * 80)
print("方法 1: 簡單 CSV 整合")
print("=" * 80)
print()

# 創建示例 CSV 文件 (如果沒有的話)
print("📝 創建示例流量數據...")
sample_data = pd.DataFrame({
    'packet_size': np.random.normal(50, 5, 100),
    'request_rate': np.random.normal(15, 3, 100),
    'source_ip': [f'192.168.1.{i}' for i in range(100)],
    'payload': ['GET /api/data'] * 100
})

sample_data.loc[10:15, 'payload'] = "'; DROP TABLE users; --"
sample_data.loc[20:25, 'payload'] = "<script>alert('XSS')</script>"

# 保存 CSV
csv_file = 'my_traffic_data.csv'
sample_data.to_csv(csv_file, index=False)
print(f"✅ 示例 CSV 已生成: {csv_file}")
print()

# 讀取 CSV 文件
print("📖 讀取 CSV 文件...")
data = pd.read_csv(csv_file)
print(f"✅ 成功讀取，行數: {len(data)}")
print()

# 提取特徵列（假設有 'packet_size' 和 'request_rate'）
print("🔧 提取特徵...")
features = data[['packet_size', 'request_rate']].values
print(f"✅ 特徵形狀: {features.shape}")
print(f"✅ 特徵範圍: [{features.min():.2f}, {features.max():.2f}]")
print()

# 訓練
print("🎯 訓練 AI 模型...")
system = LurRenJiaDefenseSystem()
system.train_ai_baseline(features)
print()

# ===== 方法 2: 分析 CSV 中的所有流量 =====

print("=" * 80)
print("方法 2: 分析 CSV 中的流量")
print("=" * 80)
print()

# 分析每一行
print("🔍 分析流量數據...")
blocked_count = 0
allowed_count = 0
threat_distribution = {}

for idx, row in data.iterrows():
    ip = str(row.get('source_ip', 'UNKNOWN'))
    payload = str(row.get('payload', ''))
    packet_size = float(row.get('packet_size', 50))
    request_rate = float(row.get('request_rate', 15))
    
    # 分析
    result = system.analyze_incoming_traffic(
        ip,
        payload,
        np.array([packet_size, request_rate])
    )
    
    # 統計
    if result['action'] == 'blocked':
        blocked_count += 1
    else:
        allowed_count += 1
    
    threat_type = result['threat_type']
    threat_distribution[threat_type] = threat_distribution.get(threat_type, 0) + 1

print(f"✅ 分析完成")
print()

# 顯示結果
print("=" * 80)
print("📊 分析結果摘要")
print("=" * 80)
print()

total = len(data)
print(f"📈 總流量: {total}")
print(f"✔️  允許: {allowed_count}")
print(f"🚫 阻止: {blocked_count}")
print(f"🛡️  防禦率: {blocked_count/total*100:.1f}%")
print()

print("⚠️  威脅類型分布:")
for threat_type, count in sorted(threat_distribution.items(), key=lambda x: x[1], reverse=True):
    bar = "█" * count + "░" * (15 - count)
    print(f"  {threat_type:20s} {bar} ({count})")
print()

# ===== 方法 3: 使用系統統計 =====

print("=" * 80)
print("方法 3: 系統統計信息")
print("=" * 80)
print()

stats = system.get_statistics()
print(f"📊 系統統計:")
print(f"  總請求: {stats['total_requests']}")
print(f"  被阻止: {stats['blocked_requests']}")
print(f"  允許: {stats['allowed_requests']}")
print(f"  阻止率: {stats['block_rate']:.1%}")
print()

# ===== 方法 4: 導出分析結果 =====

print("=" * 80)
print("方法 4: 導出分析結果")
print("=" * 80)
print()

# 再次分析並保存詳細結果
print("📝 詳細分析和導出...")
analysis_results = []

for idx, row in data.iterrows():
    ip = str(row.get('source_ip', 'UNKNOWN'))
    payload = str(row.get('payload', ''))
    packet_size = float(row.get('packet_size', 50))
    request_rate = float(row.get('request_rate', 15))
    
    result = system.analyze_incoming_traffic(
        ip,
        payload,
        np.array([packet_size, request_rate])
    )
    
    analysis_results.append({
        'source_ip': ip,
        'payload': payload[:100],
        'packet_size': packet_size,
        'request_rate': request_rate,
        'action': result['action'],
        'threat_type': result['threat_type'],
        'risk_score': result['risk_score'],
        'severity': result['severity']
    })

# 轉換為 DataFrame 並保存
results_df = pd.DataFrame(analysis_results)
output_file = 'traffic_analysis_results.csv'
results_df.to_csv(output_file, index=False, encoding='utf-8')

print(f"✅ 分析結果已導出: {output_file}")
print()

# 顯示結果預覽
print("📋 結果預覽 (前 10 行):")
print(results_df.head(10).to_string(index=False))
print()

# ===== 方法 5: 查詢高危事件 =====

print("=" * 80)
print("方法 5: 查詢高危事件")
print("=" * 80)
print()

high_risk = results_df[results_df['risk_score'] > 0.8]
print(f"🚨 高危事件: {len(high_risk)} 個")
print()

for idx, row in high_risk.iterrows():
    print(f"事件 #{idx+1}:")
    print(f"  🌐 IP: {row['source_ip']}")
    print(f"  ⚠️  威脅: {row['threat_type']}")
    print(f"  📊 風險: {row['risk_score']:.1%}")
    print(f"  🔴 嚴重性: {row['severity']}")
    print()

print("=" * 80)
print("✅ 演示完成")
print("=" * 80)
print()

print("💡 使用提示:")
print("  1. 準備您的 CSV 文件，包含 'packet_size' 和 'request_rate' 列")
print("  2. 使用 pd.read_csv() 讀取 CSV 文件")
print("  3. 提取特徵: data[['packet_size', 'request_rate']].values")
print("  4. 訓練系統: system.train_ai_baseline(features)")
print("  5. 分析流量: system.analyze_incoming_traffic(ip, payload, features)")
print("  6. 導出結果: pd.DataFrame(results).to_csv('output.csv')")
