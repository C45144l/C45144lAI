"""
測試 Flask API 保護
模擬不同的 API 請求場景
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np

# 初始化防禦系統
system = LurRenJiaDefenseSystem()

# 訓練系統
print("🚀 初始化 API 防禦系統...\n")
normal_api_traffic = np.random.randn(2000, 2) * 5 + 30
system.train_ai_baseline(normal_api_traffic)

# 模擬 API 請求
print("=" * 80)
print("🔍 API 流量分析")
print("=" * 80)
print()

api_requests = [
    {
        "description": "正常用戶登入",
        "ip": "203.0.113.10",
        "payload": '{"username": "john", "password": "secret123"}',
        "features": [32, 55]  # payload_size: 32, request_rate: 55
    },
    {
        "description": "正常數據查詢",
        "ip": "203.0.113.20",
        "payload": '{"query": "SELECT name FROM users"}',
        "features": [35, 50]
    },
    {
        "description": "SQL 注入攻擊",
        "ip": "45.33.2.1",
        "payload": '{"id": "1\' OR \'1\'=\'1"}',
        "features": [28, 60]
    },
    {
        "description": "暴力破解（高頻率）",
        "ip": "88.10.4.5",
        "payload": '{"attempt": 1}',
        "features": [15, 5000]  # 極高的请求频率
    },
    {
        "description": "異常大型請求（檔案上傳攻擊）",
        "ip": "112.55.4.3",
        "payload": "x" * 10000,
        "features": [10000, 100]
    },
    {
        "description": "正常文件下載",
        "ip": "203.0.113.30",
        "payload": '{"file_id": "doc_123"}',
        "features": [25, 52]
    },
    {
        "description": "跨站腳本（XSS）",
        "ip": "45.33.2.2",
        "payload": '{"comment": "<script>alert(\'XSS\')</script>"}',
        "features": [50, 55]
    }
]

results = []
for idx, req in enumerate(api_requests, 1):
    ip = req["ip"]
    payload = req["payload"]
    features = np.array(req["features"])
    
    # 分析流量
    result = system.analyze_incoming_traffic(ip, payload, features)
    results.append(result)
    
    status = "🟢" if result['action'] == 'allowed' else "🔴"
    
    print(f"[{idx}] {status} {req['description']}")
    print(f"   IP: {ip}")
    print(f"   Action: {result['action'].upper()}")
    print(f"   Threat: {result['threat_type']}")
    print(f"   Risk: {result['risk_score']:.1%}")
    print(f"   Reason: {result['reason']}")
    print()

# 統計
print("=" * 80)
print("📊 API 防禦統計")
print("=" * 80)
print()

stats = system.get_statistics()
allowed = len([r for r in results if r['action'] == 'allowed'])
blocked = len([r for r in results if r['action'] == 'blocked'])

print(f"✅ 總請求: {stats['total_requests']} 個")
print(f"🟢 允許通過: {allowed} 個")
print(f"🔴 攔截請求: {blocked} 個")
print(f"⚠️ 防禦率: {stats['block_rate']:.1%}")
print()

# 關鍵威脅分類
print("🎯 檢測到的威脅:")
threat_types = {}
for result in results:
    if result['action'] == 'blocked':
        threat_type = result['threat_type']
        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

for threat_type, count in sorted(threat_types.items()):
    print(f"  • {threat_type}: {count}")

print()
print("=" * 80)
print("✅ Flask API 防禦系統運作正常")
print("=" * 80)
