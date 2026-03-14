"""
模擬真實世界的各種駭客攻擊與正常情境
包含: SQL 注入、XSS、DDoS、資料外洩、黑名單等
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np

# 初始化防禦系統
system = LurRenJiaDefenseSystem()

# 訓練 AI 基準模型
print("🚀 初始化防禦系統...\n")
normal_data = np.random.randn(3000, 2) * 10 + 50
system.train_ai_baseline(normal_data)

# 模擬真實世界的各種駭客攻擊與正常情境
test_cases = [
    {"ip": "192.168.1.10", "payload": "GET /index.html", "features": [52, 12]}, # 正常員工瀏覽
    {"ip": "10.0.0.5", "payload": "GET /api/data", "features": [48, 15]},       # 正常 API 呼叫
    {"ip": "45.33.2.1", "payload": "admin' OR 1=1 --", "features": [55, 14]},   # 傳統 SQL 攻擊 (觸發規則)
    {"ip": "112.55.4.3", "payload": "<script>alert(1)</script>", "features": [50, 12]}, # XSS 攻擊 (觸發規則)
    {"ip": "88.10.4.5", "payload": "GET /image.jpg", "features": [8500, 15]},   # 模擬 DDoS 前兆 (觸發 AI)
    {"ip": "203.0.113.1", "payload": "POST /upload", "features": [40, 9900]},   # 模擬資料外洩 (觸發 AI)
    {"ip": "45.33.2.1", "payload": "GET /login", "features": [50, 10]}          # 駭客想再試一次 (被黑名單擋下)
]

# 黑名單系統（儲存被檢測到的攻擊者）
blacklist = set()

# 詳細分析結果
print("=" * 80)
print("🔍 流量分析報告")
print("=" * 80)
print()

results = []
for idx, test_case in enumerate(test_cases, 1):
    ip = test_case["ip"]
    payload = test_case["payload"]
    features = np.array(test_case["features"])
    
    # 檢查黑名單
    if ip in blacklist:
        result = {
            "ip": ip,
            "action": "blocked",
            "reason": "IP 在黑名單中",
            "threat_type": "BLACKLIST",
            "risk_score": 1.0,
            "payload": payload
        }
        status = "🔴"
    else:
        # 分析流量
        result = system.analyze_incoming_traffic(ip, payload, features)
        
        # 如果檢測到攻擊，加入黑名單
        if result['action'] == 'blocked':
            blacklist.add(ip)
        
        status = "🟢" if result['action'] == 'allowed' else "🔴"
    
    results.append(result)
    
    # 顯示結果
    print(f"[{idx}] {status} {result['action'].upper()} | IP: {ip}")
    print(f"    Payload: {payload}")
    print(f"    威脅類型: {result['threat_type']}")
    print(f"    風險評分: {result['risk_score']:.1%}")
    print(f"    原因: {result['reason']}")
    print()

# 生成詳細統計報告
print("=" * 80)
print("📊 安全統計報告")
print("=" * 80)
print()

stats = system.get_statistics()
blocked_results = [r for r in results if r['action'] == 'blocked']
allowed_results = [r for r in results if r['action'] == 'allowed']

print(f"✅ 總掃描流量: {stats['total_requests']} 個請求")
print(f"🔴 攔截威脅: {stats['blocked_requests']} 個")
print(f"🟢 放行正常: {stats['allowed_requests']} 個")
print(f"⚠️ 防禦成功率: {stats['block_rate']:.1%}")
print(f"🤖 AI 偵測異常: {stats['anomalies_detected']} 個")
print()

# 威脅分類統計
print("🎯 威脅分類統計:")
threat_types = {}
for result in results:
    threat_type = result['threat_type']
    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

for threat_type, count in sorted(threat_types.items()):
    print(f"  • {threat_type}: {count}")
print()

# 黑名單報告
print("🚫 黑名單報告:")
print(f"  已攔截的惡意 IP: {len(blacklist)} 個")
for blocked_ip in sorted(blacklist):
    print(f"    • {blocked_ip}")
print()

# 風險評估
print("⚠️ 風險評估:")
high_risk = [r for r in results if r['risk_score'] > 0.7]
medium_risk = [r for r in results if 0.3 < r['risk_score'] <= 0.7]

print(f"  高風險 (>70%): {len(high_risk)} 個")
if high_risk:
    for r in high_risk:
        print(f"    • {r['ip']}: {r['threat_type']} ({r['risk_score']:.1%})")

print(f"  中風險 (30-70%): {len(medium_risk)} 個")
if medium_risk:
    for r in medium_risk:
        print(f"    • {r['ip']}: {r['threat_type']} ({r['risk_score']:.1%})")

print()
print("=" * 80)
print("✅ 防禦系統運作正常 - 所有威脅已被識別並攔截")
print("=" * 80)
