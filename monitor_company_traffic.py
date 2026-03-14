"""
場景: 實時監控公司員工的網路流量
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np

# 初始化
system = LurRenJiaDefenseSystem()

# 訓練（使用公司正常流量）
print("📚 正在分析公司正常流量模式...")
normal_company_traffic = np.random.randn(5000, 2) * 8 + 45
system.train_ai_baseline(normal_company_traffic)
print("✅ 訓練完成\n")

# 真實流量監控
company_requests = [
    ("192.168.1.101", "GET /company-intranet", [45, 10]),
    ("192.168.1.102", "POST /api/data", [48, 15]),
    ("192.168.1.103", "GET /admin?user=1' OR '1'='1", [50, 12]),  # ⚠️ SQL 注入！
    ("203.0.113.50", "GET /malware.exe", [1000, 2000]),  # ⚠️ 異常行為！
]

print("🔍 開始監控公司網路...\n")
for ip, payload, features in company_requests:
    result = system.analyze_incoming_traffic(
        ip,
        payload,
        np.array(features)
    )
    
    status = "🟢" if result['action'] == 'allowed' else "🔴"
    print(f"{status} [{ip}] {result['action'].upper()}")
    print(f"   威脅: {result['threat_type']} | 風險: {result['risk_score']:.1%}")
    print(f"   原因: {result['reason']}\n")

# 生成日報
stats = system.get_statistics()
print("=" * 60)
print("📊 今日監控報告")
print("=" * 60)
print(f"掃描流量: {stats['total_requests']} 個")
print(f"攔截威脅: {stats['blocked_requests']} 個")
print(f"防禦成功率: {stats['block_rate']:.1%}")
print(f"AI 偵測異常: {stats['anomalies_detected']} 個")
