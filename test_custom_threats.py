#!/usr/bin/env python3
"""
Test script for custom threat pattern functionality
演示自定義威脅模式功能
"""

import numpy as np
import re
from src.defense_system import LurRenJiaDefenseSystem

def test_default_threat_patterns():
    """Test that default threat patterns are initialized"""
    print("\n" + "="*80)
    print("📊 Test 1: Default Threat Patterns Initialization")
    print("="*80)
    
    system = LurRenJiaDefenseSystem()
    
    # Check that threat patterns are initialized
    print(f"✅ 威脅模式已初始化")
    print(f"📋 預設威脅模式數量: {len(system.threat_patterns)}")
    
    for threat_name, patterns in system.threat_patterns.items():
        print(f"   • {threat_name}: {len(patterns)} 個正則表達式")
    
    return system


def test_custom_threat_patterns(system):
    """Test adding custom threat patterns"""
    print("\n" + "="*80)
    print("📊 Test 2: Adding Custom Threat Patterns")
    print("="*80)
    
    # Add custom threat pattern
    custom_patterns = [
        r"(?i)(custom_malware|special_backdoor)",
        r"(?i)(exploit_kit|zero_day)",
        r"(?i)(ransomware_variant_[0-9]+)",
    ]
    
    system.add_custom_threat('CUSTOM_THREAT', custom_patterns)
    print(f"✅ 自定義威脅已添加: CUSTOM_THREAT")
    print(f"   📊 模式數量: 3")
    
    # Add another custom threat
    system.add_custom_threat('INSIDER_THREAT', [
        r"(?i)(export_confidential|leak_source_code)",
        r"(?i)(unauthorized_access|privilege_escalation)",
    ])
    print(f"✅ 自定義威脅已添加: INSIDER_THREAT")
    print(f"   📊 模式數量: 2")


def test_pattern_matching():
    """Test that patterns can match payloads"""
    print("\n" + "="*80)
    print("📊 Test 3: Pattern Matching Verification")
    print("="*80)
    
    system = LurRenJiaDefenseSystem()
    
    test_cases = [
        {
            'payload': "' DROP TABLE users; --",
            'threat_type': 'SQL_INJECTION',
            'expected': True
        },
        {
            'payload': "<script>alert('XSS')</script>",
            'threat_type': 'XSS',
            'expected': True
        },
        {
            'payload': "cat /etc/passwd",
            'threat_type': 'COMMAND_INJECTION',
            'expected': True
        },
        {
            'payload': "normal GET request",
            'threat_type': 'SQL_INJECTION',
            'expected': False
        },
    ]
    
    for test_case in test_cases:
        payload = test_case['payload']
        threat_type = test_case['threat_type']
        expected = test_case['expected']
        
        if threat_type in system.threat_patterns:
            patterns = system.threat_patterns[threat_type]
            matched = any(re.search(pattern, payload) for pattern in patterns)
            
            status = "✅" if matched == expected else "❌"
            result = "matched" if matched else "not matched"
            print(f"{status} {threat_type}: '{payload[:40]}...' {result}")
        else:
            print(f"⚠️  Threat type not found: {threat_type}")


def test_pattern_retrieval():
    """Test retrieving threat patterns"""
    print("\n" + "="*80)
    print("📊 Test 4: Pattern Retrieval")
    print("="*80)
    
    system = LurRenJiaDefenseSystem()
    
    # Add a few custom threats
    system.add_custom_threat('TEST_THREAT_1', [r'pattern1', r'pattern2'])
    system.add_custom_threat('TEST_THREAT_2', [r'pattern3'])
    
    # Get all patterns
    all_patterns = system.get_threat_patterns()
    
    print(f"✅ 已檢索所有威脅模式")
    print(f"📋 總威脅類型: {len(all_patterns)}")
    
    threat_counts = {name: len(patterns) for name, patterns in all_patterns.items()}
    
    for threat_name in sorted(threat_counts.keys()):
        print(f"   • {threat_name}: {threat_counts[threat_name]} 個模式")


def test_analysis_with_custom_threats():
    """Test that analysis still works with custom threats initialized"""
    print("\n" + "="*80)
    print("📊 Test 5: System Analysis with Custom Threats")
    print("="*80)
    
    system = LurRenJiaDefenseSystem()
    
    # Add custom threat
    system.add_custom_threat('CRYPTO_MINER', [
        r"(?i)(monero|ethash|cryptonight)",
        r"(?i)(stratum\+tcp|mining\.pool)",
    ])
    
    # Train the system
    normal_traffic = np.random.randn(50, 5)
    system.train_ai_baseline(normal_traffic)
    
    # Test various traffic
    test_cases = [
        ("192.168.1.100", "normal request", [1, 1, 1, 1, 1]),
        ("192.168.1.101", "' OR '1'='1", [5, 5, 5, 5, 5]),
        ("192.168.1.102", "<script>alert('xss')</script>", [5, 5, 5, 5, 5]),
    ]
    
    print(f"✅ 系統已訓練用新威脅模式")
    print(f"📊 分析 {len(test_cases)} 個流量樣本...\n")
    
    for ip, payload, features in test_cases:
        result = system.analyze_incoming_traffic(ip, payload, np.array(features))
        
        status_icon = "🚫" if result['action'] == 'blocked' else "✅"
        print(f"{status_icon} 決策: {result['action'].upper()}")
        print(f"   • 威脅: {result['threat_type']}")
        print(f"   • 風險: {result['risk_score']:.2f}")
        print(f"   • 理由: {result['reason']}")
        print()


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("🔐 C45144lAI 自定義威脅模式測試套件")
    print("="*80)
    
    # Test 1: Default patterns
    system = test_default_threat_patterns()
    
    # Test 2: Adding custom patterns
    test_custom_threat_patterns(system)
    
    # Test 3: Pattern matching
    test_pattern_matching()
    
    # Test 4: Pattern retrieval
    test_pattern_retrieval()
    
    # Test 5: Analysis with custom threats
    test_analysis_with_custom_threats()
    
    print("\n" + "="*80)
    print("✅ 所有自定義威脅模式測試完成！")
    print("="*80 + "\n")


if __name__ == '__main__':
    main()
