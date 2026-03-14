"""
增強型防禦系統 - 行業特定威脅檢測
Enhanced Defense System with Industry-Specific Threat Detection
"""

import numpy as np
import logging
from src.defense_system import LurRenJiaDefenseSystem


class EnhancedDefenseSystem(LurRenJiaDefenseSystem):
    """增強型防禦系統 - 添加自定義規則與行業特定威脅檢測"""
    
    def __init__(self, *args, **kwargs):
        """初始化增強型防禦系統"""
        super().__init__(*args, **kwargs)
        self._add_industry_specific_rules()
    
    def _add_industry_specific_rules(self):
        """添加特定行業的威脅規則"""
        
        # 金融行業特定威脅
        self.threat_patterns['financial_threats'] = [
            r'credit_card',
            r'bank_account',
            r'routing_number',
            r'swift_code',
            r'iban',
            r'account_number',
        ]
        
        # 醫療行業特定威脅
        self.threat_patterns['healthcare_threats'] = [
            r'patient_id',
            r'medical_record',
            r'prescription',
            r'hipaa',
            r'protected_health',
            r'diagnosis',
        ]
        
        # 政府機構特定威脅
        self.threat_patterns['government_threats'] = [
            r'classified',
            r'top_secret',
            r'ssn',  # 社會安全號
            r'passport',
            r'national_id',
            r'confidential',
        ]
        
        # 加密貨幣交易所特定威脅
        self.threat_patterns['crypto_threats'] = [
            r'private_key',
            r'seed_phrase',
            r'wallet_address',
            r'cryptocurrency',
            r'bitcoin',
            r'ethereum',
            r'mnemonic',
        ]
        
        self.logger.info("✅ 已載入特定行業威脅規則 (4 個行業特定威脅類別)")
    
    def add_custom_pattern(self, category: str, patterns: list):
        """
        動態添加自定義威脅模式
        
        Args:
            category: 威脅類別名稱
            patterns: 正則表達式模式列表
        """
        if category not in self.threat_patterns:
            self.threat_patterns[category] = []
        
        # 確保是列表
        if isinstance(patterns, str):
            patterns = [patterns]
        
        self.threat_patterns[category].extend(patterns)
        self.logger.info(f"✅ 已添加 {len(patterns)} 個 '{category}' 規則 (總計: {len(self.threat_patterns[category])} 個)")
    
    def analyze_with_scoring(self, ip: str, payload: str, traffic_features: np.ndarray):
        """
        增強版分析 - 返回詳細評分
        
        Args:
            ip: 來源 IP 地址
            payload: 請求有效負載
            traffic_features: 流量特徵 [size, latency]
        
        Returns:
            包含詳細評分的分析結果
        """
        # 執行標準分析
        result = self.analyze_incoming_traffic(ip, payload, traffic_features)
        
        # 驗證輸入
        if isinstance(traffic_features, list):
            traffic_features = np.array(traffic_features)
        
        # 計算詳細評分
        detailed_score = {
            'base_risk': float(result['risk_score']),
            'payload_complexity': min(len(payload) / 1000, 1.0),  # 正規化到 0-1
            'feature_anomaly': min(float(traffic_features.std()) / 100, 1.0) if len(traffic_features) > 0 else 0.0,  # 正規化
            'threat_severity': self._calculate_severity(result['threat_type'])
        }
        
        # 加權計算風險
        weights = {
            'base_risk': 0.4,
            'payload_complexity': 0.2,
            'feature_anomaly': 0.2,
            'threat_severity': 0.2
        }
        
        weighted_risk = sum(
            detailed_score[key] * weights[key]
            for key in detailed_score.keys()
        )
        
        result['detailed_scores'] = detailed_score
        result['weighted_risk_score'] = min(weighted_risk, 1.0)
        result['risk_breakdown'] = weights
        
        return result
    
    def _calculate_severity(self, threat_type: str) -> float:
        """
        根據威脅類型計算嚴重程度
        
        Args:
            threat_type: 威脅類型
        
        Returns:
            嚴重程度分數 (0-1)
        """
        severity_map = {
            'SQL_INJECTION': 0.95,
            'XSS': 0.85,
            'COMMAND_INJECTION': 0.99,
            'PATH_TRAVERSAL': 0.80,
            'MALWARE': 0.90,
            'APT_EXFILTRATION': 0.98,
            'BRUTE_FORCE': 0.75,
            'financial_threats': 0.92,
            'healthcare_threats': 0.94,
            'government_threats': 0.99,
            'crypto_threats': 0.91,
            'UNKNOWN': 0.0,
            'NO_THREAT': 0.0
        }
        return severity_map.get(threat_type, 0.5)
    
    def batch_analyze_with_scoring(self, payloads: list, ip: str = "127.0.0.1", 
                                   traffic_features: np.ndarray = None):
        """
        批量分析帶詳細評分
        
        Args:
            payloads: 有效負載列表
            ip: 來源 IP 地址
            traffic_features: 流量特徵 (如果為 None，將生成隨機特徵)
        
        Returns:
            分析結果列表
        """
        results = []
        
        for payload in payloads:
            # 如果未提供流量特徵，生成默認特徵
            if traffic_features is None:
                features = np.array([100, 50])
            else:
                features = traffic_features
            
            result = self.analyze_with_scoring(ip, payload, features)
            results.append(result)
        
        return results
    
    def get_threat_statistics(self):
        """獲取威脅統計信息"""
        stats = self.statistics.copy()
        stats['threat_categories'] = list(self.threat_patterns.keys())
        stats['total_patterns'] = sum(
            len(patterns) if isinstance(patterns, list) else 1
            for patterns in self.threat_patterns.values()
        )
        
        if stats['total_requests'] > 0:
            stats['block_rate'] = (stats['blocked_requests'] / stats['total_requests']) * 100
            stats['anomaly_rate'] = (stats['anomalies_detected'] / stats['total_requests']) * 100
        
        return stats
    
    def print_system_info(self):
        """打印系統信息"""
        print("\n" + "="*60)
        print("🔐 增強型防禦系統信息")
        print("="*60)
        print(f"類名: {self.__class__.__name__}")
        print(f"基類: {self.__class__.__bases__[0].__name__}")
        print(f"\n📊 威脅檢測:")
        print(f"  - 行業特定威脅類別: {len(self.threat_patterns)}")
        
        for category, patterns in self.threat_patterns.items():
            pattern_count = len(patterns) if isinstance(patterns, list) else 1
            print(f"    • {category}: {pattern_count} 個規則")
        
        stats = self.get_threat_statistics()
        print(f"\n📈 統計信息:")
        print(f"  - 總請求數: {stats['total_requests']}")
        print(f"  - 已阻止: {stats['blocked_requests']}")
        print(f"  - 已允許: {stats['allowed_requests']}")
        print(f"  - 異常檢測: {stats['anomalies_detected']}")
        
        if stats['total_requests'] > 0:
            print(f"  - 阻止率: {stats['block_rate']:.2f}%")
            print(f"  - 異常率: {stats['anomaly_rate']:.2f}%")
        
        print(f"\n🤖 AI 模型:")
        print(f"  - 已訓練: {'是' if self.trained else '否'}")
        print(f"  - Contamination: {self.model.contamination}")
        print("="*60 + "\n")


def demonstrate_enhanced_system():
    """演示增強型防禦系統的使用"""
    from datetime import datetime
    
    print(f"\n🚀 [${datetime.now().strftime('%H:%M:%S')}] 啟動增強型防禦系統演示\n")
    
    # 初始化系統
    system = EnhancedDefenseSystem()
    
    # 添加自定義規則
    system.add_custom_pattern('internal_threats', [
        r'confidential_data',
        r'employee_records',
        r'business_strategy',
        r'proprietary_algorithm'
    ])
    
    # 訓練系統
    print("📚 訓練 AI 模型...")
    normal_data = np.random.randn(1000, 2) * 10 + 50
    system.train_ai_baseline(normal_data)
    print("✅ AI 模型訓練完成\n")
    
    # 打印系統信息
    system.print_system_info()
    
    # 執行分析
    print("🔍 執行威脅分析...")
    print("-" * 60)
    
    test_cases = [
        ("192.168.1.100", "SELECT confidential_data FROM employees", [52, 12], "SQL + 內部威脅"),
        ("192.168.1.101", "GET /admin/credit_card_list", [100, 80], "金融威脅"),
        ("192.168.1.102", "POST /api/patient_id?record=123456", [150, 45], "醫療威脅"),
        ("192.168.1.103", "Normal request to /api/users", [50, 20], "正常流量"),
        ("192.168.1.104", "private_key = '0xaf...'", [200, 100], "加密貨幣威脅"),
    ]
    
    for ip, payload, features, description in test_cases:
        result = system.analyze_with_scoring(ip, payload, np.array(features))
        
        print(f"\n🎯 測試: {description}")
        print(f"   IP: {ip}")
        print(f"   Payload: {payload[:50]}...")
        print(f"   威脅類型: {result['threat_type']}")
        print(f"   基礎風險: {result['risk_score']:.2%}")
        print(f"   加權風險: {result['weighted_risk_score']:.2%}")
        print(f"   動作: {result['action']}")
        print(f"   詳細評分:")
        for key, value in result['detailed_scores'].items():
            print(f"      - {key}: {value:.4f}")
    
    print("\n" + "-" * 60)
    print("✅ 完整分析演示完成\n")
    
    # 最終統計
    stats = system.get_threat_statistics()
    print("📊 最終統計:")
    print(f"   總請求: {stats['total_requests']}")
    print(f"   已阻止: {stats['blocked_requests']}")
    print(f"   已允許: {stats['allowed_requests']}")
    if stats['total_requests'] > 0:
        print(f"   阻止率: {stats['block_rate']:.2f}%")


if __name__ == "__main__":
    demonstrate_enhanced_system()
