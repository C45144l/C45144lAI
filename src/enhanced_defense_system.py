"""
增強型防禦系統 - 行業特定威脅檢測
Enhanced Defense System with Industry-Specific Threat Detection

Features:
- Industry-specific threat patterns
- Detailed scoring with multiple dimensions
- Advanced analytics and reporting
- Threat trend analysis
"""

import numpy as np
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import threading

from src.defense_system import LurRenJiaDefenseSystem


class EnhancedDefenseSystem(LurRenJiaDefenseSystem):
    """增強型防禦系統 - 添加自定義規則與行業特定威脅檢測"""
    
    def __init__(self, *args, enable_analytics: bool = True, **kwargs):
        """
        初始化增強型防禦系統
        
        Args:
            enable_analytics: Enable detailed threat analytics
            *args, **kwargs: Arguments passed to parent class
        """
        super().__init__(*args, **kwargs)
        
        self.enable_analytics = enable_analytics
        self.threat_analytics: Dict[str, int] = {}  # Track threat frequencies
        self._analytics_lock = threading.Lock() if enable_analytics else None
        self._industry_specific_rules_added = False
        
        self._add_industry_specific_rules()
    
    def _add_industry_specific_rules(self) -> None:
        """添加特定行業的威脅規則"""
        
        # 金融行業特定威脅 (銀行、支付、證券)
        self.threat_patterns['financial_threats'] = [
            'credit_card',
            r'(?i)(credit_card|credit card)',
            r'(?i)(bank_account|bank account)',
            r'(?i)(routing_number|routing number)',
            'swift_code',
            r'(?i)(swift_code|swift code|swiftcode)',
            r'(?i)iban',
            r'(?i)(account_number|account number)',
            r'(?i)(cvv|cvc|cvv2)',
            r'(?i)(pan|primary account number)',
        ]
        
        # 醫療行業特定威脅 (PHI)
        self.threat_patterns['healthcare_threats'] = [
            'patient_id',
            r'(?i)(patient_id|patient id|mrn)',
            r'(?i)(medical_record|medical record|health record)',
            r'(?i)prescription',
            'hipaa',
            r'(?i)(hipaa|hipaa violation)',
            r'(?i)(protected_health|protected health information)',
            r'(?i)diagnosis',
            r'(?i)(dob|date of birth)',
            r'(?i)(ssn|social security)',
        ]
        
        # 政府機構特定威脅 (分類信息)
        self.threat_patterns['government_threats'] = [
            'classified',
            r'(?i)classified',
            r'(?i)(top_secret|top secret)',
            'ssn',
            r'(?i)(ssn|social security number)',
            r'(?i)(passport|passport number)',
            r'(?i)(national_id|national id)',
            r'(?i)confidential',
            r'(?i)(state secret|official secret)',
            r'(?i)(clearance level|security clearance)',
        ]
        
        # 加密貨幣交易所特定威脅 (私鑰洩露)
        self.threat_patterns['crypto_threats'] = [
            'private_key',
            r'(?i)(private_key|private key)',
            'seed_phrase',
            r'(?i)(seed_phrase|seed phrase|recovery phrase)',
            r'(?i)(wallet_address|wallet address)',
            r'(?i)cryptocurrency',
            r'(?i)bitcoin',
            r'(?i)ethereum',
            r'(?i)mnemonic',
            r'0x[a-fA-F0-9]{40}',  # Ethereum address
            r'1[a-zA-Z0-9]{25,34}|3[a-zA-Z0-9]{25,34}',  # Bitcoin address
        ]
        
        # 智慧財產權 (源代碼、商業機密)
        self.threat_patterns['intellectual_property'] = [
            r'(?i)(source code|source_code)',
            r'(?i)(trade secret|trade_secret)',
            r'(?i)(proprietary|proprietary code)',
            r'(?i)(patent|patent application)',
            r'(?i)(api_key|api key)',
            r'(?i)(database password|db password)',
            r'(?i)(ssh key|rsa key)',
        ]
        
        self._industry_specific_rules_added = True
        self.logger.info(f"✅ 已載入特定行業威脅規則 ({len(self.threat_patterns)-8} 個通用 + 5 個行業特定類別)")
    
    def add_custom_pattern(self, category: str, patterns: Union[str, List[str]]) -> None:
        """
        動態添加自定義威脅模式
        
        Args:
            category: 威脅類別名稱
            patterns: 正則表達式模式或模式列表
            
        Raises:
            ValueError: If patterns is invalid type
        """
        if not isinstance(patterns, (str, list)):
            raise ValueError(f"Patterns must be str or list, got {type(patterns)}")
        
        # Ensure patterns is a list
        if isinstance(patterns, str):
            patterns = [patterns]
        
        if category not in self.threat_patterns:
            self.threat_patterns[category] = []
        
        # Validate each pattern
        import re
        for pattern in patterns:
            try:
                re.compile(pattern)  # Test compilation
            except re.error as e:
                self.logger.error(f"❌ 無效的正則表達式: {pattern} - {str(e)}")
                raise ValueError(f"Invalid regex pattern: {pattern}")
        
        self.threat_patterns[category].extend(patterns)
        
        # Clear cache
        if self.enable_caching:
            self._cache.clear()
        
        self.logger.info(f"✅ 已添加 {len(patterns)} 個 '{category}' 規則 (總計: {len(self.threat_patterns[category])} 個)")
    
    def analyze_with_scoring(self, ip: str, payload: str, traffic_features: Union[List, np.ndarray]) -> Dict[str, Any]:
        """
        增強版分析 - 返回詳細評分
        
        Args:
            ip: 來源 IP 地址
            payload: 請求有效負載
            traffic_features: 流量特徵 [size, latency]
        
        Returns:
            包含詳細評分和多維度分析的結果字典
        """
        # 執行標準分析
        result = self.analyze_incoming_traffic(ip, payload, traffic_features)
        
        # 驗證輸入
        traffic_features = np.asarray(traffic_features)
        if traffic_features.ndim == 1:
            traffic_features = traffic_features.reshape(1, -1)
        
        # 計算詳細評分 - 所有分數都規範化到 0-1 範圍內
        detailed_score = {
            'base_risk': float(result['risk_score']),
            'payload_complexity': self._normalize_score(min(len(payload) / 100, 10)),
            'feature_anomaly': self._normalize_score(
                float(traffic_features[0].std()) if len(traffic_features[0]) > 0 else 0.0
            ),
            'threat_severity': self._calculate_severity(result['threat_type'])
        }
        
        # 加權計算風險
        weights = {
            'base_risk': 0.4,
            'payload_complexity': 0.15,
            'feature_anomaly': 0.15,
            'threat_severity': 0.3
        }
        
        weighted_risk = sum(
            detailed_score[key] * weights[key]
            for key in detailed_score.keys()
        )
        
        result['detailed_scores'] = detailed_score
        result['weighted_risk_score'] = min(weighted_risk, 1.0)
        result['risk_breakdown'] = weights
        result['analysis_timestamp'] = datetime.now().isoformat()
        
        # Track threat analytics
        if self.enable_analytics:
            self._track_threat(result['threat_type'])
        
        return result
    
    def _normalize_score(self, value: float) -> float:
        """
        將任意分數正規化到 0-1 範圍
        使用平滑的比率映射函數，以便 0 對應 0
        
        Args:
            value: 原始分數
        
        Returns:
            正規化分數 (0-1)
        """
        if value <= 0:
            return 0.0
        normalized = value / (1.0 + abs(value))
        return float(np.clip(normalized, 0.0, 1.0))
    
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
            'COMMAND_INJECTION': 0.99,
            'RCE': 0.99,
            'XSS': 0.85,
            'XSS_ENCODED': 0.78,
            'PATH_TRAVERSAL': 0.80,
            'MALWARE': 0.90,
            'APT_EXFILTRATION': 0.98,
            'REVERSE_SHELL': 0.97,
            'BRUTE_FORCE': 0.65,
            'MULTI_VECTOR_ATTACK': 0.96,
            'financial_threats': 0.92,
            'healthcare_threats': 0.94,
            'government_threats': 0.99,
            'crypto_threats': 0.91,
            'intellectual_property': 0.93,
            'ABNORMAL_TRAFFIC': 0.50,
            'UNKNOWN': 0.0,
            'NONE': 0.0
        }
        return severity_map.get(threat_type, 0.5)
    
    def _track_threat(self, threat_type: str) -> None:
        """Track threat occurrences for analytics"""
        if self._analytics_lock:
            with self._analytics_lock:
                self.threat_analytics[threat_type] = self.threat_analytics.get(threat_type, 0) + 1
        else:
            self.threat_analytics[threat_type] = self.threat_analytics.get(threat_type, 0) + 1
    
    def batch_analyze_with_scoring(self, payloads: List[str], ip: str = "127.0.0.1", 
                                   traffic_features: Optional[np.ndarray] = None) -> List[Dict[str, Any]]:
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
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """
        獲取威脅統計信息
        
        Returns:
            包含詳細威脅統計的字典
        """
        stats = self.statistics.copy()
        stats['threat_categories'] = list(self.threat_patterns.keys())
        stats['total_patterns'] = sum(
            len(patterns) if isinstance(patterns, list) else 1
            for patterns in self.threat_patterns.values()
        )
        
        if self.enable_analytics:
            stats['threat_distribution'] = self.threat_analytics.copy()
            stats['most_detected'] = max(self.threat_analytics, key=self.threat_analytics.get) if self.threat_analytics else None
        
        if stats['total_requests'] > 0:
            stats['block_rate'] = (stats['blocked_requests'] / stats['total_requests']) * 100
            stats['anomaly_rate'] = (stats['anomalies_detected'] / stats['total_requests']) * 100
        else:
            stats['block_rate'] = 0.0
            stats['anomaly_rate'] = 0.0
        
        return stats
    
    def get_industry_threat_report(self) -> Dict[str, Dict[str, Any]]:
        """
        生成按行業分類的威脅報告
        
        Returns:
            按行業分類的威脅統計報告
        """
        industry_categories = [
            'financial_threats',
            'healthcare_threats',
            'government_threats',
            'crypto_threats',
            'intellectual_property'
        ]
        
        report = {}
        for category in industry_categories:
            report[category] = {
                'count': self.threat_analytics.get(category, 0),
                'patterns': len(self.threat_patterns.get(category, [])),
                'total_reports': sum(
                    1 for event in self.event_history 
                    if event['threat_type'] == category
                )
            }
        
        return report
    
    def print_system_info(self) -> None:
        """打印詳細的系統信息"""
        print("\n" + "="*70)
        print("🔐 增強型防禦系統 - 詳細信息")
        print("="*70)
        print(f"系統類名: {self.__class__.__name__}")
        print(f"基類: {self.__class__.__bases__[0].__name__}")
        print(f"\n📋 業務配置:")
        print(f"  • 分析引擎: {'✅ 啟用' if self.enable_analytics else '❌ 禁用'}")
        print(f"  • 行業規則: {'✅ 已載入' if self._industry_specific_rules_added else '❌ 未載入'}")
        
        print(f"\n📊 威脅檢測:")
        print(f"  • 總威脅類別: {len(self.threat_patterns)}")
        print(f"  • 總檢測規則: {sum(len(patterns) if isinstance(patterns, list) else 1 for patterns in self.threat_patterns.values())}")
        print(f"\n  詳細分類:")
        
        for category, patterns in list(self.threat_patterns.items())[:10]:
            pattern_count = len(patterns) if isinstance(patterns, list) else 1
            print(f"    • {category}: {pattern_count} 個規則")
        
        stats = self.get_threat_statistics()
        print(f"\n📈 統計信息:")
        print(f"  • 總請求數: {stats['total_requests']}")
        print(f"  • 已阻止: {stats['blocked_requests']}")
        print(f"  • 已允許: {stats['allowed_requests']}")
        print(f"  • 異常檢測: {stats['anomalies_detected']}")
        
        if stats['total_requests'] > 0:
            print(f"  • 阻止率: {stats.get('block_rate', 'N/A')}")
            print(f"  • 異常率: {stats.get('anomaly_rate', 'N/A')}")
        
        if self.enable_analytics and stats.get('most_detected'):
            print(f"\n  • 最常檢測威脅: {stats['most_detected']}")
            print(f"  • 威脅出現次數: {self.threat_analytics.get(stats['most_detected'], 0)}")
        
        print(f"\n🤖 AI 模型:")
        model_stats = self.get_model_stats()
        print(f"  • 已訓練: {'✅ 是' if self.trained else '❌ 否'}")
        print(f"  • 估計器數量: {model_stats.get('n_estimators', 'N/A')}")
        print(f"  • 基線樣本: {model_stats.get('baseline_size', 0)}")
        print("="*70 + "\n")


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
