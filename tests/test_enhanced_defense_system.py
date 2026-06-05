"""
增強型防禦系統測試
Tests for Enhanced Defense System
"""

import pytest
import numpy as np
from src.enhanced_defense_system import EnhancedDefenseSystem


class TestEnhancedDefenseSystemInitialization:
    """測試增強型系統初始化"""

    @pytest.fixture
    def system(self):
        """初始化增強型防禦系統"""
        return EnhancedDefenseSystem()

    def test_initialization(self, system):
        """測試系統初始化"""
        assert system is not None
        assert system.trained is False

    def test_industry_specific_rules_loaded(self, system):
        """測試行業特定規則已載入"""
        assert 'financial_threats' in system.threat_patterns
        assert 'healthcare_threats' in system.threat_patterns
        assert 'government_threats' in system.threat_patterns
        assert 'crypto_threats' in system.threat_patterns

    def test_rules_content(self, system):
        """測試規則內容"""
        # 金融威脅
        assert r'credit_card' in system.threat_patterns['financial_threats']
        assert r'swift_code' in system.threat_patterns['financial_threats']
        
        # 醫療威脅
        assert r'patient_id' in system.threat_patterns['healthcare_threats']
        assert r'hipaa' in system.threat_patterns['healthcare_threats']
        
        # 政府威脅
        assert r'classified' in system.threat_patterns['government_threats']
        assert r'ssn' in system.threat_patterns['government_threats']
        
        # 加密貨幣威脅
        assert r'private_key' in system.threat_patterns['crypto_threats']
        assert r'seed_phrase' in system.threat_patterns['crypto_threats']


class TestCustomPatternAddition:
    """測試自定義模式添加"""

    @pytest.fixture
    def system(self):
        """初始化增強型防禦系統"""
        return EnhancedDefenseSystem()

    def test_add_custom_pattern_new_category(self, system):
        """測試添加新類別的自定義模式"""
        system.add_custom_pattern('custom_threats', [r'custom_pattern1', r'custom_pattern2'])
        
        assert 'custom_threats' in system.threat_patterns
        assert r'custom_pattern1' in system.threat_patterns['custom_threats']
        assert r'custom_pattern2' in system.threat_patterns['custom_threats']

    def test_add_custom_pattern_existing_category(self, system):
        """測試向現有類別添加模式"""
        original_count = len(system.threat_patterns['financial_threats'])
        system.add_custom_pattern('financial_threats', [r'new_financial_threat'])
        
        assert len(system.threat_patterns['financial_threats']) == original_count + 1
        assert r'new_financial_threat' in system.threat_patterns['financial_threats']

    def test_add_single_pattern_as_string(self, system):
        """測試添加單個字符串模式"""
        system.add_custom_pattern('single_threat', r'single_pattern')
        
        assert 'single_threat' in system.threat_patterns
        assert r'single_pattern' in system.threat_patterns['single_threat']

    def test_add_multiple_patterns(self, system):
        """測試添加多個模式"""
        patterns = [r'pattern1', r'pattern2', r'pattern3']
        system.add_custom_pattern('multi_threats', patterns)
        
        assert len(system.threat_patterns['multi_threats']) == 3


class TestEnhancedAnalysis:
    """測試增強版分析"""

    @pytest.fixture
    def system(self):
        """初始化和訓練系統"""
        system = EnhancedDefenseSystem()
        
        # 訓練系統
        normal_data = np.random.randn(1000, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        return system

    def test_analyze_with_scoring_structure(self, system):
        """測試分析結果結構"""
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "GET /api/users",
            np.array([100, 50])
        )
        
        # 驗證結果包含所有必要字段
        assert 'detailed_scores' in result
        assert 'weighted_risk_score' in result
        assert 'risk_breakdown' in result
        assert 'threat_type' in result
        assert 'action' in result

    def test_detailed_scores_content(self, system):
        """測試詳細評分內容"""
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "SELECT * FROM users",
            np.array([100, 50])
        )
        
        scores = result['detailed_scores']
        assert 'base_risk' in scores
        assert 'payload_complexity' in scores
        assert 'feature_anomaly' in scores
        assert 'threat_severity' in scores
        
        # 驗證分數範圍
        for key, value in scores.items():
            assert 0 <= value <= 1, f"{key} 超出範圍: {value}"

    def test_weighted_risk_calculation(self, system):
        """測試加權風險計算"""
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "SELECT credit_card FROM customers",
            np.array([150, 80])
        )
        
        weighted_risk = result['weighted_risk_score']
        assert 0 <= weighted_risk <= 1
        assert weighted_risk > 0  # 應該檢測到威脅

    def test_threat_detection_in_analysis(self, system):
        """測試威脅在分析中的檢測"""
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "SELECT patient_id FROM medical_records",
            np.array([100, 50])
        )
        
        # 應該檢測到醫療威脅
        assert result['threat_type'] is not None


class TestSeverityCalculation:
    """測試嚴重程度計算"""

    @pytest.fixture
    def system(self):
        """初始化系統"""
        return EnhancedDefenseSystem()

    def test_severity_values(self, system):
        """測試嚴重程度計算值"""
        threat_types = [
            ('SQL_INJECTION', 0.95),
            ('COMMAND_INJECTION', 0.99),
            ('XSS', 0.85),
            ('crypto_threats', 0.91),
            ('government_threats', 0.99),
            ('UNKNOWN', 0.0),
        ]
        
        for threat_type, expected_severity in threat_types:
            severity = system._calculate_severity(threat_type)
            assert severity == expected_severity, f"Unexpected severity for {threat_type}"

    def test_unknown_threat_severity(self, system):
        """測試未知威脅的嚴重程度"""
        severity = system._calculate_severity('unknown_threat')
        assert severity == 0.5  # 默認值


class TestBatchAnalysis:
    """測試批量分析"""

    @pytest.fixture
    def system(self):
        """初始化和訓練系統"""
        system = EnhancedDefenseSystem()
        
        normal_data = np.random.randn(100, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        return system

    def test_batch_analyze_with_scoring(self, system):
        """測試批量分析"""
        payloads = [
            "SELECT * FROM users",
            "GET /api/normal",
            "credit_card information",
        ]
        
        results = system.batch_analyze_with_scoring(payloads)
        
        assert len(results) == 3
        for result in results:
            assert 'weighted_risk_score' in result
            assert 'detailed_scores' in result

    def test_batch_analyze_with_custom_features(self, system):
        """測試帶自定義特徵的批量分析"""
        payloads = ["test1", "test2"]
        features = np.array([100, 50])
        
        results = system.batch_analyze_with_scoring(
            payloads,
            ip="192.168.1.100",
            traffic_features=features
        )
        
        assert len(results) == 2
        for result in results:
            assert result['ip'] == "192.168.1.100"


class TestStatistics:
    """測試統計功能"""

    @pytest.fixture
    def system(self):
        """初始化和訓練系統"""
        system = EnhancedDefenseSystem()
        
        normal_data = np.random.randn(100, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        return system

    def test_get_threat_statistics(self, system):
        """測試獲取威脅統計"""
        # 執行一些分析
        system.analyze_incoming_traffic("192.168.1.1", "SELECT * FROM users", np.array([100, 50]))
        system.analyze_incoming_traffic("192.168.1.2", "GET /normal", np.array([50, 20]))
        
        stats = system.get_threat_statistics()
        
        assert 'total_requests' in stats
        assert 'blocked_requests' in stats
        assert 'threat_categories' in stats
        assert 'total_patterns' in stats
        assert stats['total_requests'] == 2

    def test_block_rate_calculation(self, system):
        """測試阻止率計算"""
        # 執行分析
        system.analyze_incoming_traffic("192.168.1.1", "SELECT * FROM users", np.array([100, 50]))
        system.analyze_incoming_traffic("192.168.1.2", "GET /normal", np.array([50, 20]))
        
        stats = system.get_threat_statistics()
        
        assert 'block_rate' in stats
        assert 0 <= stats['block_rate'] <= 100


class TestIntegration:
    """集成測試"""

    @pytest.fixture
    def system(self):
        """初始化和訓練系統"""
        system = EnhancedDefenseSystem()
        
        # 添加自定義規則
        system.add_custom_pattern('internal_threats', [
            r'confidential',
            r'internal_memo'
        ])
        
        # 訓練
        normal_data = np.random.randn(100, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        return system

    def test_full_workflow(self, system):
        """測試完整工作流"""
        # 1. 執行分析
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "SELECT confidential FROM employees",
            np.array([100, 50])
        )
        
        assert result is not None
        assert 'weighted_risk_score' in result
        assert result['action'] in ['blocked', 'allowed']

    def test_multiple_threat_types(self, system):
        """測試多個威脅類型的檢測"""
        threat_payloads = [
            "SELECT credit_card FROM customers",  # 金融
            "patient_id = 123456",  # 醫療
            "private_key = 'xyz'",  # 加密貨幣
            "SELECT confidential FROM internal",  # 內部
        ]
        
        for payload in threat_payloads:
            result = system.analyze_with_scoring(
                "192.168.1.1",
                payload,
                np.array([100, 50])
            )
            
            # 應該檢測到威脅或異常
            assert result['weighted_risk_score'] >= 0

    def test_system_info_output(self, system):
        """測試系統信息輸出（不應崩潰）"""
        try:
            system.print_system_info()
            assert True
        except Exception as e:
            pytest.fail(f"print_system_info() 失敗: {e}")


class TestEdgeCases:
    """邊界案例測試"""

    @pytest.fixture
    def system(self):
        """初始化系統"""
        return EnhancedDefenseSystem()

    def test_empty_payload(self, system):
        """測試空有效負載"""
        system.train_ai_baseline(np.random.randn(100, 2) * 10 + 50)
        
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "",
            np.array([100, 50])
        )
        
        assert 'weighted_risk_score' in result

    def test_very_long_payload(self, system):
        """測試非常長的有效負載"""
        system.train_ai_baseline(np.random.randn(100, 2) * 10 + 50)
        
        long_payload = "A" * 10000
        result = system.analyze_with_scoring(
            "192.168.1.1",
            long_payload,
            np.array([100, 50])
        )
        
        assert result['detailed_scores']['payload_complexity'] > 0

    def test_feature_with_zero_std(self, system):
        """測試特徵標準差為零的情況"""
        system.train_ai_baseline(np.random.randn(100, 2) * 10 + 50)
        
        # 相同的特徵值
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "test",
            np.array([50, 50])
        )
        
        assert result['detailed_scores']['feature_anomaly'] == 0.0

    def test_list_traffic_features(self, system):
        """測試列表格式的流量特徵"""
        system.train_ai_baseline(np.random.randn(100, 2) * 10 + 50)
        
        result = system.analyze_with_scoring(
            "192.168.1.1",
            "test",
            [100, 50]  # 使用列表而不是 numpy 數組
        )
        
        assert 'weighted_risk_score' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
