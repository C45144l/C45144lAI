"""
測試規則檢測功能
Tests for rule-based threat detection using custom patterns
"""

import pytest
from src.defense_system import LurRenJiaDefenseSystem


class TestRuleBasedDetection:
    """測試規則基礎的威脅檢測"""

    @pytest.fixture
    def system(self):
        """初始化防禦系統"""
        system = LurRenJiaDefenseSystem()
        return system

    # ===== 基本規則檢測測試 =====
    
    def test_rule_check_simple_pattern(self, system):
        """測試簡單模式匹配"""
        # 清除默認模式以避免衝突
        system.threat_patterns.clear()
        system.threat_patterns['custom_attacks'] = [
            r'vulnerable_endpoint',
            r'admin_panel',
        ]
        
        # 測試匹配
        is_threat, threat_name, patterns = system.rule_based_check('GET /admin_panel')
        assert is_threat is True
        assert threat_name == 'custom_attacks'
        assert r'admin_panel' in patterns

    def test_rule_check_case_insensitive(self, system):
        """測試不區分大小寫"""
        system.threat_patterns.clear()
        system.threat_patterns['custom_attacks'] = [r'ADMIN_PANEL']
        
        # 小寫應該被匹配
        is_threat, threat_name, patterns = system.rule_based_check('GET /admin_panel')
        assert is_threat is True
        assert threat_name == 'custom_attacks'

    def test_rule_check_no_match(self, system):
        """測試無匹配結果"""
        system.threat_patterns.clear()
        system.threat_patterns['custom_attacks'] = [r'admin_panel']
        
        is_threat, threat_name, patterns = system.rule_based_check('GET /normal_page')
        assert is_threat is False
        assert threat_name == 'NONE'
        assert patterns == []

    def test_rule_check_multiple_matches(self, system):
        """測試單個威脅類型內的多個模式匹配"""
        # 清除默認模式，添加自定義威脅
        system.threat_patterns.clear()
        system.threat_patterns['sql_attacks'] = [
            r'drop\s+table',
            r'delete\s+from',
            r'union\s+select',
        ]
        
        payload = "drop table users;"
        is_threat, threat_name, patterns = system.rule_based_check(payload)
        assert is_threat is True
        assert threat_name == 'sql_attacks'
        assert len(patterns) >= 1

    def test_rule_check_regex_pattern(self, system):
        """測試正則表達式模式"""
        system.threat_patterns.clear()
        system.threat_patterns['api_attacks'] = [
            r'/api/.*?/admin',
            r'/api/.*?/delete',
        ]
        
        is_threat, threat_name, patterns = system.rule_based_check('/api/v1/admin')
        assert is_threat is True
        assert threat_name == 'api_attacks'

    def test_rule_check_priority(self, system):
        """測試威脅優先級 - 第一個匹配的威脅被返回"""
        system.threat_patterns.clear()
        system.threat_patterns['high_priority'] = [r'critical']
        system.threat_patterns['low_priority'] = [r'critical']
        
        is_threat, threat_name, patterns = system.rule_based_check('critical system')
        assert is_threat is True
        # 應該返回第一個匹配的威脅
        assert threat_name in ['high_priority', 'low_priority']

    # ===== 批量檢測測試 =====

    def test_batch_rule_check_single(self, system):
        """測試批量檢測 - 單個有效負載"""
        system.threat_patterns.clear()
        system.threat_patterns['custom_attacks'] = [r'admin_panel']
        
        payloads = ['GET /admin_panel']
        results = system.batch_rule_check(payloads)
        
        assert len(results) == 1
        assert results[0]['is_threat'] is True
        assert results[0]['threat_type'] == 'custom_attacks'
        assert 'payload' in results[0]
        assert 'matched_patterns' in results[0]

    def test_batch_rule_check_multiple(self, system):
        """測試批量檢測 - 多個有效負載"""
        system.threat_patterns.clear()
        system.threat_patterns['attacks'] = [r'admin', r'delete']
        
        payloads = [
            'GET /admin_panel',
            'normal request',
            'DELETE /database',
        ]
        results = system.batch_rule_check(payloads)
        
        assert len(results) == 3
        assert results[0]['is_threat'] is True
        assert results[1]['is_threat'] is False
        assert results[2]['is_threat'] is True

    def test_batch_rule_check_structure(self, system):
        """測試批量檢測結果結構"""
        system.threat_patterns.clear()
        system.threat_patterns['test'] = [r'threat']
        
        results = system.batch_rule_check(['threat detected'])
        result = results[0]
        
        # 驗證結構
        assert 'payload' in result
        assert 'is_threat' in result
        assert 'threat_type' in result
        assert 'matched_patterns' in result
        assert isinstance(result['matched_patterns'], list)

    # ===== URL 檢測測試 =====

    def test_rule_check_url_patterns(self, system):
        """測試 URL 特定模式"""
        system.threat_patterns.clear()
        system.threat_patterns['api_vulnerabilities'] = [
            r'/admin/',
            r'/backup\.',
            r'\.env',
            r'config\.php',
        ]
        
        test_cases = [
            ('GET /admin/panel HTTP/1.1', True, 'api_vulnerabilities'),
            ('GET /backup.sql HTTP/1.1', True, 'api_vulnerabilities'),
            ('POST /.env HTTP/1.1', True, 'api_vulnerabilities'),
            ('GET /normal HTTP/1.1', False, 'NONE'),
        ]
        
        for payload, expected_threat, expected_type in test_cases:
            is_threat, threat_name, patterns = system.rule_based_check(payload)
            assert is_threat == expected_threat, f"Failed for: {payload}"
            assert threat_name == expected_type, f"Wrong threat type for: {payload}"

    # ===== 特殊字符測試 =====

    def test_rule_check_special_characters(self, system):
        """測試含有特殊字符的模式"""
        system.threat_patterns.clear()
        system.threat_patterns['sql_injection'] = [
            r"'\s*or\s*'1'\s*=\s*'1",
            r'union.*select',
        ]
        
        is_threat, threat_name, patterns = system.rule_based_check("' or '1'='1")
        assert is_threat is True

    def test_rule_check_invalid_regex(self, system):
        """測試無效正則表達式的處理"""
        system.threat_patterns.clear()
        system.threat_patterns['test'] = [
            r'valid_pattern',
            r'[invalid(',  # 無效的正則表達式
        ]
        
        # 應該返回 valid_pattern 的匹配，無效的被跳過
        is_threat, threat_name, patterns = system.rule_based_check('valid_pattern test')
        assert is_threat is True
        assert r'valid_pattern' in patterns

    # ===== 集成測試 =====

    def test_integration_analyze_incoming_traffic_with_rules(self, system):
        """測試規則檢測與主分析流程的集成"""
        # 訓練系統
        import numpy as np
        training_data = np.array([
            [100, 50],
            [110, 55],
            [105, 52],
            [102, 48],
            [108, 51]
        ])
        system.train_ai_baseline(training_data)
        
        # 添加自定義規則
        system.threat_patterns.clear()
        system.threat_patterns['custom_attacks'] = [r'admin_panel']
        
        # 使用主分析方法
        features = [100, 50]  # [request_count, latency]
        result = system.analyze_incoming_traffic('192.168.1.1', 'GET /admin_panel', features)
        
        # 驗證規則檢測被集成
        assert 'threat_type' in result
        # 應該檢測到自定義威脅
        assert result['threat_type'] == 'custom_attacks'

    def test_integration_rule_priority_over_keyword(self, system):
        """測試規則檢測優先級 - 應優先於關鍵詞檢測"""
        # 訓練系統
        import numpy as np
        training_data = np.array([
            [100, 50],
            [110, 55],
            [105, 52],
            [102, 48],
            [108, 51]
        ])
        system.train_ai_baseline(training_data)
        
        # 設定自定義規則（高優先級）
        system.threat_patterns.clear()
        system.threat_patterns['high_priority_attack'] = [r'test_dangerous_payload']
        
        features = [50, 30]
        result = system.analyze_incoming_traffic(
            '192.168.1.1',
            'test_dangerous_payload',
            features
        )
        
        assert result['threat_type'] == 'high_priority_attack'

    # ===== 邊界測試 =====

    def test_rule_check_empty_payload(self, system):
        """測試空有效負載"""
        system.threat_patterns.clear()
        system.threat_patterns['test'] = [r'pattern']
        
        is_threat, threat_name, patterns = system.rule_based_check('')
        assert is_threat is False
        assert threat_name == 'NONE'

    def test_rule_check_very_long_payload(self, system):
        """測試非常長的有效負載"""
        system.threat_patterns.clear()
        system.threat_patterns['test'] = [r'dangerous']
        
        long_payload = 'GET /page HTTP/1.1\r\n' + 'A' * 10000 + 'dangerous' + 'A' * 10000
        is_threat, threat_name, patterns = system.rule_based_check(long_payload)
        assert is_threat is True

    def test_rule_check_empty_patterns_dict(self, system):
        """測試空模式字典"""
        system.threat_patterns.clear()
        
        is_threat, threat_name, patterns = system.rule_based_check('test payload')
        assert is_threat is False
        assert threat_name == 'NONE'

    # ===== 真實攻擊場景測試 =====

    def test_real_scenario_sql_injection_rules(self, system):
        """真實場景：SQL 注入規則"""
        system.threat_patterns.clear()
        system.threat_patterns['advanced_sqli'] = [
            r'union.*select',
            r'order\s+by\s+\d+',
            r'extractvalue\s*\(',
        ]
        
        payloads = [
            ('SELECT * FROM users UNION SELECT 1,2,3', True),
            ('SELECT * FROM users ORDER BY 1', True),
            ('extractvalue(0x0a,0x0a)', True),
            ('SELECT * FROM users WHERE id=1', False),
        ]
        
        for payload, should_detect in payloads:
            is_threat, threat_name, patterns = system.rule_based_check(payload)
            assert is_threat == should_detect, f"Failed for payload: {payload}"

    def test_real_scenario_xss_rules(self, system):
        """真實場景：XSS 攻擊規則"""
        system.threat_patterns.clear()
        system.threat_patterns['xss_vectors'] = [
            r'<script[^>]*>',
            r'onerror\s*=',
            r'javascript\s*:',
        ]
        
        payloads = [
            ('<script>alert("XSS")</script>', True),
            ('<img onerror=alert("XSS")>', True),
            ('<a href="javascript:void(0)">Click</a>', True),
            ('<div>Normal content</div>', False),
        ]
        
        for payload, should_detect in payloads:
            is_threat, threat_name, patterns = system.rule_based_check(payload)
            assert is_threat == should_detect

    def test_real_scenario_api_abuse_rules(self, system):
        """真實場景：API 濫用規則"""
        system.threat_patterns.clear()
        system.threat_patterns['api_abuse'] = [
            r'/api/.*?/debug',
            r'/api/.*?/admin',
            r'/api/.*?/backup',
        ]
        
        payloads = [
            ('/api/v1/debug', True),
            ('/api/users/admin', True),
            ('/api/system/backup', True),
            ('/api/users/list', False),
        ]
        
        for payload, should_detect in payloads:
            is_threat, threat_name, patterns = system.rule_based_check(payload)
            assert is_threat == should_detect

    # ===== 效能測試 =====

    def test_performance_rule_check(self, system):
        """測試規則檢測效能"""
        import time
        
        # 添加多個威脅類型
        system.threat_patterns.clear()
        system.threat_patterns['sql'] = [r'drop', r'delete', r'union']
        system.threat_patterns['xss'] = [r'<script', r'onerror', r'onclick']
        system.threat_patterns['rce'] = [r'exec', r'system', r'shell_exec']
        
        payload = 'GET /api/user?id=1 HTTP/1.1'
        
        start = time.time()
        for _ in range(1000):
            system.rule_based_check(payload)
        elapsed = time.time() - start
        
        # 1000 次檢測應該在 1 秒內完成
        assert elapsed < 1.0, f"Performance issue: {elapsed}s for 1000 checks"

    def test_performance_batch_check(self, system):
        """測試批量檢測效能"""
        import time
        
        system.threat_patterns.clear()
        system.threat_patterns['test'] = [r'pattern']
        payloads = ['payload ' + str(i) for i in range(1000)]
        
        start = time.time()
        system.batch_rule_check(payloads)
        elapsed = time.time() - start
        
        # 1000 個有效負載的批量檢測應該在 2 秒內完成
        assert elapsed < 2.0, f"Performance issue: {elapsed}s for batch of 1000"


class TestRuleBasedDetectionAdvanced:
    """高級規則檢測測試"""

    @pytest.fixture
    def system(self):
        """初始化防禦系統"""
        return LurRenJiaDefenseSystem()

    def test_complex_regex_patterns(self, system):
        """測試複雜的正則表達式"""
        system.threat_patterns.clear()
        system.threat_patterns['advanced'] = [
            r'(?:admin|administrator)[\w_]*',
            r'(?:password|passwd|pwd)[\s=:]*(?:["\']?[\w@#$%]+["\']?)',
        ]
        
        test_cases = [
            ('GET /administrator_panel', True),
            ('admin_dashboard', True),
            ('password="secret123"', True),
            ('passwd: test', True),
            ('normal request', False),
        ]
        
        for payload, expected in test_cases:
            is_threat, _, _ = system.rule_based_check(payload)
            assert is_threat == expected, f"Failed for: {payload}"

    def test_threat_patterns_modification(self, system):
        """測試在運行時修改威脅模式"""
        system.threat_patterns.clear()
        system.threat_patterns['dynamic'] = [r'version1']
        
        # 第一次檢測
        is_threat1, _, _ = system.rule_based_check('version1')
        assert is_threat1 is True
        
        # 修改模式
        system.threat_patterns.clear()
        system.threat_patterns['dynamic'] = [r'version2']
        
        # 舊模式應該不再匹配
        is_threat2, _, _ = system.rule_based_check('version1')
        assert is_threat2 is False
        
        # 新模式應該匹配
        is_threat3, _, _ = system.rule_based_check('version2')
        assert is_threat3 is True

    def test_multiple_threat_categories(self, system):
        """測試多個威脅類別的優先級"""
        system.threat_patterns.clear()
        system.threat_patterns['sql'] = [r'sql_keyword']
        system.threat_patterns['xss'] = [r'xss_keyword']
        system.threat_patterns['rce'] = [r'rce_keyword']
        
        payloads = [
            'sql_keyword test',
            'xss_keyword test',
            'rce_keyword test',
        ]
        
        results = system.batch_rule_check(payloads)
        assert results[0]['threat_type'] == 'sql'
        assert results[1]['threat_type'] == 'xss'
        assert results[2]['threat_type'] == 'rce'

    def test_mixed_payload_analysis(self, system):
        """測試混合攻擊有效負載分析"""
        system.threat_patterns.clear()
        system.threat_patterns['combined'] = [
            r'<script.*?javascript',  # XSS + inline JS
            r'union.*select.*from',   # SQL injection
        ]
        
        # 混合攻擊
        payload = "<script>var x = 'union select * from users'</script>"
        is_threat, threat_type, patterns = system.rule_based_check(payload)
        
        assert is_threat is True
        assert len(patterns) >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
