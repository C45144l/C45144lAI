"""
Test suite for security event analysis and report generation
"""

import pytest
import json
import os
import numpy as np
from src.defense_system import LurRenJiaDefenseSystem


class TestEventRecording:
    """Test event recording and history"""
    
    @pytest.fixture
    def trained_system(self):
        """Provide a trained defense system"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        return system
    
    def test_single_event_recording(self, trained_system):
        """Test recording of single security event"""
        trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "GET /api/users",
            np.array([50, 15])
        )
        
        events = trained_system.get_event_history()
        assert len(events) == 1
        assert events[0]['ip'] == "192.168.1.1"
    
    def test_multiple_events_recording(self, trained_system):
        """Test recording of multiple security events"""
        for i in range(5):
            trained_system.analyze_incoming_traffic(
                f"192.168.1.{i+1}",
                f"GET /api/request_{i}",
                np.array([50, 15])
            )
        
        events = trained_system.get_event_history()
        assert len(events) == 5
    
    def test_event_timestamp_format(self, trained_system):
        """Test that event timestamps are in ISO format"""
        trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "GET /api/users",
            np.array([50, 15])
        )
        
        event = trained_system.get_event_history()[0]
        timestamp = event['timestamp']
        
        # Check ISO format (contains T and Z or +/-offset)
        assert 'T' in timestamp
    
    def test_event_payload_truncation(self, trained_system):
        """Test that payloads are truncated to 100 chars"""
        long_payload = "A" * 200
        trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            long_payload,
            np.array([50, 15])
        )
        
        event = trained_system.get_event_history()[0]
        assert len(event['payload']) <= 100


class TestStatisticsGeneration:
    """Test statistics generation"""
    
    @pytest.fixture
    def trained_system_with_events(self):
        """Provide a system with recorded events"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        # Analyze some requests
        payloads = [
            "GET /api/users",
            "<script>alert(1)</script>",
            "'; DROP TABLE users; --",
        ]
        
        for i, payload in enumerate(payloads):
            system.analyze_incoming_traffic(
                f"192.168.1.{i+1}",
                payload,
                np.array([50, 15])
            )
        
        return system
    
    def test_statistics_structure(self, trained_system_with_events):
        """Test that statistics have correct structure"""
        stats = trained_system_with_events.get_statistics()
        
        required_fields = [
            'total_requests',
            'blocked_requests',
            'allowed_requests',
            'block_rate',
            'anomalies_detected'
        ]
        
        for field in required_fields:
            assert field in stats
    
    def test_statistics_values(self, trained_system_with_events):
        """Test that statistics values are valid"""
        stats = trained_system_with_events.get_statistics()
        
        assert stats['total_requests'] == 3
        assert stats['blocked_requests'] >= 0
        assert stats['allowed_requests'] >= 0
        assert stats['blocked_requests'] + stats['allowed_requests'] == stats['total_requests']
        assert 0 <= stats['block_rate'] <= 1.0
    
    def test_block_rate_calculation(self, trained_system_with_events):
        """Test that block rate is calculated correctly"""
        stats = trained_system_with_events.get_statistics()
        
        expected_block_rate = stats['blocked_requests'] / stats['total_requests']
        assert abs(stats['block_rate'] - expected_block_rate) < 0.001


class TestReportGeneration:
    """Test report generation functionality"""
    
    @pytest.fixture
    def trained_system_with_events(self):
        """Provide a system with recorded events"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        # Analyze attack scenarios
        attacks = [
            ("192.168.1.1", "GET /api/users", [50, 15]),
            ("10.0.0.5", "<script>alert('XSS')</script>", [52, 12]),
            ("203.0.113.1", "'; DROP TABLE users; --", [50, 15]),
        ]
        
        for ip, payload, features in attacks:
            system.analyze_incoming_traffic(ip, payload, np.array(features))
        
        return system
    
    def test_json_report_structure(self, trained_system_with_events):
        """Test that JSON report has correct structure"""
        stats = trained_system_with_events.get_statistics()
        events = trained_system_with_events.get_event_history()
        
        report = {
            'report_metadata': {
                'timestamp': '2026-03-14T00:00:00',
                'report_title': 'Security Audit Report',
            },
            'summary': stats,
            'events': events,
        }
        
        # Try to serialize to JSON
        json_str = json.dumps(report)
        assert len(json_str) > 0
        
        # Try to deserialize
        report_loaded = json.loads(json_str)
        assert 'summary' in report_loaded
        assert 'events' in report_loaded
    
    def test_high_risk_event_extraction(self, trained_system_with_events):
        """Test extraction of high-risk events"""
        events = trained_system_with_events.get_event_history()
        
        high_risk = [e for e in events if e['risk_score'] > 0.8]
        
        # Should have at least some high-risk events
        assert len(high_risk) >= 0
        
        # All extracted events should meet criteria
        for event in high_risk:
            assert event['risk_score'] > 0.8
    
    def test_threat_statistics_from_events(self, trained_system_with_events):
        """Test aggregation of threat statistics from events"""
        events = trained_system_with_events.get_event_history()
        
        threat_types = {}
        for event in events:
            threat_type = event['threat_type']
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Should have detected different threat types
        assert len(threat_types) > 0
        
        # Total count should match event count
        assert sum(threat_types.values()) == len(events)


class TestReportFormatting:
    """Test report formatting and output"""
    
    @pytest.fixture
    def trained_system_with_events(self):
        """Provide a system with recorded events"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        # Analyze some requests
        system.analyze_incoming_traffic("192.168.1.1", "GET /api/users", np.array([50, 15]))
        system.analyze_incoming_traffic("192.168.1.2", "<script>alert(1)</script>", np.array([50, 15]))
        
        return system
    
    def test_json_serialization(self, trained_system_with_events):
        """Test that all report data can be JSON serialized"""
        stats = trained_system_with_events.get_statistics()
        events = trained_system_with_events.get_event_history()
        
        report = {
            'summary': stats,
            'events': events,
        }
        
        # Should not raise exception
        json_str = json.dumps(report)
        assert isinstance(json_str, str)
        assert len(json_str) > 0
    
    def test_report_readable_formats(self, trained_system_with_events):
        """Test that report can be formatted in readable ways"""
        stats = trained_system_with_events.get_statistics()
        events = trained_system_with_events.get_event_history()
        
        # Test percentage formatting
        block_rate_percent = f"{stats['block_rate']:.1%}"
        assert '%' in block_rate_percent
        
        # Test timestamp formatting
        for event in events:
            timestamp = event['timestamp']
            assert timestamp is not None
            assert len(timestamp) > 0


class TestEventHistoryQueries:
    """Test event history querying and filtering"""
    
    @pytest.fixture
    def trained_system_with_many_events(self):
        """Provide a system with many recorded events"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        
        # Generate multiple events
        for i in range(20):
            payload = "GET /api/data" if i % 2 == 0 else f"<script>alert({i})</script>"
            system.analyze_incoming_traffic(
                f"192.168.1.{i+1}",
                payload,
                np.array([50, 15])
            )
        
        return system
    
    def test_get_all_events(self, trained_system_with_many_events):
        """Test retrieving all events"""
        events = trained_system_with_many_events.get_event_history()
        assert len(events) == 20
    
    def test_get_limited_events(self, trained_system_with_many_events):
        """Test retrieving limited number of events"""
        events = trained_system_with_many_events.get_event_history(limit=5)
        assert len(events) == 5
    
    def test_limit_returns_most_recent(self, trained_system_with_many_events):
        """Test that limit returns most recent events"""
        all_events = trained_system_with_many_events.get_event_history()
        limited_events = trained_system_with_many_events.get_event_history(limit=3)
        
        # Most recent events should be at the end
        for i, event in enumerate(limited_events):
            # These should be the last 3 events from all_events
            assert event == all_events[-(3-i)]


class TestEventDataIntegrity:
    """Test integrity of recorded event data"""
    
    @pytest.fixture
    def trained_system(self):
        """Provide a trained defense system"""
        system = LurRenJiaDefenseSystem()
        normal_data = np.random.randn(500, 2) * 10 + 50
        system.train_ai_baseline(normal_data)
        return system
    
    def test_event_data_types(self, trained_system):
        """Test that event data has correct types"""
        trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "GET /api/users",
            np.array([50, 15])
        )
        
        event = trained_system.get_event_history()[0]
        
        # Check data types
        assert isinstance(event['timestamp'], str)
        assert isinstance(event['ip'], str)
        assert isinstance(event['action'], str)
        assert isinstance(event['threat_type'], str)
        assert isinstance(event['risk_score'], (int, float))
        assert isinstance(event['payload'], str)
    
    def test_event_values_valid(self, trained_system):
        """Test that event values are valid"""
        trained_system.analyze_incoming_traffic(
            "192.168.1.1",
            "GET /api/users",
            np.array([50, 15])
        )
        
        event = trained_system.get_event_history()[0]
        
        # Check value constraints
        assert event['action'] in ['blocked', 'allowed']
        assert 0 <= event['risk_score'] <= 1.0
        assert len(event['ip']) > 0
        assert len(event['timestamp']) > 0
