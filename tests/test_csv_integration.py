"""
Test suite for CSV data integration module
"""

import pytest
import pandas as pd
import numpy as np
import os
from csv_traffic_analyzer import TrafficDataProcessor, CSVTrafficAnalyzer, generate_sample_traffic_csv


class TestTrafficDataProcessor:
    """Test CSV data processing"""
    
    @pytest.fixture
    def sample_csv(self):
        """Create a sample CSV for testing"""
        data = {
            'packet_size': [50, 52, 48, 55, 60],
            'request_rate': [15, 18, 12, 20, 25],
            'source_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'],
            'payload': ['GET /api/data', 'POST /api/data', 'GET /api/users', 'GET /api/config', 'DELETE /api/data']
        }
        df = pd.DataFrame(data)
        csv_file = 'test_traffic.csv'
        df.to_csv(csv_file, index=False)
        yield csv_file
        # Cleanup
        if os.path.exists(csv_file):
            os.remove(csv_file)
    
    def test_load_csv(self, sample_csv):
        """Test CSV loading"""
        processor = TrafficDataProcessor(sample_csv)
        df = processor.load_csv()
        assert len(df) == 5
        assert list(df.columns) == ['packet_size', 'request_rate', 'source_ip', 'payload']
    
    def test_extract_features(self, sample_csv):
        """Test feature extraction"""
        processor = TrafficDataProcessor(sample_csv)
        processor.load_csv()
        features = processor.extract_features()
        
        assert features.shape == (5, 2)
        assert np.issubdtype(features.dtype, np.number)
    
    def test_validate_data(self, sample_csv):
        """Test data validation"""
        processor = TrafficDataProcessor(sample_csv)
        processor.load_csv()
        assert processor.validate_data() is True
    
    def test_get_statistics(self, sample_csv):
        """Test statistics extraction"""
        processor = TrafficDataProcessor(sample_csv)
        processor.load_csv()
        stats = processor.get_statistics()
        
        assert stats['total_rows'] == 5
        assert stats['total_columns'] == 4
        assert 'packet_size' in stats['column_names']


class TestCSVTrafficAnalyzer:
    """Test CSV traffic analysis"""
    
    @pytest.fixture
    def sample_csv(self):
        """Create a sample CSV for testing"""
        data = {
            'packet_size': np.random.normal(50, 5, 30),
            'request_rate': np.random.normal(15, 3, 30),
            'source_ip': [f'192.168.1.{i}' for i in range(30)],
            'payload': ['GET /api/data'] * 25 + ["'; DROP TABLE users; --"] * 5
        }
        df = pd.DataFrame(data)
        csv_file = 'test_analyzer.csv'
        df.to_csv(csv_file, index=False)
        yield csv_file
        # Cleanup
        if os.path.exists(csv_file):
            os.remove(csv_file)
        if os.path.exists('analysis_results.csv'):
            os.remove('analysis_results.csv')
    
    def test_analyze_csv_traffic(self, sample_csv):
        """Test CSV traffic analysis"""
        analyzer = CSVTrafficAnalyzer()
        results = analyzer.analyze_csv_traffic(sample_csv)
        
        assert len(results) == 30
        assert all('ip' in r for r in results)
        assert all('action' in r for r in results)
        assert all('threat_type' in r for r in results)
    
    def test_get_summary(self, sample_csv):
        """Test analysis summary"""
        analyzer = CSVTrafficAnalyzer()
        analyzer.analyze_csv_traffic(sample_csv)
        summary = analyzer.get_summary()
        
        assert summary is not None
        assert 'total_analyzed' in summary
        assert 'blocked' in summary
        assert 'allowed' in summary
        assert 'block_rate' in summary
    
    def test_export_results_csv(self, sample_csv):
        """Test results export"""
        analyzer = CSVTrafficAnalyzer()
        analyzer.analyze_csv_traffic(sample_csv)
        analyzer.export_results_csv('test_results.csv')
        
        assert os.path.exists('test_results.csv')
        
        # Verify exported data
        df = pd.read_csv('test_results.csv')
        assert len(df) == 30
        
        # Cleanup
        os.remove('test_results.csv')


class TestSampleDataGeneration:
    """Test sample data generation"""
    
    def test_generate_sample_traffic_csv(self):
        """Test sample CSV generation"""
        csv_file = 'test_sample.csv'
        df = generate_sample_traffic_csv(csv_file, num_records=50)
        
        # Allow for slight deviation due to rounding in sample generation
        assert 45 <= len(df) <= 50
        assert 'source_ip' in df.columns
        assert 'payload' in df.columns
        assert 'packet_size' in df.columns
        assert 'request_rate' in df.columns
        
        # Verify normal and attack traffic mix
        normal_count = (df['payload'].str.startswith('GET')).sum()
        assert normal_count > 0
        
        # Cleanup
        os.remove(csv_file)


class TestDataIntegration:
    """Test integration between components"""
    
    def test_full_workflow(self):
        """Test complete workflow from CSV to analysis"""
        # Generate sample data
        csv_file = 'test_workflow.csv'
        df = generate_sample_traffic_csv(csv_file, num_records=40)
        generated_count = len(df)
        
        try:
            # Load and process
            processor = TrafficDataProcessor(csv_file)
            data = processor.load_csv()
            assert len(data) == generated_count
            
            # Analyze
            analyzer = CSVTrafficAnalyzer()
            results = analyzer.analyze_csv_traffic(csv_file)
            assert len(results) == generated_count
            
            # Get summary
            summary = analyzer.get_summary()
            assert summary['total_analyzed'] == generated_count
            
        finally:
            # Cleanup
            if os.path.exists(csv_file):
                os.remove(csv_file)
            if os.path.exists('analysis_results.csv'):
                os.remove('analysis_results.csv')
