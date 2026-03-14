#!/usr/bin/env python3
"""
Test suite for AI model tuning and parameter optimization
AI 模型調參測試套件
"""

import pytest
import numpy as np
from src.defense_system import LurRenJiaDefenseSystem


class TestModelInitialization:
    """Test model initialization with different parameters"""
    
    def test_default_initialization(self):
        """Test default model initialization"""
        system = LurRenJiaDefenseSystem()
        
        assert system.model is not None
        assert system.trained == False
        assert system.baseline is None
        
        params = system.get_model_params()
        assert params['n_estimators'] == 100  # Default IsolationForest value
        assert params['contamination'] == 0.1
    
    def test_custom_contamination(self):
        """Test initialization with custom contamination"""
        system = LurRenJiaDefenseSystem(contamination=0.2)
        
        params = system.get_model_params()
        assert params['contamination'] == 0.2


class TestSetModelParams:
    """Test set_model_params method"""
    
    def test_set_single_param(self):
        """Test setting a single parameter"""
        system = LurRenJiaDefenseSystem()
        
        result = system.set_model_params(n_estimators=200)
        
        assert result['n_estimators'] == 200
        assert system.get_model_params()['n_estimators'] == 200
    
    def test_set_multiple_params(self):
        """Test setting multiple parameters"""
        system = LurRenJiaDefenseSystem()
        
        result = system.set_model_params(
            n_estimators=150,
            contamination=0.15
        )
        
        params = system.get_model_params()
        assert params['n_estimators'] == 150
        assert params['contamination'] == 0.15
    
    def test_params_persist_after_set(self):
        """Test that parameters persist after setting"""
        system = LurRenJiaDefenseSystem()
        
        system.set_model_params(n_estimators=250)
        params1 = system.get_model_params()
        params2 = system.get_model_params()
        
        assert params1['n_estimators'] == params2['n_estimators'] == 250
    
    def test_retrain_after_set_params(self):
        """Test that model retrains after setting parameters with baseline"""
        system = LurRenJiaDefenseSystem()
        
        # Train initial baseline
        normal_data = np.random.randn(50, 5)
        system.train_ai_baseline(normal_data)
        
        assert system.trained == True
        
        # Change parameters
        system.set_model_params(n_estimators=200)
        
        assert system.trained == True
        assert system.get_model_params()['n_estimators'] == 200


class TestGetModelParams:
    """Test get_model_params method"""
    
    def test_get_default_params(self):
        """Test getting default model parameters"""
        system = LurRenJiaDefenseSystem()
        
        params = system.get_model_params()
        
        assert 'n_estimators' in params
        assert 'contamination' in params
        assert 'random_state' in params
        assert params['random_state'] == 42
    
    def test_get_params_returns_dict(self):
        """Test that get_model_params returns a dictionary"""
        system = LurRenJiaDefenseSystem()
        
        params = system.get_model_params()
        
        assert isinstance(params, dict)
        assert len(params) > 0


class TestTuneAIModel:
    """Test tune_ai_model method with presets"""
    
    def test_fast_mode(self):
        """Test fast tuning mode"""
        system = LurRenJiaDefenseSystem()
        
        result = system.tune_ai_model('fast')
        
        assert result['n_estimators'] == 50
        assert result['contamination'] == 0.1
    
    def test_balanced_mode(self):
        """Test balanced tuning mode"""
        system = LurRenJiaDefenseSystem()
        
        result = system.tune_ai_model('balanced')
        
        assert result['n_estimators'] == 100
        assert result['contamination'] == 0.1
    
    def test_accurate_mode(self):
        """Test accurate tuning mode"""
        system = LurRenJiaDefenseSystem()
        
        result = system.tune_ai_model('accurate')
        
        assert result['n_estimators'] == 200
        assert result['contamination'] == 0.1
    
    def test_sensitive_mode(self):
        """Test sensitive tuning mode"""
        system = LurRenJiaDefenseSystem()
        
        result = system.tune_ai_model('sensitive')
        
        assert result['n_estimators'] == 100
        assert result['contamination'] == 0.15
    
    def test_strict_mode(self):
        """Test strict tuning mode"""
        system = LurRenJiaDefenseSystem()
        
        result = system.tune_ai_model('strict')
        
        assert result['n_estimators'] == 100
        assert result['contamination'] == 0.05
    
    def test_invalid_mode_raises_error(self):
        """Test that invalid mode raises ValueError"""
        system = LurRenJiaDefenseSystem()
        
        with pytest.raises(ValueError):
            system.tune_ai_model('nonexistent_mode')
    
    def test_tune_with_baseline_retrains(self):
        """Test that tuning with baseline retrains model"""
        system = LurRenJiaDefenseSystem()
        
        # Train initial baseline
        normal_data = np.random.randn(50, 5)
        system.train_ai_baseline(normal_data)
        
        initial_trained = system.trained
        
        # Retune
        system.tune_ai_model('accurate')
        
        assert system.trained == True
        assert system.get_model_params()['n_estimators'] == 200


class TestGetModelStats:
    """Test get_model_stats method"""
    
    def test_get_stats_before_training(self):
        """Test getting stats before training"""
        system = LurRenJiaDefenseSystem()
        
        stats = system.get_model_stats()
        
        assert stats['trained'] == False
        assert stats['baseline_size'] == 0
        assert stats['model_type'] == 'IsolationForest'
    
    def test_get_stats_after_training(self):
        """Test getting stats after training"""
        system = LurRenJiaDefenseSystem()
        
        normal_data = np.random.randn(100, 5)
        system.train_ai_baseline(normal_data)
        
        stats = system.get_model_stats()
        
        assert stats['trained'] == True
        assert stats['baseline_size'] == 100
        assert stats['n_estimators'] == 100
        assert stats['contamination'] == 0.1
    
    def test_stats_include_all_fields(self):
        """Test that stats include all expected fields"""
        system = LurRenJiaDefenseSystem()
        
        stats = system.get_model_stats()
        
        assert 'model_type' in stats
        assert 'trained' in stats
        assert 'baseline_size' in stats
        assert 'n_estimators' in stats
        assert 'contamination' in stats
        assert 'random_state' in stats
        assert 'n_jobs' in stats


class TestIntegrationWithAnalysis:
    """Test that model tuning works with threat analysis"""
    
    def test_analysis_after_tuning(self):
        """Test threat analysis after model tuning"""
        system = LurRenJiaDefenseSystem()
        
        # Train baseline
        normal_data = np.random.randn(50, 5)
        system.train_ai_baseline(normal_data)
        
        # Tune to accurate mode
        system.tune_ai_model('accurate')
        
        # Analyze traffic
        result = system.analyze_incoming_traffic(
            "192.168.1.1",
            "normal request",
            np.array([1, 1, 1, 1, 1])
        )
        
        assert 'threat_type' in result
        assert 'risk_score' in result
        assert 'action' in result
    
    def test_analysis_sensitive_vs_strict(self):
        """Test different sensitivity modes detect different things"""
        system_sensitive = LurRenJiaDefenseSystem()
        system_strict = LurRenJiaDefenseSystem()
        
        # Train both
        normal_data = np.random.randn(50, 5)
        system_sensitive.train_ai_baseline(normal_data)
        system_strict.train_ai_baseline(normal_data)
        
        # Apply different tuning
        system_sensitive.tune_ai_model('sensitive')
        system_strict.tune_ai_model('strict')
        
        # Analyze same suspicious traffic
        suspicious_features = np.array([10, 10, 10, 10, 10])
        
        result_sensitive = system_sensitive.analyze_incoming_traffic(
            "192.168.1.1",
            "suspicious request",
            suspicious_features
        )
        
        result_strict = system_strict.analyze_incoming_traffic(
            "192.168.1.1",
            "suspicious request",
            suspicious_features
        )
        
        # Sensitive mode should have higher contamination rate
        # (more likely to flag things as anomalies)
        assert result_sensitive is not None
        assert result_strict is not None


class TestModelPerformance:
    """Test model performance with different configurations"""
    
    def test_fast_mode_performance(self):
        """Test fast mode completes quickly"""
        system = LurRenJiaDefenseSystem()
        system.tune_ai_model('fast')
        
        normal_data = np.random.randn(1000, 5)
        system.train_ai_baseline(normal_data)
        
        assert system.trained == True
    
    def test_accurate_mode_performance(self):
        """Test accurate mode with more estimators"""
        system = LurRenJiaDefenseSystem()
        system.tune_ai_model('accurate')
        
        normal_data = np.random.randn(1000, 5)
        system.train_ai_baseline(normal_data)
        
        assert system.trained == True
        assert system.get_model_params()['n_estimators'] == 200
    
    def test_batch_analysis_with_tuned_model(self):
        """Test batch analysis with tuned model"""
        system = LurRenJiaDefenseSystem()
        system.tune_ai_model('accurate')
        
        normal_data = np.random.randn(50, 5)
        system.train_ai_baseline(normal_data)
        
        # Create proper batch data with required fields
        traffic_data = [
            {
                'ip': f'192.168.1.{i}',
                'payload': f'request_{i}',
                'features': np.random.randn(5)
            }
            for i in range(10)
        ]
        
        results = system.batch_analyze(traffic_data)
        
        assert len(results) == 10
        assert all('action' in r for r in results)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
