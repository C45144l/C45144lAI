#!/usr/bin/env python3
"""
Model Tuning Demo Script
AI 模型調參演示腳本

演示如何使用新的模型調參功能來優化威脅檢測性能
"""

import numpy as np
from src.defense_system import LurRenJiaDefenseSystem
import time


def demo_basic_tuning():
    """Demo 1: 基本模型調參"""
    print("\n" + "="*70)
    print("📊 Demo 1: 基本模型調參")
    print("="*70)
    
    system = LurRenJiaDefenseSystem()
    
    # 顯示默認參數
    print("\n🔹 默認模型參數:")
    system.print_model_info()
    
    # 增加 n_estimators 以提高準確性
    print("🔹 調整參數 - 提高 n_estimators 到 200:")
    system.set_model_params(n_estimators=200)
    
    # 訓練基線
    normal_data = np.random.randn(100, 5)
    system.train_ai_baseline(normal_data)
    
    # 顯示調整後的參數
    print("\n🔹 調整後的模型參數:")
    system.print_model_info()


def demo_preset_modes():
    """Demo 2: 使用預設調參模式"""
    print("\n" + "="*70)
    print("📊 Demo 2: 預設調參模式對比")
    print("="*70)
    
    modes = ['fast', 'balanced', 'accurate', 'sensitive', 'strict']
    results = {}
    
    for mode in modes:
        print(f"\n🔹 測試模式: {mode}")
        print("-" * 50)
        
        system = LurRenJiaDefenseSystem()
        system.tune_ai_model(mode)
        
        # 訓練
        normal_data = np.random.randn(100, 5)
        start_time = time.time()
        system.train_ai_baseline(normal_data)
        training_time = time.time() - start_time
        
        # 獲取統計信息
        stats = system.get_model_stats()
        results[mode] = {
            'n_estimators': stats['n_estimators'],
            'contamination': stats['contamination'],
            'training_time': training_time
        }
        
        print(f"  • n_estimators: {stats['n_estimators']}")
        print(f"  • contamination: {stats['contamination']}")
        print(f"  • 訓練時間: {training_time:.4f}s")
    
    # 摘要對比
    print("\n" + "="*50)
    print("📈 模式對比摘要:")
    print("="*50)
    for mode, result in results.items():
        print(f"\n{mode.upper()}:")
        print(f"  Estimators: {result['n_estimators']}, Contamination: {result['contamination']}, Time: {result['training_time']:.4f}s")


def demo_sensitivity_comparison():
    """Demo 3: 靈敏度對比 - 敏感 vs 嚴格"""
    print("\n" + "="*70)
    print("📊 Demo 3: 靈敏度對比 - 敏感 vs 嚴格")
    print("="*70)
    
    # 敏感模式系統
    system_sensitive = LurRenJiaDefenseSystem()
    system_sensitive.tune_ai_model('sensitive')
    
    # 嚴格模式系統
    system_strict = LurRenJiaDefenseSystem()
    system_strict.tune_ai_model('strict')
    
    # 訓練
    normal_data = np.random.randn(100, 5)
    system_sensitive.train_ai_baseline(normal_data)
    system_strict.train_ai_baseline(normal_data)
    
    print("\n🔹 模型配置:")
    print(f"  敏感模式 contamination: {system_sensitive.get_model_params()['contamination']}")
    print(f"  嚴格模式 contamination: {system_strict.get_model_params()['contamination']}")
    
    # 測試流量
    test_cases = [
        ("正常流量", np.array([1, 1, 1, 1, 1]), "GET /index.html"),
        ("中度可疑", np.array([3, 3, 3, 3, 3]), "SELECT * FROM users"),
        ("高度異常", np.array([8, 8, 8, 8, 8]), "DROP TABLE admin; --"),
    ]
    
    print("\n🔹 檢測結果對比:")
    print("-" * 70)
    
    for description, features, payload in test_cases:
        result_sensitive = system_sensitive.analyze_incoming_traffic(
            "192.168.1.1",
            payload,
            features
        )
        result_strict = system_strict.analyze_incoming_traffic(
            "192.168.1.2",
            payload,
            features
        )
        
        print(f"\n{description}: {payload[:30]}...")
        print(f"  敏感模式: {result_sensitive['action'].upper()} (風險: {result_sensitive['risk_score']:.2f})")
        print(f"  嚴格模式: {result_strict['action'].upper()} (風險: {result_strict['risk_score']:.2f})")


def demo_dynamic_retuning():
    """Demo 4: 動態重新調參"""
    print("\n" + "="*70)
    print("📊 Demo 4: 動態重新調參")
    print("="*70)
    
    system = LurRenJiaDefenseSystem()
    
    # 初始訓練
    normal_data = np.random.randn(100, 5)
    system.train_ai_baseline(normal_data)
    
    print("\n🔹 初始配置:")
    stats = system.get_model_stats()
    print(f"  n_estimators: {stats['n_estimators']}")
    print(f"  contamination: {stats['contamination']}")
    
    # 檢測一些流量
    result1 = system.analyze_incoming_traffic("192.168.1.1", "normal", np.array([1, 1, 1, 1, 1]))
    print(f"\n  初始檢測: {result1['action']}")
    
    # 發現誤報太多，切換到嚴格模式
    print("\n🔹 檢測到太多誤報，切換到嚴格模式...")
    system.tune_ai_model('strict')
    
    # 重新檢測
    result2 = system.analyze_incoming_traffic("192.168.1.2", "normal", np.array([1, 1, 1, 1, 1]))
    print(f"  嚴格模式檢測: {result2['action']}")
    
    # 發現漏報增多，調整到平衡模式
    print("\n🔹 發現漏報增多，調整到平衡模式...")
    system.tune_ai_model('balanced')
    
    # 最終檢測
    result3 = system.analyze_incoming_traffic("192.168.1.3", "normal", np.array([1, 1, 1, 1, 1]))
    print(f"  平衡模式檢測: {result3['action']}")
    
    print("\n✅ 動態調參完成！")


def demo_custom_parameters():
    """Demo 5: 自定義參數設置"""
    print("\n" + "="*70)
    print("📊 Demo 5: 自定義參數設置")
    print("="*70)
    
    system = LurRenJiaDefenseSystem()
    
    print("\n🔹 設置自定義參數組合:")
    print("  • n_estimators: 150")
    print("  • contamination: 0.12")
    
    result = system.set_model_params(
        n_estimators=150,
        contamination=0.12
    )
    
    print("\n✅ 參數更新完成")
    
    # 訓練
    normal_data = np.random.randn(100, 5)
    system.train_ai_baseline(normal_data)
    
    # 顯示最終參數
    print("\n🔹 最終模型參數:")
    system.print_model_info()


def demo_batch_analysis_performance():
    """Demo 6: 批量分析性能測試"""
    print("\n" + "="*70)
    print("📊 Demo 6: 批量分析性能測試")
    print("="*70)
    
    batch_sizes = [10, 50, 100]
    
    for batch_size in batch_sizes:
        print(f"\n🔹 測試批量大小: {batch_size}")
        
        # 創建系統
        system = LurRenJiaDefenseSystem()
        system.tune_ai_model('accurate')
        
        # 訓練
        normal_data = np.random.randn(100, 5)
        system.train_ai_baseline(normal_data)
        
        # 生成批量數據
        traffic_data = [
            {
                'ip': f'192.168.1.{i % 254 + 1}',
                'payload': f'request_{i}',
                'features': np.random.randn(5)
            }
            for i in range(batch_size)
        ]
        
        # 執行批量分析
        start_time = time.time()
        results = system.batch_analyze(traffic_data)
        elapsed = time.time() - start_time
        
        # 統計
        blocked_count = sum(1 for r in results if r['action'] == 'blocked')
        
        print(f"  • 分析時間: {elapsed:.4f}s")
        print(f"  • 每個流量: {(elapsed/batch_size)*1000:.2f}ms")
        print(f"  • 被阻止: {blocked_count}/{batch_size}")


def main():
    """Run all demos"""
    print("\n" + "="*70)
    print("🎯 C45144lAI AI 模型調參演示")
    print("="*70)
    
    try:
        demo_basic_tuning()
        demo_preset_modes()
        demo_sensitivity_comparison()
        demo_dynamic_retuning()
        demo_custom_parameters()
        demo_batch_analysis_performance()
        
        print("\n" + "="*70)
        print("✅ 所有演示完成！")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Demo 執行出錯: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
