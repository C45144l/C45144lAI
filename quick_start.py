from src.defense_system import LurRenJiaDefenseSystem
import numpy as np

# 初始化
system = LurRenJiaDefenseSystem()

# 訓練（模擬正常流量）
normal_data = np.random.randn(1000, 2) * 10 + 50
system.train_ai_baseline(normal_data)

# 分析流量
result = system.analyze_incoming_traffic(
    ip="192.168.1.100",
    payload="GET /index.html",
    traffic_features=np.array([52, 12])
)

print(f"✅ 結果: {result['action']}")  # 'allowed' 或 'blocked'
