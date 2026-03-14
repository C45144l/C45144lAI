"""
場景: 保護 Flask/Django API 伺服器
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np
from flask import Flask, request, jsonify

app = Flask(__name__)
system = LurRenJiaDefenseSystem()

# 訓練系統
normal_api_traffic = np.random.randn(2000, 2) * 5 + 30
system.train_ai_baseline(normal_api_traffic)

@app.route('/api/data', methods=['POST'])
def protected_api():
    """受保護的 API 端點"""
    
    # 提取流量信息
    ip = request.remote_addr
    payload = request.get_json()
    
    # 模擬特徵提取（實際應用中應從網路堆疊提取）
    payload_size = len(str(payload))
    request_rate = 50  # 每秒請求數
    features = np.array([payload_size, request_rate])
    
    # 分析流量
    result = system.analyze_incoming_traffic(
        ip,
        str(payload),
        features
    )
    
    # 如果被封鎖，返回 403
    if result['action'] == 'blocked':
        return jsonify({
            'error': 'Access Denied',
            'reason': result['reason'],
            'risk_score': result['risk_score']
        }), 403
    
    # 允許通過
    return jsonify({'data': 'Success'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
