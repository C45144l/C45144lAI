import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class LurRenJiaDefenseSystem:
    """C45144lAI Defense System - AI-powered network defense"""
    
    def __init__(self, contamination=0.1):
        """
        Initialize the defense system
        
        Args:
            contamination: Expected proportion of outliers/attacks
        """
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.trained = False
        self.baseline = None
        self.event_history = []  # Store all security events
        self.threat_patterns = {}  # Custom threat patterns dictionary
        self._initialize_threat_patterns()  # Load default threat patterns
        self.statistics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'anomalies_detected': 0
        }
        
    def train_ai_baseline(self, normal_data):
        """
        Train the AI model on normal traffic patterns
        
        Args:
            normal_data: Array of normal traffic features
        """
        # Normalize the data
        self.baseline = self.scaler.fit_transform(normal_data)
        
        # Train the anomaly detection model
        self.model.fit(self.baseline)
        self.trained = True
        print(f"✅ AI baseline trained on {len(normal_data)} normal traffic samples")
    
    def _initialize_threat_patterns(self):
        """
        Initialize default threat patterns with regex rules
        
        This method can be called to reset to default patterns or
        to combine with custom patterns
        """
        import re
        
        self.threat_patterns = {
            'SQL_INJECTION': [
                r"(?i)(drop|delete|insert|truncate|exec|execute|union|select).*(\"|'|;)",
                r"(?i)(-{2}|#|/\*|\*/|xp_|sp_)",
                r"(?i)(union.*select|select.*from|where.*=)",
                r"(?i)('.*or.*1.*=.*1|'.*or.*'.*=.*')",
            ],
            'XSS': [
                r"(?i)(<script|javascript:)",
                r"(?i)(onerror|onload|onclick|onmouseover)=",
                r"(?i)(<iframe|<img.*src)",
                r"(?i)(eval\(|alert\(|prompt\()",
            ],
            'XSS_ENCODED': [
                r"(%2e%2e%2f|%252e|%3cscript|%3ciframe|%3c)",
                r"(&#x|&#[0-9])",
                r"(\\x|\\u00)",
            ],
            'COMMAND_INJECTION': [
                r"(?i)(cat\s+/etc|/bin/bash|/bin/sh|bash\s+-i)",
                r"(?i)(/dev/tcp|nc\s+-|ncat)",
                r"(?i)(curl\|bash|wget\|python|curl\|python)",
                r"(?i)(whoami|id\s+|uname\s+-)",
            ],
            'RCE': [
                r"(?i)(exec|system|passthru|shell_exec|backtick)",
                r"(?i)(\$_\[|getenv|putenv)",
                r"(?i)(os\.system|subprocess|popen)",
            ],
            'PATH_TRAVERSAL': [
                r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
                r"(%2e%2e/|%252e%252e)",
            ],
            'MALWARE': [
                r"(?i)(\.(exe|dll|bat|com|scr|vbs|js|zip|rar)\.?)",
                r"(?i)(trojan|ransomware|backdoor|worm|virus)",
            ],
        }
    
    def add_custom_threat(self, threat_name, patterns):
        """
        Add or update custom threat patterns
        
        Args:
            threat_name: Name of the threat (e.g., 'custom_threat')
            patterns: List of regex patterns to match this threat
            
        Example:
            system.add_custom_threat('custom_threat', [
                r'你的正則表達式1',
                r'你的正則表達式2',
            ])
        """
        if not isinstance(patterns, list):
            patterns = [patterns]
        
        self.threat_patterns[threat_name] = patterns
        print(f"✅ 自定義威脅模式已添加: {threat_name}")
        print(f"   📊 模式數量: {len(patterns)}")
    
    def get_threat_patterns(self):
        """Get all current threat patterns"""
        return self.threat_patterns.copy()
    
    def _detect_threat_type(self, payload, features):
        """Detect the type of threat in the payload with enhanced detection"""
        payload_lower = payload.lower()
        threat_scores = {}
        
        # ===== 危險程度 1: 關鍵威脅 (SQL + RCE + APT) =====
        
        # 1. SQL 注入檢測 (包括編碼和繞過)
        sql_danger_keywords = ["drop", "delete", "insert", "truncate", "exec", "execute", "union"]
        sql_evasion_keywords = ["/*!", "*/", "--", "#", "xp_", "sp_"]
        sql_patterns = ["'", "\"", ";"]
        
        sql_danger_count = sum(1 for pattern in sql_danger_keywords if pattern in payload_lower)
        sql_evasion_count = sum(1 for pattern in sql_evasion_keywords if pattern in payload_lower)
        sql_quote_count = sum(1 for pattern in sql_patterns if pattern in payload)
        
        if sql_danger_count > 0 or (sql_evasion_count > 0 and sql_quote_count > 0):
            threat_scores["SQL_INJECTION"] = 0.95 + (sql_danger_count * 0.05)  # 基礎 95% + 危險度加成
        elif sql_quote_count >= 2 and any(kw in payload_lower for kw in ["or", "and", "="]):
            threat_scores["SQL_INJECTION"] = 0.85
        
        # 2. 遠端代碼執行 (RCE) - 最危險
        rce_patterns = ["cat /etc/", "whoami", "nc -l", "bash -i", "sh -i", "/dev/tcp", "curl|bash", "wget|python"]
        if any(pattern in payload_lower for pattern in rce_patterns):
            threat_scores["COMMAND_INJECTION"] = 0.99  # 極度危險
        else:
            cmd_basic = [";", "|", "&&", "||"]
            if sum(1 for pattern in cmd_basic if pattern in payload_lower) >= 2:
                threat_scores["COMMAND_INJECTION"] = 0.90
        
        # 3. APT 潛行特徵 - 極度可疑
        if features[1] > 5000:  # 超大延遲 = 超大單次數據傳輸
            threat_scores["APT_EXFILTRATION"] = 0.98
        elif features[1] > 1000:
            threat_scores["APT_EXFILTRATION"] = 0.92
        
        # ===== 危險程度 2: 高風險威脅 (XSS + 暴力破解) =====
        
        # 4. XSS 攻擊檢測 (包括多種編碼)
        xss_dangerous = ["<iframe", "<img", "<svg", "onerror=", "onload=", "onclick="]
        xss_basic = ["<script", "alert(", "eval("]
        
        if any(pattern in payload_lower for pattern in xss_dangerous):
            threat_scores["XSS"] = 0.88
        elif any(pattern in payload_lower for pattern in xss_basic):
            threat_scores["XSS"] = 0.85
        
        # URL 編碼檢測
        url_encoded_dangerous = ["%2e%2e%2f", "%252e", "%3cscript", "%3ciframe"]
        if any(encoded in payload_lower for encoded in url_encoded_dangerous):
            threat_scores["XSS_ENCODED"] = 0.87
        
        # 5. 暴力破解 + DoS 檢測
        if (features[0] > 5000 and features[1] < 50) or (features[1] > 100 and "login" in payload_lower):
            threat_scores["BRUTE_FORCE"] = 0.92  # 高頻率短連接 = 暴力破解
        elif features[0] > 1000:
            threat_scores["BRUTE_FORCE"] = 0.85
        
        # ===== 危險程度 3: 中風險威脅 =====
        
        # 6. 惡意程式檢測
        malware_extensions = [".exe", ".dll", ".bat", ".com", ".scr", ".vbs", ".js."]
        if any(exe in payload_lower for exe in malware_extensions):
            threat_scores["MALWARE"] = 0.88
        
        # 7. 異常流量檢測 (DDoS/大流量攻擊)
        if features[0] > 8000 or features[1] > 3000:
            threat_scores["ABNORMAL_TRAFFIC"] = 0.80
        elif features[0] > 500 or features[1] > 500:
            threat_scores["ABNORMAL_TRAFFIC"] = 0.70
        
        # 8. 混合型攻擊 (多個威脅組合)
        if len(threat_scores) > 1:
            # 多個威脅並存 = 更危險的攻擊
            max_threat = max(threat_scores.values())
            threat_scores["MULTI_VECTOR_ATTACK"] = min(0.99, max_threat + 0.10)
        
        # 返回最高風險的威脅類型
        if threat_scores:
            return max(threat_scores, key=threat_scores.get)
        
        return "UNKNOWN"
    
    def _calculate_enhanced_risk_score(self, threat_type, anomaly_score, payload, features):
        """Calculate enhanced risk score based on threat type and features"""
        base_score = min(1.0, max(0.0, -anomaly_score))
        
        # 威脅類型風險係數
        threat_multipliers = {
            "SQL_INJECTION": 1.4,
            "COMMAND_INJECTION": 1.5,
            "APT_EXFILTRATION": 1.45,
            "BRUTE_FORCE": 1.3,
            "XSS": 1.2,
            "XSS_ENCODED": 1.25,
            "MALWARE": 1.35,
            "ABNORMAL_TRAFFIC": 1.1,
            "MULTI_VECTOR_ATTACK": 1.6,
            "UNKNOWN": 1.0
        }
        
        multiplier = threat_multipliers.get(threat_type, 1.0)
        enhanced_score = min(0.99, base_score * multiplier)
        
        # 特徵加成 (特別危險的流量特徵)
        if features[0] > 5000 or features[1] > 5000:
            enhanced_score = min(0.99, enhanced_score + 0.15)
        elif features[0] > 1000 or features[1] > 1000:
            enhanced_score = min(0.99, enhanced_score + 0.08)
        
        return enhanced_score
        
    def analyze_incoming_traffic(self, ip, payload, traffic_features):
        """
        Analyze incoming traffic and determine if it's an attack
        
        Args:
            ip: Source IP address
            payload: Request payload
            traffic_features: Array of traffic features [size, latency, etc.]
            
        Returns:
            Dictionary with analysis results
        """
        self.statistics['total_requests'] += 1
        
        if not self.trained:
            return {
                "action": "blocked",
                "reason": "System not trained",
                "threat_type": "UNKNOWN",
                "risk_score": 0.0
            }
        
        # Normalize the incoming features
        features_normalized = self.scaler.transform([traffic_features])
        
        # Predict: -1 for anomaly, 1 for normal
        prediction = self.model.predict(features_normalized)[0]
        
        # Get anomaly score
        anomaly_score = self.model.score_samples(features_normalized)[0]
        
        # Detect threat type (enhanced)
        threat_type = self._detect_threat_type(payload, traffic_features)
        
        # Calculate enhanced risk score
        risk_score = self._calculate_enhanced_risk_score(threat_type, anomaly_score, payload, traffic_features)
        
        # Enhanced decision logic - lower threshold for high-risk threats
        threat_risk_thresholds = {
            "SQL_INJECTION": 0.50,
            "COMMAND_INJECTION": 0.45,
            "APT_EXFILTRATION": 0.50,
            "BRUTE_FORCE": 0.55,
            "MALWARE": 0.55,
            "MULTI_VECTOR_ATTACK": 0.40
        }
        
        threshold = threat_risk_thresholds.get(threat_type, 0.65)
        
        # Determine action based on prediction and enhanced risk score
        if prediction == -1 or risk_score > threshold:
            action = "blocked"
            self.statistics['blocked_requests'] += 1
            self.statistics['anomalies_detected'] += 1
            
            # Generate detailed reason
            if threat_type == "SQL_INJECTION":
                reason = "SQL injection pattern detected - CRITICAL"
            elif threat_type == "COMMAND_INJECTION":
                reason = "Remote code execution attempt detected - CRITICAL"
            elif threat_type == "APT_EXFILTRATION":
                reason = "APT exfiltration pattern detected - SEVERE"
            elif threat_type == "BRUTE_FORCE":
                reason = "Brute force attack detected - HIGH"
            elif threat_type == "MULTI_VECTOR_ATTACK":
                reason = "Multi-vector attack detected - CRITICAL"
            elif threat_type == "XSS" or threat_type == "XSS_ENCODED":
                reason = "Cross-site scripting detected - HIGH"
            elif threat_type == "MALWARE":
                reason = "Malware signature detected - HIGH"
            elif threat_type == "ABNORMAL_TRAFFIC":
                reason = "Abnormal traffic pattern detected - MEDIUM"
            else:
                reason = f"Anomaly detected (score: {anomaly_score:.2f}) - Risk: {risk_score:.1%}"
        else:
            action = "allowed"
            self.statistics['allowed_requests'] += 1
            reason = "Normal traffic pattern"
        
        result = {
            "ip": ip,
            "action": action,
            "payload": payload,
            "anomaly_score": float(anomaly_score),
            "prediction": int(prediction),
            "confidence": abs(float(anomaly_score)),
            "threat_type": threat_type,
            "risk_score": risk_score,
            "reason": reason,
            "severity": self._get_severity_level(threat_type, risk_score)
        }
        
        # Record event to history
        from datetime import datetime
        self.event_history.append({
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "action": action,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "payload": payload[:100]  # Store first 100 chars of payload
        })
        
        return result
    
    def _get_severity_level(self, threat_type, risk_score):
        """Determine severity level based on threat type and risk score"""
        severity_map = {
            "COMMAND_INJECTION": "🔴 CRITICAL",
            "SQL_INJECTION": "🔴 CRITICAL",
            "MULTI_VECTOR_ATTACK": "🔴 CRITICAL",
            "APT_EXFILTRATION": "🟠 SEVERE",
            "BRUTE_FORCE": "🟠 HIGH",
            "MALWARE": "🟠 HIGH",
            "XSS": "🟡 MEDIUM-HIGH",
            "XSS_ENCODED": "🟡 MEDIUM-HIGH",
            "ABNORMAL_TRAFFIC": "🟡 MEDIUM",
            "UNKNOWN": "🔵 LOW"
        }
        
        return severity_map.get(threat_type, "🔵 LOW")
    
    def batch_analyze(self, traffic_data):
        """
        Analyze multiple traffic records at once
        
        Args:
            traffic_data: List of dicts with 'ip', 'payload', 'features'
            
        Returns:
            List of analysis results
        """
        results = []
        for data in traffic_data:
            result = self.analyze_incoming_traffic(
                data['ip'],
                data['payload'],
                data['features']
            )
            results.append(result)
        
        return results
    
    def get_statistics(self):
        """Get monitoring statistics"""
        total = self.statistics['total_requests']
        blocked = self.statistics['blocked_requests']
        
        block_rate = blocked / total if total > 0 else 0
        
        return {
            'total_requests': total,
            'blocked_requests': blocked,
            'allowed_requests': self.statistics['allowed_requests'],
            'block_rate': block_rate,
            'anomalies_detected': self.statistics['anomalies_detected']
        }
    
    def get_event_history(self, limit=None):
        """
        Get event history (all recorded security events)
        
        Args:
            limit: Maximum number of events to return (None for all)
            
        Returns:
            List of events, most recent first
        """
        if limit:
            return self.event_history[-limit:]
        return self.event_history
