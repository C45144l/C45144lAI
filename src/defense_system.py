"""
C45144lAI Defense System - National Defense Grade AI-Powered Hybrid Network Defense
Enhanced with military-grade threat detection, zero-day analysis, and APT attribution

Security Classification: TOP SECRET // SCI
NIST 800-53 Compliant | MITRE ATT&CK Full Coverage | Cyber Kill Chain Integrated
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
from typing import Dict, List, Tuple, Optional, Any, Union
from datetime import datetime
from functools import lru_cache
import hashlib
import threading
import re
import ipaddress
from collections import deque
from urllib.parse import unquote
import base64
import os
from pathlib import Path

# 優先使用進階解碼器（可選）
try:
    from src.advanced_enhancements import AdvancedPayloadDecoder
except Exception:
    AdvancedPayloadDecoder = None
import yaml

from src.time_series_anomaly_detector import TimeSeriesAnomalyDetector

# 遠端日誌（延遲匯入，僅在啟用時載入）
try:
    from src.remote_logging import RemoteLogger
except ImportError:
    RemoteLogger = None

# 國防級威脅偵測引擎
try:
    from src.national_defense_engine import (
        NationalDefenseEngine,
        SecurityClassification,
        APTGroupSignatures,
        CriticalInfrastructurePatterns,
        SupplyChainAttackDetector,
        CryptoProtocolDetector,
        InformationWarfareDetector,
        NetworkForensicsPatterns,
        ZeroDayBehaviorDetector,
    )
    NATIONAL_DEFENSE_AVAILABLE = True
except ImportError:
    NATIONAL_DEFENSE_AVAILABLE = False

# 型別提示
ThreatPattern = Dict[str, List[str]]
TrafficFeatures = Union[np.ndarray, List[float]]
AnalysisResult = Dict[str, Any]


class LurRenJiaDefenseSystem:
    """C45144lAI Defense System - National Defense Grade AI-powered network defense
    
    Security Level: TOP SECRET // SCI
    Capabilities:
    - 16+ base threat types + 50+ national defense threat categories
    - APT nation-state group attribution (APT28/29/38/40/41, SANDWORM, TURLA, etc.)
    - Critical infrastructure protection (SCADA/ICS/Power Grid/Water/Nuclear/Telecom)
    - Zero-day behavioral analysis with Kill Chain tracking
    - Supply chain attack detection
    - Cryptographic & protocol attack detection
    - Information warfare & cognitive operations detection
    - Network forensics deep packet inspection patterns
    - MITRE ATT&CK full tactic coverage (14 tactics)
    - Lockheed Martin Cyber Kill Chain (7 phases)
    - NIST 800-53 / NATO STANAG compliance ready
    """
    
    def __init__(self, contamination: float = 0.1, enable_caching: bool = True,
                 enable_threading: bool = True, remote_logger=None,
                 enable_national_defense: bool = False):
        """
        Initialize the defense system
        
        Args:
            contamination: Expected proportion of outliers/attacks (default: 0.1)
            enable_caching: Enable pattern matching cache for performance (default: True)
            enable_threading: Enable thread-safe operations (default: True)
            remote_logger: Optional RemoteLogger instance for real-time remote logging
        """
        # Setup logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
        # AI Model Configuration
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
        self.trained = False
        self.baseline = None
        self.time_series_detector = TimeSeriesAnomalyDetector(window_seconds=600)
        self.time_series_feature_names = [
            'request_count_window',
            'avg_interarrival_sec',
            'interarrival_std_sec',
            'avg_packet_size',
            'packet_size_change_rate'
        ]
        
        # Security Features
        self.event_history: deque = deque(maxlen=10000)  # 有界事件歷史，防止記憶體洩漏
        self.threat_patterns: ThreatPattern = {}
        self._compiled_threat_patterns: Dict[str, List[re.Pattern]] = {}
        self._compiled_whitelist_patterns: List[re.Pattern] = []
        self._compiled_pattern_snapshot = None
        self._initialize_threat_patterns()
        
        # IP 信譽系統
        self._ip_scores: Dict[str, float] = {}       # IP → 累積風險分數
        self._ip_violations: Dict[str, int] = {}     # IP → 違規次數
        self._ip_blacklist: set = set()               # 永久封鎖 IP
        self._ip_whitelist: set = set()               # 白名單 IP（跳過檢查）
        self._path_whitelist: List[str] = []          # 路徑白名單模式
        
        # Performance Features
        self.enable_caching = enable_caching
        self._cache: Dict[str, Tuple[bool, str, List[str]]] = {}
        self._cache_lock = threading.Lock() if enable_threading else None
        
        # Statistics
        self.statistics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'anomalies_detected': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Threat Severity Levels (Updated)
        self.threat_severity = {
            "COMMAND_INJECTION": 10,
            "SQL_INJECTION": 10,
            "MULTI_VECTOR_ATTACK": 10,
            "APT_EXFILTRATION": 9,
            "RCE": 10,
            "REVERSE_SHELL": 9,
            "BRUTE_FORCE": 8,
            "MALWARE": 8,
            "PATH_TRAVERSAL": 8,
            "XSS": 7,
            "XSS_ENCODED": 7,
            "ABNORMAL_TRAFFIC": 5,
            "financial_threats": 9,
            "healthcare_threats": 9,
            "government_threats": 10,
            "crypto_threats": 9,
            "intellectual_property": 8,
            "UNKNOWN": 2
        }
        
        # Remote Logging
        self._remote_logger = remote_logger
        
        # 國防級威脅偵測引擎
        self._national_defense_engine = None
        self._enable_national_defense = enable_national_defense
        if enable_national_defense and NATIONAL_DEFENSE_AVAILABLE:
            self._national_defense_engine = NationalDefenseEngine()
            # 載入國防級規則到核心規則庫
            defense_patterns = self._national_defense_engine.get_all_defense_patterns()
            for category, patterns in defense_patterns.items():
                self.threat_patterns[category] = patterns
            # 更新威脅嚴重等級
            self._add_national_defense_severity()
            self.logger.info(
                f"🛡️ 國防級偵測引擎已啟動: "
                f"+{len(defense_patterns)} 類別, "
                f"+{sum(len(v) for v in defense_patterns.values())} 條規則"
            )
        
        self.logger.info(
            f"✅ 防禦系統已初始化 "
            f"(快取: {'啟用' if enable_caching else '禁用'}, "
            f"線程安全: {'是' if enable_threading else '否'}, "
            f"遠端日誌: {'啟用' if remote_logger else '禁用'}, "
            f"國防級: {'啟用' if self._national_defense_engine else '禁用'})"
        )
        # 讀取 config 中的 max_iterations（可從多個候選路徑載入）
        self.max_payload_decode_iterations = 10
        try:
            candidate_paths = [
                Path.cwd() / 'config.yaml',
                Path(__file__).resolve().parents[1] / 'config.yaml',
                Path('/etc/c45144l/config.yaml')
            ]
            for p in candidate_paths:
                if p.exists():
                    with open(p, 'r', encoding='utf-8') as f:
                        cfg = yaml.safe_load(f) or {}
                        v = None
                        if isinstance(cfg, dict):
                            v = cfg.get('defense', {}) and cfg.get('defense').get('max_iterations')
                        if v is not None:
                            try:
                                self.max_payload_decode_iterations = int(v)
                            except Exception:
                                pass
                            break
        except Exception:
            pass
    
    def _add_national_defense_severity(self) -> None:
        """添加國防級威脅嚴重等級"""
        national_severity = {
            # 關鍵基礎設施
            "CI_MODBUS_ATTACK": 10, "CI_DNP3_ATTACK": 10,
            "CI_OPC_UA_ATTACK": 10, "CI_STUXNET_PATTERN": 10,
            "CI_TRITON_TRISIS": 10, "CI_POWER_GRID_ATTACK": 10,
            "CI_WATER_SYSTEM_ATTACK": 10, "CI_TELECOM_ATTACK": 10,
            "CI_NUCLEAR_FACILITY": 10, "CI_TRANSPORTATION": 10,
            # 供應鏈
            "SC_DEPENDENCY_CONFUSION": 9, "SC_BUILD_SYSTEM_COMPROMISE": 9,
            "SC_CODE_SIGNING_ABUSE": 9, "SC_UPDATE_MECHANISM_HIJACK": 10,
            "SC_FIRMWARE_SUPPLY_CHAIN": 10,
            # 加密/協定
            "CRYPTO_CRYPTO_ATTACK": 8, "CRYPTO_PROTOCOL_ABUSE": 8,
            "CRYPTO_SIDE_CHANNEL": 9, "CRYPTO_COVERT_CHANNEL": 9,
            # 資訊戰
            "IW_DISINFORMATION": 8, "IW_CYBER_ESPIONAGE": 10,
            "IW_ELECTION_INTERFERENCE": 10, "IW_CRITICAL_COMM_INTERCEPT": 10,
            # 網路鑑識
            "NF_DPI_ANOMALY": 7, "NF_LATERAL_MOVEMENT": 9,
            "NF_DATA_EXFILTRATION_ADVANCED": 10, "NF_CREDENTIAL_HARVESTING": 9,
            "NF_PRIVILEGE_ESCALATION_ADVANCED": 9,
        }
        self.threat_severity.update(national_severity)
    
    # ════════════════════════════════════════════════════════
    # 遠端日誌管理
    # ════════════════════════════════════════════════════════
    
    def set_remote_logger(self, remote_logger) -> None:
        """設定或替換遠端日誌系統"""
        self._remote_logger = remote_logger
        self.logger.info("🔗 遠端日誌系統已設定")
    
    def get_remote_logger(self):
        """取得目前的遠端日誌實例"""
        return self._remote_logger
    
    # ════════════════════════════════════════════════════════
    # IP 信譽與白名單管理
    # ════════════════════════════════════════════════════════
    
    def add_ip_whitelist(self, *ips: str) -> None:
        """將 IP 加入白名單（跳過威脅檢測）"""
        for ip in ips:
            self._ip_whitelist.add(ip)
        self.logger.info(f"✅ 白名單已更新: +{len(ips)} 個 IP (總計 {len(self._ip_whitelist)})")
    
    def add_ip_blacklist(self, *ips: str) -> None:
        """將 IP 加入黑名單（永久封鎖）"""
        for ip in ips:
            self._ip_blacklist.add(ip)
        self.logger.info(f"🚫 黑名單已更新: +{len(ips)} 個 IP (總計 {len(self._ip_blacklist)})")
    
    def add_path_whitelist(self, *patterns: str) -> None:
        """新增路徑白名單模式（正則），匹配的路徑不會觸發攻擊判定"""
        for p in patterns:
            try:
                compiled = re.compile(p, re.IGNORECASE)
                self._path_whitelist.append(p)
                self._compiled_whitelist_patterns.append(compiled)
            except re.error as e:
                self.logger.warning(f"⚠️ 無效的路徑白名單正則: {p} - {str(e)}")
        self.logger.info(f"✅ 路徑白名單已更新: +{len(patterns)} 條規則")
    
    def _is_whitelisted(self, ip: str, payload: str) -> bool:
        """檢查 IP 或路徑是否在白名單中"""
        if ip in self._ip_whitelist:
            return True
        for compiled in self._compiled_whitelist_patterns:
            if compiled.search(payload):
                return True
        return False
    
    def _update_ip_reputation(self, ip: str, is_threat: bool, risk_score: float) -> None:
        """更新 IP 信譽分數"""
        if ip not in self._ip_scores:
            self._ip_scores[ip] = 0.0
            self._ip_violations[ip] = 0
        
        if is_threat:
            self._ip_scores[ip] += risk_score
            self._ip_violations[ip] += 1
            # 累積 5 次違規 → 自動加入黑名單
            if self._ip_violations[ip] >= 5:
                self._ip_blacklist.add(ip)
                self.logger.warning(f"🚫 IP {ip} 已自動加入黑名單 (違規 {self._ip_violations[ip]} 次)")
                if self._remote_logger:
                    self._remote_logger.log_critical(
                        f"IP auto-blacklisted: {ip} ({self._ip_violations[ip]} violations)",
                        {"ip": ip, "violations": self._ip_violations[ip]}
                    )
        else:
            # 正常行為微幅回復信譽
            self._ip_scores[ip] = max(0, self._ip_scores[ip] - 0.05)
    
    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """查詢 IP 信譽資訊"""
        return {
            "ip": ip,
            "risk_score": self._ip_scores.get(ip, 0.0),
            "violations": self._ip_violations.get(ip, 0),
            "blacklisted": ip in self._ip_blacklist,
            "whitelisted": ip in self._ip_whitelist,
        }
    
    # ════════════════════════════════════════════════════════
    # Payload 解碼器（自動解碼繞過攻擊）
    # ════════════════════════════════════════════════════════
    
    def _decode_payload(self, payload: str) -> str:
        """多層解碼 payload，揭露混淆攻擊"""
        # 優先使用 AdvancedPayloadDecoder（若可用）
        try:
            if AdvancedPayloadDecoder is not None:
                decoder = AdvancedPayloadDecoder(max_iterations=self.max_payload_decode_iterations)
                decoded, _ = decoder.decode(payload)
                return decoded
        except Exception:
            # 若第三方解碼器失敗，退回到內建備援解碼流程
            pass

        decoded = payload
        max_iter = max(1, int(getattr(self, 'max_payload_decode_iterations', 10) or 10))
        iterations = 0

        # 逐次嘗試所有解碼方式，直到無變化或超過最大迭代次數
        while iterations < max_iter:
            previous = decoded

            # 嘗試 URL 解碼
            try:
                url_decoded = unquote(decoded)
                if url_decoded != decoded:
                    decoded = url_decoded
                    iterations += 1
                    continue
            except Exception:
                pass

            # 嘗試 Base64 解碼
            try:
                if decoded and len(decoded) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', decoded):
                    try:
                        b = base64.b64decode(decoded, validate=True)
                        decoded_str = b.decode('utf-8')
                        if decoded_str != decoded:
                            decoded = decoded_str
                            iterations += 1
                            continue
                    except Exception:
                        pass
            except Exception:
                pass

            # 嘗試十六進制解碼
            try:
                hex_candidate = decoded.replace('0x', '').replace('\\x', '')
                if re.match(r'^([0-9a-fA-F]{2})+$', hex_candidate):
                    try:
                        decoded_hex = bytes.fromhex(hex_candidate).decode('utf-8')
                        if decoded_hex != decoded:
                            decoded = decoded_hex
                            iterations += 1
                            continue
                    except Exception:
                        pass
            except Exception:
                pass

            # 嘗試 Unicode 轉義
            try:
                u = decoded.encode().decode('unicode_escape')
                if u != decoded:
                    decoded = u
                    iterations += 1
                    continue
            except Exception:
                pass

            # 嘗試 HTML 實體
            try:
                # 命名實體
                entities = {'&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&apos;': "'"}
                temp = decoded
                for ent, ch in entities.items():
                    temp = temp.replace(ent, ch)
                temp = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), temp)
                temp = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), temp)
                if temp != decoded:
                    decoded = temp
                    iterations += 1
                    continue
            except Exception:
                pass

            # 若未發生改變，停止
            if decoded == previous:
                break

            iterations += 1

        return decoded
    
    # ════════════════════════════════════════════════════════
    # IP 格式驗證
    # ════════════════════════════════════════════════════════
    
    def _validate_ip(self, ip: str) -> bool:
        """驗證 IP 格式是否合法"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def train_ai_baseline(self, normal_data: TrafficFeatures) -> None:
        """
        Train the AI model on normal traffic patterns
        
        Args:
            normal_data: Array of normal traffic features
            
        Raises:
            ValueError: If normal_data is empty or invalid format
        """
        try:
            normal_data = np.asarray(normal_data)
            
            if normal_data.size == 0:
                raise ValueError("normal_data cannot be empty")
            
            if normal_data.ndim == 1:
                normal_data = normal_data.reshape(-1, 1)

            if normal_data.ndim == 2 and normal_data.shape[1] == 2:
                normal_data = self._augment_time_series_training_features(normal_data)
            
            # Normalize the data
            self.baseline = self.scaler.fit_transform(normal_data)
            
            # Train the anomaly detection model
            self.model.fit(self.baseline)
            self.trained = True
            
            self.logger.info(f"✅ AI 基線已訓練 ({len(normal_data)} 個樣本, {normal_data.shape[1]} 個特徵)")
            
        except Exception as e:
            self.logger.error(f"❌ 訓練失敗: {str(e)}")
            raise

    def _augment_time_series_training_features(self, normal_data: np.ndarray) -> np.ndarray:
        """Augment 2D normal training data with sliding time-series features."""
        if normal_data.ndim != 2 or normal_data.shape[1] != 2:
            return normal_data

        augmented_rows = []
        temp_detector = TimeSeriesAnomalyDetector(window_seconds=self.time_series_detector.window_seconds)
        for index, (packet_size, latency) in enumerate(normal_data):
            extra_features = temp_detector.append_event(
                "baseline",
                float(packet_size),
                float(latency),
                timestamp=float(index),
            )
            augmented_rows.append(np.concatenate([[packet_size, latency], extra_features]))

        return np.asarray(augmented_rows)

    def _prepare_traffic_features(self, ip: str, traffic_features: np.ndarray) -> np.ndarray:
        """Prepare traffic features by appending derived time-series features for each IP."""
        if traffic_features.ndim == 1:
            traffic_features = traffic_features.reshape(1, -1)

        expected_dim = self.baseline.shape[1] if self.baseline is not None else None
        if traffic_features.shape[1] >= 2:
            if expected_dim is None or expected_dim == 7:
                base_features = np.asarray(traffic_features[0, :2], dtype=float)
                derived_features = self.time_series_detector.append_event(
                    ip,
                    float(base_features[0]),
                    float(base_features[1]),
                )
                combined = np.concatenate([base_features, derived_features]).reshape(1, -1)
                return combined
            if expected_dim == 2:
                return traffic_features[:, :2]
            return traffic_features[:, :expected_dim]

        return traffic_features

    def _calculate_time_series_risk(self, traffic_features: np.ndarray, current_risk: float) -> float:
        """Add extra risk for time-series anomalies such as low-and-slow C2 behavior."""
        score = current_risk
        if traffic_features.shape[1] >= 7:
            derived = list(traffic_features[0, 2:7])
            ts_score = self.time_series_detector._score_behavioral_anomaly(derived)
            score = min(0.99, score + ts_score * 0.18)
        return score
    
    def set_model_params(self, **params) -> Dict[str, Any]:
        """
        Set model parameters and retrain if baseline exists
        
        Args:
            **params: Model parameters to set (n_estimators, contamination, etc.)
                      Parameters are passed to IsolationForest.set_params()
        
        Returns:
            Dictionary with new parameters
            
        Raises:
            ValueError: If invalid parameters provided
            
        Example:
            system.set_model_params(n_estimators=200, contamination=0.15)
        """
        try:
            self.model.set_params(**params)
            self.logger.info(f"✅ 模型參數已更新: {params}")
            
            # Retrain if baseline exists
            if self.baseline is not None:
                self.logger.info("🔄 重新訓練模型...")
                self.model.fit(self.baseline)
                self.trained = True
                self.logger.info("✅ 模型重新訓練完成")
            
            return self.get_model_params()
        except Exception as e:
            self.logger.error(f"❌ 參數設置失敗: {str(e)}")
            raise ValueError(f"Invalid parameters: {str(e)}")
    
    def get_model_params(self) -> Dict[str, Any]:
        """
        Get current model parameters
        
        Returns:
            Dictionary of current model parameters
        """
        params = self.model.get_params()
        return params
    
    def tune_ai_model(self, mode: str = "balanced") -> Dict[str, Any]:
        """
        Quick tuning presets for common use cases
        
        Args:
            mode: Tuning preset
                - 'fast': Faster detection, less accurate (n_estimators=50)
                - 'balanced': Default mode (n_estimators=100)
                - 'accurate': More accurate, slower (n_estimators=200)
                - 'sensitive': Detect more anomalies (contamination=0.15)
                - 'strict': Fewer false positives (contamination=0.05)
        
        Returns:
            Dictionary of model parameters after tuning
            
        Raises:
            ValueError: If invalid tuning mode provided
            
        Example:
            system.tune_ai_model('accurate')
        """
        tuning_configs = {
            'fast': {'n_estimators': 50, 'contamination': 0.1},
            'balanced': {'n_estimators': 100, 'contamination': 0.1},
            'accurate': {'n_estimators': 200, 'contamination': 0.1},
            'sensitive': {'n_estimators': 100, 'contamination': 0.15},
            'strict': {'n_estimators': 100, 'contamination': 0.05},
        }
        
        if mode not in tuning_configs:
            raise ValueError(f"Unknown tuning mode: {mode}. Available: {list(tuning_configs.keys())}")
        
        config = tuning_configs[mode]
        self.logger.info(f"🎯 應用 '{mode}' 模式調整...")
        
        return self.set_model_params(**config)
    
    def get_model_stats(self) -> Dict[str, Any]:
        """
        Get current model statistics and configuration
        
        Returns:
            Dictionary containing comprehensive model statistics
        """
        params = self.get_model_params()
        stats = {
            'model_type': self.model.__class__.__name__,
            'trained': self.trained,
            'baseline_size': len(self.baseline) if self.baseline is not None else 0,
            'baseline_features': self.baseline.shape[1] if self.baseline is not None else 0,
            'n_estimators': params.get('n_estimators'),
            'contamination': params.get('contamination'),
            'random_state': params.get('random_state'),
            'n_jobs': params.get('n_jobs', 1),
            'max_samples': params.get('max_samples'),
            'max_features': params.get('max_features'),
            'cache_enabled': self.enable_caching,
            'cache_size': len(self._cache),
            'threat_patterns_count': len(self.threat_patterns),
        }
        return stats
    
    def print_model_info(self) -> None:
        """Print current model information and comprehensive statistics"""
        stats = self.get_model_stats()
        print("\n" + "="*70)
        print("🤖 AI 模型信息 & 統計")
        print("="*70)
        print(f"模型類型: {stats['model_type']}")
        print(f"訓練狀態: {'✅ 已訓練' if stats['trained'] else '❌ 未訓練'}")
        print(f"基線數據: {stats['baseline_size']} 樣本 × {stats['baseline_features']} 特徵")
        print(f"\n參數配置:")
        print(f"  • n_estimators: {stats['n_estimators']}")
        print(f"  • contamination: {stats['contamination']}")
        print(f"  • random_state: {stats['random_state']}")
        print(f"  • n_jobs: {stats['n_jobs']} (並行處理)")
        print(f"  • max_samples: {stats['max_samples']}")
        print(f"  • max_features: {stats['max_features']}")
        print(f"\n性能配置:")
        print(f"  • 快取: {'✅ 啟用' if stats['cache_enabled'] else '❌ 禁用'}")
        print(f"  • 快取大小: {stats['cache_size']} 項")
        print(f"  • 威脅模式: {stats['threat_patterns_count']} 類")
        print("="*70 + "\n")
    
    def _initialize_threat_patterns(self):
        """
        Initialize default threat patterns with regex rules
        
        This method can be called to reset to default patterns or
        to combine with custom patterns
        """
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
                r"(?i)(rm\s+-rf|chmod\s+\+x|mkfifo|chown\s+|crontab)",
                r"(?i)(;\s*\w+\s+[-/])",
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
        self._compile_threat_patterns()
    
    def _compile_threat_patterns(self) -> None:
        """Compile threat regex patterns for faster rule-based matching."""
        self._compiled_threat_patterns = {}
        for threat_name, patterns in self.threat_patterns.items():
            if not isinstance(patterns, list):
                patterns = [patterns]
            compiled = []
            for pattern in patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    self.logger.warning(f"⚠️ 無效的正則表達式: {pattern}")
            self._compiled_threat_patterns[threat_name] = compiled
        self._compiled_pattern_snapshot = self._create_threat_pattern_snapshot()

    def _create_threat_pattern_snapshot(self):
        """Create a stable snapshot of the current threat patterns for change detection."""
        snapshot = []
        for threat_name, patterns in self.threat_patterns.items():
            if isinstance(patterns, list):
                patterns_tuple = tuple(patterns)
            else:
                patterns_tuple = (patterns,)
            snapshot.append((threat_name, patterns_tuple))
        return tuple(sorted(snapshot))
    
    def add_custom_threat(self, threat_name: str, patterns: Union[str, List[str]]) -> None:
        """
        Add or update custom threat patterns
        
        Args:
            threat_name: Name of the threat (e.g., 'custom_threat')
            patterns: String or list of regex patterns to match this threat
            
        Example:
            system.add_custom_threat('custom_threat', [
                r'vulnerable_endpoint',
                r'backup\\.sql'
            ])
        """
        if not isinstance(patterns, list):
            patterns = [patterns] if isinstance(patterns, str) else list(patterns)
        
        self.threat_patterns[threat_name] = patterns
        self._compile_threat_patterns()
        
        # Clear cache when patterns are updated
        if self.enable_caching:
            self._cache.clear()
            self.logger.info(f"✅ 自定義威脅模式已添加: {threat_name} ({len(patterns)} 個模式, 快取已清空)")
        else:
            self.logger.info(f"✅ 自定義威脅模式已添加: {threat_name} ({len(patterns)} 個模式)")
    
    def get_threat_patterns(self) -> ThreatPattern:
        """
        Get all current threat patterns
        
        Returns:
            Dictionary copy of all threat patterns
        """
        return self.threat_patterns.copy()
    
    def _payload_hash(self, payload: str) -> str:
        """Generate hash for payload caching"""
        return hashlib.md5(payload.encode()).hexdigest()
    
    def rule_based_check(self, payload: str) -> Tuple[bool, str, List[str]]:
        """
        Perform rule-based threat detection using custom threat patterns.

        Supports optional caching for improved performance on repeated payloads.
        """
        payload_hash = self._payload_hash(payload)

        # Recompile patterns if the raw threat_patterns dict has changed
        current_snapshot = self._create_threat_pattern_snapshot()
        if self._compiled_pattern_snapshot != current_snapshot:
            self._compile_threat_patterns()
            if self.enable_caching:
                self._cache.clear()

        if self.enable_caching:
            if payload_hash in self._cache:
                self.statistics['cache_hits'] += 1
                return self._cache[payload_hash]
            self.statistics['cache_misses'] += 1

        matched_threats = {}

        for threat_name, compiled_patterns in self._compiled_threat_patterns.items():
            matched_in_threat = []
            for compiled in compiled_patterns:
                if compiled.search(payload):
                    matched_in_threat.append(compiled.pattern)
            if matched_in_threat:
                matched_threats[threat_name] = matched_in_threat

        if matched_threats:
            threat_name = next(iter(matched_threats.keys()))
            matched_patterns = matched_threats[threat_name]
            result = (True, threat_name, matched_patterns)
        else:
            result = (False, "NONE", [])

        if self.enable_caching:
            if self._cache_lock:
                with self._cache_lock:
                    self._cache[payload_hash] = result
            else:
                self._cache[payload_hash] = result

        return result
    
    def batch_rule_check(self, payloads: List[str]) -> List[Dict[str, Any]]:
        """
        Perform rule-based detection on multiple payloads efficiently
        
        Args:
            payloads: List of payloads to check
            
        Returns:
            List of detection results for each payload
            
        Example:
            results = system.batch_rule_check([
                'GET /admin_panel',
                'POST /api/users',
                'GET /backup.sql'
            ])
            print(results[0])  # {'payload': '...', 'is_threat': True, ...}
        """
        results = []
        for payload in payloads:
            is_threat, threat_name, patterns = self.rule_based_check(payload)
            results.append({
                'payload': payload,
                'is_threat': is_threat,
                'threat_type': threat_name,
                'matched_patterns': patterns
            })
        return results
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache performance statistics
        
        Returns:
            Dictionary with cache hit/miss statistics
        """
        total_accesses = self.statistics['cache_hits'] + self.statistics['cache_misses']
        hit_rate = (self.statistics['cache_hits'] / total_accesses * 100) if total_accesses > 0 else 0
        
        return {
            'cache_enabled': self.enable_caching,
            'cache_size': len(self._cache),
            'cache_hits': self.statistics['cache_hits'],
            'cache_misses': self.statistics['cache_misses'],
            'hit_rate': f"{hit_rate:.1f}%",
            'total_accesses': total_accesses
        }
    
    def get_threat_patterns(self):
        """Get all current threat patterns"""
        return self.threat_patterns.copy()
    
    def _detect_threat_type(self, payload, features):
        """Detect the type of threat in the payload with enhanced detection."""
        is_custom_threat, custom_threat_name, _ = self.rule_based_check(payload)
        if is_custom_threat:
            return custom_threat_name

        payload_lower = payload.lower()
        threat_scores: Dict[str, float] = {}

        threat_scores.update(self._score_sql_and_nosql(payload_lower))
        threat_scores.update(self._score_remote_code(payload_lower))
        threat_scores.update(self._score_apt_exfiltration(features))
        threat_scores.update(self._score_xss(payload_lower))
        threat_scores.update(self._score_brute_force(payload_lower, features))
        threat_scores.update(self._score_malware_abnormal(payload_lower, features))
        threat_scores.update(self._score_low_slow_c2(features))
        self._score_multi_vector_attack(threat_scores)

        if threat_scores:
            return max(threat_scores, key=threat_scores.get)
        return "UNKNOWN"

    def _score_sql_and_nosql(self, payload_lower: str) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        sql_danger_keywords = ["drop", "delete", "insert", "truncate", "exec", "execute", "union"]
        sql_evasion_keywords = ["/*!", "*/", "--", "#", "xp_", "sp_"]
        sql_patterns = ["'", '"', ";"]

        sql_danger_count = sum(1 for pattern in sql_danger_keywords if pattern in payload_lower)
        sql_evasion_count = sum(1 for pattern in sql_evasion_keywords if pattern in payload_lower)
        sql_quote_count = sum(1 for pattern in sql_patterns if pattern in payload_lower)

        if sql_danger_count > 0 or (sql_evasion_count > 0 and sql_quote_count > 0):
            scores["SQL_INJECTION"] = 0.95 + (sql_danger_count * 0.05)
        elif sql_quote_count >= 2 and any(kw in payload_lower for kw in ["or", "and", "="]):
            scores["SQL_INJECTION"] = 0.85

        nosql_patterns = ["$gt", "$lt", "$ne", "$eq", "$regex", "$where", "$or", "$and", "$nin", "$in"]
        if any(p in payload_lower for p in nosql_patterns):
            scores["SQL_INJECTION"] = max(scores.get("SQL_INJECTION", 0), 0.93)

        return scores

    def _score_remote_code(self, payload_lower: str) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        rce_patterns = ["cat /etc/", "whoami", "nc -l", "bash -i", "sh -i", "/dev/tcp", "curl|bash", "wget|python"]
        rce_code_patterns = ["os.system", "subprocess", "os.popen", "__import__", "exec(", "eval("]

        if any(pattern in payload_lower for pattern in rce_patterns):
            scores["COMMAND_INJECTION"] = 0.99
        elif any(p in payload_lower for p in rce_code_patterns):
            scores["RCE"] = 0.96
        else:
            cmd_basic = [";", "|", "&&", "||"]
            if sum(1 for pattern in cmd_basic if pattern in payload_lower) >= 2:
                scores["COMMAND_INJECTION"] = 0.90

        return scores

    def _score_apt_exfiltration(self, features) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        if len(features) > 1:
            if features[1] > 5000:
                scores["APT_EXFILTRATION"] = 0.98
            elif features[1] > 1000:
                scores["APT_EXFILTRATION"] = 0.92
        return scores

    def _score_xss(self, payload_lower: str) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        xss_dangerous = ["<iframe", "<img", "<svg", "onerror=", "onload=", "onclick=", "onmouseover="]
        xss_basic = ["<script", "alert(", "eval(", "prompt(", "confirm(", "javascript:"]
        xss_context = ["document.cookie", "document.location", "window.location", "innerhtml"]

        if any(pattern in payload_lower for pattern in xss_dangerous):
            scores["XSS"] = 0.92
        elif any(pattern in payload_lower for pattern in xss_basic):
            scores["XSS"] = 0.90
        elif any(pattern in payload_lower for pattern in xss_context):
            scores["XSS"] = 0.88

        url_encoded_dangerous = ["%2e%2e%2f", "%252e", "%3cscript", "%3ciframe", "%3c", "%3e"]
        if any(encoded in payload_lower for encoded in url_encoded_dangerous):
            scores["XSS_ENCODED"] = max(scores.get("XSS_ENCODED", 0), 0.90)

        evasion_patterns = ["\\u003c", "\\u003e", "atob(", "btoa(", "string.fromcharcode", "\\x3c", "\\x3e", "0x27"]
        if any(p in payload_lower for p in evasion_patterns):
            scores["XSS_ENCODED"] = max(scores.get("XSS_ENCODED", 0), 0.88)

        return scores

    def _score_brute_force(self, payload_lower: str, features) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        if len(features) > 1 and ((features[0] > 5000 and features[1] < 50) or (features[1] > 100 and "login" in payload_lower)):
            scores["BRUTE_FORCE"] = 0.92
        elif len(features) > 0 and features[0] > 1000:
            scores["BRUTE_FORCE"] = 0.85
        return scores

    def _score_malware_abnormal(self, payload_lower: str, features) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        malware_extensions = [".exe", ".dll", ".bat", ".com", ".scr", ".vbs", ".js."]
        if any(exe in payload_lower for exe in malware_extensions):
            scores["MALWARE"] = 0.88

        if len(features) > 1:
            if features[0] > 8000 or features[1] > 5000:
                scores["ABNORMAL_TRAFFIC"] = 0.80
            elif features[0] > 2000 or features[1] > 2000:
                scores["ABNORMAL_TRAFFIC"] = 0.70

        return scores

    def _score_low_slow_c2(self, features) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        if len(features) >= 7:
            request_count = float(features[2])
            avg_interval = float(features[3])
            interval_std = float(features[4])
            avg_packet_size = float(features[5])
            packet_change_rate = float(features[6])

            if request_count >= 4 and avg_interval > 30.0 and abs(packet_change_rate) < 0.25 and avg_packet_size < 800:
                scores["LOW_SLOW_C2"] = 0.88
            elif request_count >= 3 and avg_interval > 60.0 and interval_std > 20.0:
                scores["LOW_SLOW_C2"] = 0.82

        return scores

    def _score_multi_vector_attack(self, threat_scores: Dict[str, float]) -> None:
        if len(threat_scores) > 1:
            max_threat = max(threat_scores.values())
            threat_scores["MULTI_VECTOR_ATTACK"] = min(0.99, max_threat + 0.10)

    def _calculate_enhanced_risk_score(self, threat_type, anomaly_score, payload, features):
        """Calculate enhanced risk score based on threat type and features"""
        base_score = min(1.0, max(0.0, -anomaly_score))
        
        # 威脅類型風險係數
        threat_multipliers = {
            "SQL_INJECTION": 1.4,
            "COMMAND_INJECTION": 1.5,
            "APT_EXFILTRATION": 1.45,
            "BRUTE_FORCE": 1.3,
            "XSS": 1.35,
            "XSS_ENCODED": 1.35,
            "MALWARE": 1.35,
            "ABNORMAL_TRAFFIC": 1.1,
            "MULTI_VECTOR_ATTACK": 1.6,
            "RCE": 1.5,
            "PATH_TRAVERSAL": 1.3,
            "REVERSE_SHELL": 1.5,
            # 行業特定威脅
            "financial_threats": 1.4,
            "healthcare_threats": 1.4,
            "government_threats": 1.5,
            "crypto_threats": 1.4,
            "intellectual_property": 1.35,
            # 國防級威脅 - 最高係數
            "CI_MODBUS_ATTACK": 1.7, "CI_DNP3_ATTACK": 1.7,
            "CI_OPC_UA_ATTACK": 1.7, "CI_STUXNET_PATTERN": 1.8,
            "CI_TRITON_TRISIS": 1.8, "CI_POWER_GRID_ATTACK": 1.8,
            "CI_WATER_SYSTEM_ATTACK": 1.8, "CI_TELECOM_ATTACK": 1.7,
            "CI_NUCLEAR_FACILITY": 1.9, "CI_TRANSPORTATION": 1.7,
            "SC_DEPENDENCY_CONFUSION": 1.5, "SC_BUILD_SYSTEM_COMPROMISE": 1.6,
            "SC_CODE_SIGNING_ABUSE": 1.6, "SC_UPDATE_MECHANISM_HIJACK": 1.7,
            "SC_FIRMWARE_SUPPLY_CHAIN": 1.8,
            "CRYPTO_CRYPTO_ATTACK": 1.4, "CRYPTO_PROTOCOL_ABUSE": 1.4,
            "CRYPTO_SIDE_CHANNEL": 1.5, "CRYPTO_COVERT_CHANNEL": 1.6,
            "IW_DISINFORMATION": 1.4, "IW_CYBER_ESPIONAGE": 1.7,
            "IW_ELECTION_INTERFERENCE": 1.8, "IW_CRITICAL_COMM_INTERCEPT": 1.8,
            "NF_DPI_ANOMALY": 1.3, "NF_LATERAL_MOVEMENT": 1.6,
            "NF_DATA_EXFILTRATION_ADVANCED": 1.7, "NF_CREDENTIAL_HARVESTING": 1.6,
            "NF_PRIVILEGE_ESCALATION_ADVANCED": 1.6,
            "UNKNOWN": 1.0
        }
        
        multiplier = threat_multipliers.get(threat_type, 1.0)
        enhanced_score = min(0.99, base_score * multiplier)

        packet_size = float(features[0]) if len(features) > 0 else 0.0
        latency = float(features[1]) if len(features) > 1 else 0.0
        
        # 特徵加成 (特別危險的流量特徵)
        if packet_size > 5000 or latency > 5000:
            enhanced_score = min(0.99, enhanced_score + 0.15)
        elif packet_size > 1000 or latency > 1000:
            enhanced_score = min(0.99, enhanced_score + 0.08)

        if len(features) >= 7:
            time_series_score = self.time_series_detector._score_behavioral_anomaly(list(features[2:7]))
            enhanced_score = min(0.99, enhanced_score + min(0.12, time_series_score * 0.12))

        return enhanced_score
        
    def analyze_incoming_traffic(self, ip: str, payload: str, traffic_features: TrafficFeatures) -> AnalysisResult:
        """
        Analyze incoming traffic and determine if it's an attack
        
        Args:
            ip: Source IP address
            payload: Request payload
            traffic_features: Array of traffic features [size, latency, etc.]
            
        Returns:
            Dictionary with comprehensive analysis results
            
        Raises:
            ValueError: If system not trained or invalid input
        """
        self.statistics['total_requests'] += 1

        ip = (ip or "").strip()
        if not self._validate_ip(ip):
            self.statistics['blocked_requests'] += 1
            self.statistics['anomalies_detected'] += 1
            return {
                "ip": ip,
                "action": "blocked",
                "reason": "Invalid source IP format",
                "threat_type": "INVALID_IP",
                "risk_score": 1.0,
                "timestamp": datetime.now().isoformat(),
                "status": "invalid_input"
            }
        
        if not self.trained:
            return {
                "action": "blocked",
                "reason": "System not trained",
                "threat_type": "UNKNOWN",
                "risk_score": 0.0,
                "status": "not_ready"
            }
        
        # 黑名單直接攔截
        if ip in self._ip_blacklist:
            self.statistics['blocked_requests'] += 1
            return {
                "ip": ip, "action": "blocked",
                "reason": f"IP {ip} is blacklisted 🚫",
                "threat_type": "BLACKLISTED", "risk_score": 1.0,
                "timestamp": datetime.now().isoformat()
            }
        
        # 白名單直接放行
        if self._is_whitelisted(ip, payload):
            self.statistics['allowed_requests'] += 1
            return {
                "ip": ip, "action": "allowed",
                "payload": payload, "reason": "Whitelisted ✅",
                "threat_type": "NONE", "risk_score": 0.0,
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            # 自動解碼 payload（揭露多層混淆）
            decoded_payload = self._decode_payload(payload)
            
            # Normalize the incoming features
            traffic_features = np.asarray(traffic_features)
            if traffic_features.ndim == 1:
                traffic_features = traffic_features.reshape(1, -1)

            traffic_features = self._prepare_traffic_features(ip, traffic_features)
            features_normalized = self.scaler.transform(traffic_features)
            
            # Predict: -1 for anomaly, 1 for normal
            prediction = self.model.predict(features_normalized)[0]
            
            # Get anomaly score
            anomaly_score = self.model.score_samples(features_normalized)[0]
            
            # Detect threat type (enhanced) - 同時檢查原始和解碼後的 payload
            threat_type = self._detect_threat_type(decoded_payload, traffic_features[0])
            if threat_type == "UNKNOWN" and decoded_payload != payload:
                # 若解碼後未偵測到，再用原始 payload 檢查（保留編碼特徵偵測）
                threat_type_raw = self._detect_threat_type(payload, traffic_features[0])
                if threat_type_raw != "UNKNOWN":
                    threat_type = threat_type_raw
            
            # Calculate enhanced risk score
            risk_score = self._calculate_enhanced_risk_score(threat_type, anomaly_score, payload, traffic_features[0])
            risk_score = self._calculate_time_series_risk(traffic_features, risk_score)
            
            # Enhanced decision logic - lower threshold for high-risk threats
            threat_risk_thresholds = {
                "SQL_INJECTION": 0.50,
                "COMMAND_INJECTION": 0.45,
                "APT_EXFILTRATION": 0.50,
                "BRUTE_FORCE": 0.55,
                "MALWARE": 0.55,
                "MULTI_VECTOR_ATTACK": 0.40,
                "RCE": 0.45,
                "XSS": 0.50,
                "XSS_ENCODED": 0.50,
                "ABNORMAL_TRAFFIC": 0.60,
                "PATH_TRAVERSAL": 0.50,
                # 行業特定威脅 - 低閾值確保攔截
                "financial_threats": 0.40,
                "healthcare_threats": 0.40,
                "government_threats": 0.35,
                "crypto_threats": 0.40,
                "intellectual_property": 0.45,
                # 國防級威脅 - 超低閾值，零容忍
                "CI_MODBUS_ATTACK": 0.30,
                "CI_DNP3_ATTACK": 0.30,
                "CI_OPC_UA_ATTACK": 0.30,
                "CI_STUXNET_PATTERN": 0.25,
                "CI_TRITON_TRISIS": 0.25,
                "CI_POWER_GRID_ATTACK": 0.25,
                "CI_WATER_SYSTEM_ATTACK": 0.25,
                "CI_TELECOM_ATTACK": 0.30,
                "CI_NUCLEAR_FACILITY": 0.20,
                "CI_TRANSPORTATION": 0.30,
                "SC_DEPENDENCY_CONFUSION": 0.35,
                "SC_BUILD_SYSTEM_COMPROMISE": 0.30,
                "SC_CODE_SIGNING_ABUSE": 0.30,
                "SC_UPDATE_MECHANISM_HIJACK": 0.25,
                "SC_FIRMWARE_SUPPLY_CHAIN": 0.25,
                "CRYPTO_CRYPTO_ATTACK": 0.40,
                "CRYPTO_PROTOCOL_ABUSE": 0.40,
                "CRYPTO_SIDE_CHANNEL": 0.35,
                "CRYPTO_COVERT_CHANNEL": 0.30,
                "IW_DISINFORMATION": 0.40,
                "IW_CYBER_ESPIONAGE": 0.25,
                "IW_ELECTION_INTERFERENCE": 0.25,
                "IW_CRITICAL_COMM_INTERCEPT": 0.25,
                "NF_DPI_ANOMALY": 0.45,
                "NF_LATERAL_MOVEMENT": 0.30,
                "NF_DATA_EXFILTRATION_ADVANCED": 0.30,
                "NF_CREDENTIAL_HARVESTING": 0.30,
                "NF_PRIVILEGE_ESCALATION_ADVANCED": 0.30,
            }
            
            threshold = threat_risk_thresholds.get(threat_type, 0.70)
            
            # UNKNOWN 類型用更保守的判定（減少誤報）
            if threat_type == "UNKNOWN":
                threshold = 0.75
            
            # Determine action based on prediction and enhanced risk score
            if prediction == -1 or risk_score > threshold:
                action = "blocked"
                self.statistics['blocked_requests'] += 1
                self.statistics['anomalies_detected'] += 1
                
                # Generate detailed reason
                reason_map = {
                    "SQL_INJECTION": "SQL injection pattern detected - CRITICAL 🔴",
                    "COMMAND_INJECTION": "Remote code execution attempt detected - CRITICAL 🔴",
                    "APT_EXFILTRATION": "APT exfiltration pattern detected - SEVERE 🟠",
                    "BRUTE_FORCE": "Brute force attack detected - HIGH 🟠",
                    "MULTI_VECTOR_ATTACK": "Multi-vector attack detected - CRITICAL 🔴",
                    "XSS": "Cross-site scripting detected - HIGH 🟠",
                    "XSS_ENCODED": "Encoded XSS attack detected - HIGH 🟠",
                    "MALWARE": "Malware signature detected - HIGH 🟠",
                    "ABNORMAL_TRAFFIC": "Abnormal traffic pattern detected - MEDIUM 🟡",
                    "RCE": "Remote code execution attempt - CRITICAL 🔴",
                    "REVERSE_SHELL": "Reverse shell attempt detected - SEVERE 🟠",
                    "PATH_TRAVERSAL": "Path traversal attack detected - HIGH 🟠",
                    "financial_threats": "Financial data exfiltration detected - CRITICAL 🔴",
                    "healthcare_threats": "Healthcare data breach attempt - CRITICAL 🔴",
                    "government_threats": "Classified data access attempt - CRITICAL 🔴",
                    "crypto_threats": "Cryptocurrency theft attempt - CRITICAL 🔴",
                    "intellectual_property": "IP theft attempt detected - HIGH 🟠",
                    # 國防級威脅
                    "CI_MODBUS_ATTACK": "🔴 NATIONAL DEFENSE: SCADA/Modbus attack on critical infrastructure",
                    "CI_DNP3_ATTACK": "🔴 NATIONAL DEFENSE: DNP3 protocol attack on industrial control",
                    "CI_OPC_UA_ATTACK": "🔴 NATIONAL DEFENSE: OPC UA exploitation attempt",
                    "CI_STUXNET_PATTERN": "🔴 NATIONAL DEFENSE: CYBER WEAPON (Stuxnet-class) pattern detected",
                    "CI_TRITON_TRISIS": "🔴 NATIONAL DEFENSE: Safety system attack (Triton/TRISIS class)",
                    "CI_POWER_GRID_ATTACK": "🔴 NATIONAL DEFENSE: Power grid attack detected",
                    "CI_WATER_SYSTEM_ATTACK": "🔴 NATIONAL DEFENSE: Water system attack detected",
                    "CI_TELECOM_ATTACK": "🔴 NATIONAL DEFENSE: Telecommunications infrastructure attack",
                    "CI_NUCLEAR_FACILITY": "🔴 NATIONAL DEFENSE: Nuclear facility threat detected",
                    "CI_TRANSPORTATION": "🔴 NATIONAL DEFENSE: Transportation system attack",
                    "SC_DEPENDENCY_CONFUSION": "🔴 SUPPLY CHAIN: Dependency confusion attack",
                    "SC_BUILD_SYSTEM_COMPROMISE": "🔴 SUPPLY CHAIN: Build system compromise",
                    "SC_CODE_SIGNING_ABUSE": "🔴 SUPPLY CHAIN: Code signing abuse detected",
                    "SC_UPDATE_MECHANISM_HIJACK": "🔴 SUPPLY CHAIN: Update mechanism hijack",
                    "SC_FIRMWARE_SUPPLY_CHAIN": "🔴 SUPPLY CHAIN: Firmware supply chain attack",
                    "CRYPTO_CRYPTO_ATTACK": "🟠 CRYPTO: Cryptographic attack detected",
                    "CRYPTO_PROTOCOL_ABUSE": "🟠 CRYPTO: Protocol abuse detected",
                    "CRYPTO_SIDE_CHANNEL": "🔴 CRYPTO: Side-channel attack detected",
                    "CRYPTO_COVERT_CHANNEL": "🔴 CRYPTO: Covert channel detected",
                    "IW_DISINFORMATION": "🟠 INFO WAR: Disinformation operation detected",
                    "IW_CYBER_ESPIONAGE": "🔴 INFO WAR: Cyber espionage activity detected",
                    "IW_ELECTION_INTERFERENCE": "🔴 INFO WAR: Election interference detected",
                    "IW_CRITICAL_COMM_INTERCEPT": "🔴 INFO WAR: Communications interception detected",
                    "NF_DPI_ANOMALY": "🟡 FORENSICS: Deep packet inspection anomaly",
                    "NF_LATERAL_MOVEMENT": "🔴 FORENSICS: Lateral movement detected",
                    "NF_DATA_EXFILTRATION_ADVANCED": "🔴 FORENSICS: Advanced data exfiltration",
                    "NF_CREDENTIAL_HARVESTING": "🔴 FORENSICS: Credential harvesting detected",
                    "NF_PRIVILEGE_ESCALATION_ADVANCED": "🔴 FORENSICS: Advanced privilege escalation",
                }
                
                reason = reason_map.get(threat_type, f"Anomaly detected (score: {anomaly_score:.2f}) - Risk: {risk_score:.1%}")
            else:
                action = "allowed"
                self.statistics['allowed_requests'] += 1
                reason = "Normal traffic pattern ✅"
            
            time_series_features = traffic_features[0, 2:].tolist() if traffic_features.shape[1] >= 3 else []
            ts_is_anomaly, ts_score = self.time_series_detector.detect_time_series_anomaly(ip)

            result: AnalysisResult = {
                "ip": ip,
                "action": action,
                "payload": payload,
                "anomaly_score": float(anomaly_score),
                "prediction": int(prediction),
                "confidence": abs(float(anomaly_score)),
                "threat_type": threat_type,
                "risk_score": risk_score,
                "threat_severity": self.threat_severity.get(threat_type, 0),
                "reason": reason,
                "severity": self._get_severity_level(threat_type, risk_score),
                "time_series_features": time_series_features,
                "time_series_anomaly_score": float(ts_score),
                "time_series_anomaly": ts_is_anomaly,
                "timestamp": datetime.now().isoformat()
            }
            
            # ═══ 國防級深度掃描 ═══
            if self._national_defense_engine:
                nd_result = self._national_defense_engine.scan_payload(
                    ip, decoded_payload, traffic_features[0]
                )
                result["national_defense"] = {
                    "is_national_threat": nd_result["is_national_threat"],
                    "classification": nd_result["classification"],
                    "threat_score": nd_result["threat_score"],
                    "apt_attribution": nd_result.get("apt_attribution"),
                    "matched_categories": nd_result.get("matched_categories", []),
                    "kill_chain": nd_result.get("kill_chain", {}),
                    "mitre_tactics": nd_result.get("mitre_tactics", []),
                    "recommended_actions": nd_result.get("recommended_actions", []),
                }
                # 如果國防級偵測發現國家級威脅，提升風險分數
                if nd_result["is_national_threat"]:
                    result["risk_score"] = max(result["risk_score"], nd_result["threat_score"])
                    result["action"] = "blocked"
                    result["threat_type"] = (
                        nd_result["matched_categories"][0] 
                        if nd_result["matched_categories"] 
                        else result["threat_type"]
                    )
                    result["reason"] = (
                        f"🔴 NATIONAL DEFENSE ALERT: {result['threat_type']} "
                        f"(Classification: {nd_result['classification']})"
                    )
                    result["severity"] = f"🔴 NATIONAL THREAT - {nd_result['classification']}"
                    if nd_result.get("apt_attribution"):
                        result["reason"] += (
                            f" | APT Group: {nd_result['apt_attribution']['group']} "
                            f"({nd_result['apt_attribution']['origin']})"
                        )
                    if action != "blocked":
                        self.statistics['blocked_requests'] += 1
                        self.statistics['anomalies_detected'] += 1
                        self.statistics['allowed_requests'] -= 1
            
            # Record event to history (deque 自動管理容量)
            self.event_history.append({
                "timestamp": result['timestamp'],
                "ip": ip,
                "action": result["action"],
                "threat_type": result["threat_type"],
                "risk_score": result["risk_score"],
                "payload": payload[:100]
            })
            
            # 更新 IP 信譽
            self._update_ip_reputation(ip, result["action"] == "blocked", result["risk_score"])
            
            # 即時遠端日誌
            if self._remote_logger and result["action"] == "blocked":
                self._remote_logger.log_threat(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ 分析流量時出錯: {str(e)}")
            return {
                "action": "blocked",
                "reason": f"Analysis error: {str(e)}",
                "threat_type": "UNKNOWN",
                "risk_score": 1.0,
                "status": "error"
            }
    
    def _get_severity_level(self, threat_type, risk_score):
        """Determine severity level based on threat type and risk score"""
        severity_map = {
            "COMMAND_INJECTION": "🔴 CRITICAL",
            "SQL_INJECTION": "🔴 CRITICAL",
            "MULTI_VECTOR_ATTACK": "🔴 CRITICAL",
            "RCE": "🔴 CRITICAL",
            "APT_EXFILTRATION": "🟠 SEVERE",
            "REVERSE_SHELL": "🟠 SEVERE",
            "BRUTE_FORCE": "🟠 HIGH",
            "MALWARE": "🟠 HIGH",
            "PATH_TRAVERSAL": "🟠 HIGH",
            "BLACKLISTED": "🔴 CRITICAL",
            "XSS": "🟡 MEDIUM-HIGH",
            "XSS_ENCODED": "🟡 MEDIUM-HIGH",
            "ABNORMAL_TRAFFIC": "🟡 MEDIUM",
            "financial_threats": "🔴 CRITICAL",
            "healthcare_threats": "🔴 CRITICAL",
            "government_threats": "🔴 CRITICAL",
            "crypto_threats": "🔴 CRITICAL",
            "intellectual_property": "🟠 HIGH",
            "UNKNOWN": "🔵 LOW",
            # 國防級威脅等級
            "CI_MODBUS_ATTACK": "🔴 NATIONAL THREAT - CRITICAL INFRASTRUCTURE",
            "CI_DNP3_ATTACK": "🔴 NATIONAL THREAT - CRITICAL INFRASTRUCTURE",
            "CI_OPC_UA_ATTACK": "🔴 NATIONAL THREAT - CRITICAL INFRASTRUCTURE",
            "CI_STUXNET_PATTERN": "🔴 NATIONAL THREAT - CYBER WEAPON",
            "CI_TRITON_TRISIS": "🔴 NATIONAL THREAT - SAFETY SYSTEM ATTACK",
            "CI_POWER_GRID_ATTACK": "🔴 NATIONAL THREAT - POWER GRID",
            "CI_WATER_SYSTEM_ATTACK": "🔴 NATIONAL THREAT - WATER SYSTEM",
            "CI_TELECOM_ATTACK": "🔴 NATIONAL THREAT - TELECOMMUNICATIONS",
            "CI_NUCLEAR_FACILITY": "🔴 NATIONAL THREAT - NUCLEAR FACILITY",
            "CI_TRANSPORTATION": "🔴 NATIONAL THREAT - TRANSPORTATION",
            "SC_DEPENDENCY_CONFUSION": "🟠 SUPPLY CHAIN ATTACK",
            "SC_BUILD_SYSTEM_COMPROMISE": "🔴 SUPPLY CHAIN - BUILD SYSTEM",
            "SC_CODE_SIGNING_ABUSE": "🔴 SUPPLY CHAIN - CODE SIGNING",
            "SC_UPDATE_MECHANISM_HIJACK": "🔴 SUPPLY CHAIN - UPDATE HIJACK",
            "SC_FIRMWARE_SUPPLY_CHAIN": "🔴 SUPPLY CHAIN - FIRMWARE",
            "CRYPTO_CRYPTO_ATTACK": "🟠 CRYPTOGRAPHIC ATTACK",
            "CRYPTO_PROTOCOL_ABUSE": "🟠 PROTOCOL ABUSE",
            "CRYPTO_SIDE_CHANNEL": "🔴 SIDE CHANNEL ATTACK",
            "CRYPTO_COVERT_CHANNEL": "🔴 COVERT CHANNEL",
            "IW_DISINFORMATION": "🟠 INFORMATION WARFARE",
            "IW_CYBER_ESPIONAGE": "🔴 CYBER ESPIONAGE",
            "IW_ELECTION_INTERFERENCE": "🔴 ELECTION INTERFERENCE",
            "IW_CRITICAL_COMM_INTERCEPT": "🔴 COMMUNICATIONS INTERCEPT",
            "NF_DPI_ANOMALY": "🟡 NETWORK ANOMALY",
            "NF_LATERAL_MOVEMENT": "🔴 LATERAL MOVEMENT",
            "NF_DATA_EXFILTRATION_ADVANCED": "🔴 ADVANCED EXFILTRATION",
            "NF_CREDENTIAL_HARVESTING": "🔴 CREDENTIAL HARVESTING",
            "NF_PRIVILEGE_ESCALATION_ADVANCED": "🔴 PRIVILEGE ESCALATION",
        }
        
        return severity_map.get(threat_type, "🔵 LOW")
    
    def batch_analyze(self, traffic_data: List[Dict[str, Any]]) -> List[AnalysisResult]:
        """
        Analyze multiple traffic records efficiently
        
        Args:
            traffic_data: List of dicts with 'ip', 'payload', 'features'
            
        Returns:
            List of analysis results
        """
        results = []
        for data in traffic_data:
            try:
                result = self.analyze_incoming_traffic(
                    data.get('ip', 'unknown'),
                    data.get('payload', ''),
                    data.get('features', [0, 0])
                )
                results.append(result)
            except Exception as e:
                self.logger.error(f"❌ 批量分析錯誤: {str(e)}")
                results.append({
                    "action": "blocked",
                    "reason": f"Batch analysis error: {str(e)}",
                    "threat_type": "UNKNOWN",
                    "risk_score": 1.0
                })
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive monitoring statistics
        
        Returns:
            Dictionary with detailed statistics
        """
        total = self.statistics['total_requests']
        blocked = self.statistics['blocked_requests']
        
        block_rate = blocked / total if total > 0 else 0
        
        stats = {
            'total_requests': total,
            'blocked_requests': blocked,
            'allowed_requests': self.statistics['allowed_requests'],
            'block_rate': block_rate,
            'block_rate_percent': f"{block_rate:.1%}",
            'anomalies_detected': self.statistics['anomalies_detected'],
            'cache_stats': self.get_cache_stats() if self.enable_caching else None
        }
        return stats
    
    def print_statistics(self) -> None:
        """Print detailed security statistics"""
        stats = self.get_statistics()
        print("\n" + "="*70)
        print("📊 安全統計")
        print("="*70)
        print(f"總請求數: {stats['total_requests']}")
        print(f"被阻止: {stats['blocked_requests']}")
        print(f"允許: {stats['allowed_requests']}")
        print(f"阻止率: {stats['block_rate_percent']}")
        print(f"異常檢測: {stats['anomalies_detected']}")
        
        if self.enable_caching and stats['cache_stats']:
            cache_stats = stats['cache_stats']
            print(f"\n快取統計:")
            print(f"  • 命中: {cache_stats['cache_hits']} ({cache_stats['hit_rate']})")
            print(f"  • 失誤: {cache_stats['cache_misses']}")
            print(f"  • 大小: {cache_stats['cache_size']} 項")
        
        print("="*70 + "\n")
    
    def get_event_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get event history (all recorded security events)
        
        Args:
            limit: Maximum number of events to return (None for all)
            
        Returns:
            List of events, most recent first
        """
        history = list(self.event_history)
        if limit:
            return history[-limit:] if limit > 0 else []
        return history
    
    def export_statistics(self, filepath: str) -> None:
        """
        Export statistics to JSON file
        
        Args:
            filepath: Path to save JSON statistics
        """
        import json
        try:
            stats = self.get_statistics()
            stats['event_history'] = self.get_event_history()
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"✅ 統計已匯出到: {filepath}")
        except Exception as e:
            self.logger.error(f"❌ 匯出統計失敗: {str(e)}")
