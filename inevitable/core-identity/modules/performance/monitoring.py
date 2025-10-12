"""
Performance Monitoring Module
Tracks cache performance, hit rates, and security metrics
"""

import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """
    Monitor cache performance and security metrics
    """
    
    def __init__(self):
        """Initialize performance monitor"""
        self.metrics = defaultdict(lambda: defaultdict(int))
        self.lock = threading.Lock()
        self.start_time = time.time()
        
    def record_cache_hit(self, tenant_id: str):
        """Record a cache hit"""
        with self.lock:
            self.metrics[tenant_id]["cache_hits"] += 1
            self.metrics["_global"]["cache_hits"] += 1
    
    def record_cache_miss(self, tenant_id: str):
        """Record a cache miss"""
        with self.lock:
            self.metrics[tenant_id]["cache_misses"] += 1
            self.metrics["_global"]["cache_misses"] += 1
    
    def record_cache_set(self, tenant_id: str, key_size: int, value_size: int):
        """Record a cache set operation"""
        with self.lock:
            self.metrics[tenant_id]["cache_sets"] += 1
            self.metrics[tenant_id]["total_key_size"] += key_size
            self.metrics[tenant_id]["total_value_size"] += value_size
            self.metrics["_global"]["cache_sets"] += 1
    
    def record_security_violation(self, tenant_id: str, violation_type: str):
        """Record a security violation"""
        with self.lock:
            self.metrics[tenant_id][f"security_violation_{violation_type}"] += 1
            self.metrics["_global"][f"security_violation_{violation_type}"] += 1
            
            # Log for audit
            logger.warning(
                f"Security violation: {violation_type} for tenant {tenant_id}"
            )
    
    def record_collision_attempt(self, tenant_id: str):
        """Record a potential cache key collision attempt"""
        with self.lock:
            self.metrics[tenant_id]["collision_attempts"] += 1
            self.metrics["_global"]["collision_attempts"] += 1
    
    def get_hit_rate(self, tenant_id: Optional[str] = None) -> float:
        """Calculate cache hit rate"""
        with self.lock:
            key = tenant_id or "_global"
            hits = self.metrics[key]["cache_hits"]
            misses = self.metrics[key]["cache_misses"]
            
            total = hits + misses
            if total == 0:
                return 0.0
            
            return (hits / total) * 100
    
    def get_metrics(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get performance metrics"""
        with self.lock:
            key = tenant_id or "_global"
            metrics = dict(self.metrics[key])
            
            # Calculate derived metrics
            hit_rate = self.get_hit_rate(tenant_id)
            uptime = time.time() - self.start_time
            
            return {
                "tenant_id": tenant_id or "global",
                "cache_hits": metrics.get("cache_hits", 0),
                "cache_misses": metrics.get("cache_misses", 0),
                "cache_sets": metrics.get("cache_sets", 0),
                "hit_rate_percent": round(hit_rate, 2),
                "total_key_size_bytes": metrics.get("total_key_size", 0),
                "total_value_size_bytes": metrics.get("total_value_size", 0),
                "security_violations": {
                    k.replace("security_violation_", ""): v
                    for k, v in metrics.items()
                    if k.startswith("security_violation_")
                },
                "collision_attempts": metrics.get("collision_attempts", 0),
                "uptime_seconds": round(uptime, 2)
            }
    
    def reset_metrics(self, tenant_id: Optional[str] = None):
        """Reset metrics for a tenant or globally"""
        with self.lock:
            if tenant_id:
                self.metrics[tenant_id] = defaultdict(int)
            else:
                self.metrics.clear()
                self.metrics = defaultdict(lambda: defaultdict(int))
            self.start_time = time.time()
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate security report for cache operations"""
        with self.lock:
            total_violations = 0
            violation_breakdown = defaultdict(int)
            tenant_violations = {}
            
            for tenant_id, metrics in self.metrics.items():
                if tenant_id == "_global":
                    continue
                    
                tenant_violation_count = 0
                for key, value in metrics.items():
                    if key.startswith("security_violation_"):
                        violation_type = key.replace("security_violation_", "")
                        violation_breakdown[violation_type] += value
                        tenant_violation_count += value
                        total_violations += value
                
                if tenant_violation_count > 0:
                    tenant_violations[tenant_id] = tenant_violation_count
            
            collision_attempts = sum(
                metrics.get("collision_attempts", 0)
                for metrics in self.metrics.values()
            )
            
            return {
                "total_security_violations": total_violations,
                "violation_breakdown": dict(violation_breakdown),
                "tenants_with_violations": tenant_violations,
                "total_collision_attempts": collision_attempts,
                "security_status": "SECURE" if total_violations == 0 else "VIOLATIONS_DETECTED",
                "recommendations": self._generate_recommendations(
                    total_violations,
                    collision_attempts,
                    violation_breakdown
                )
            }
    
    def _generate_recommendations(
        self,
        total_violations: int,
        collision_attempts: int,
        violation_breakdown: Dict[str, int]
    ) -> list:
        """Generate security recommendations based on metrics"""
        recommendations = []
        
        if total_violations > 0:
            recommendations.append(
                "Security violations detected. Review audit logs for details."
            )
        
        if collision_attempts > 10:
            recommendations.append(
                f"High number of collision attempts ({collision_attempts}). "
                "Possible attack or misconfiguration."
            )
        
        if violation_breakdown.get("integrity_failure", 0) > 0:
            recommendations.append(
                "Cache integrity failures detected. Possible cache poisoning attempt."
            )
        
        if violation_breakdown.get("cross_tenant_access", 0) > 0:
            recommendations.append(
                "Cross-tenant access attempts detected. Review tenant isolation."
            )
        
        if not recommendations:
            recommendations.append("No security issues detected. Cache is operating securely.")
        
        return recommendations


# Global monitor instance
_monitor_instance: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = PerformanceMonitor()
    return _monitor_instance