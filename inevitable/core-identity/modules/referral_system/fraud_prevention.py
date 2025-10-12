"""
Fraud detection and prevention for referral system
"""
import hashlib
import ipaddress
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import re

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Referral, CreditTransaction, ProductHuntActivity,
    ReferralStatus
)


logger = logging.getLogger(__name__)


class RiskScore:
    """Risk scoring constants"""
    LOW = 0.0
    MEDIUM = 0.3
    HIGH = 0.6
    CRITICAL = 0.8


class FraudPattern:
    """Common fraud patterns"""
    SELF_REFERRAL = "self_referral"
    VELOCITY_SPIKE = "velocity_spike"
    SAME_DEVICE = "same_device"
    SUSPICIOUS_IP = "suspicious_ip"
    PATTERN_ABUSE = "pattern_abuse"
    FAKE_ACTIVITY = "fake_activity"


class DeviceFingerprinter:
    """Generate device fingerprints for tracking"""
    
    def __init__(self):
        self.fingerprint_components = [
            'user_agent',
            'accept_language',
            'screen_resolution',
            'timezone',
            'platform',
            'plugins',
            'fonts',
            'canvas_fingerprint'
        ]
    
    def generate_fingerprint(
        self,
        device_data: Dict[str, Any]
    ) -> str:
        """Generate device fingerprint from browser data"""
        # Normalize components
        components = []
        
        for component in self.fingerprint_components:
            value = device_data.get(component, '')
            if isinstance(value, list):
                value = ','.join(sorted(str(v) for v in value))
            components.append(str(value).lower())
        
        # Create hash
        fingerprint_string = '|'.join(components)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]
    
    def calculate_similarity(
        self,
        fingerprint1: str,
        fingerprint2: str
    ) -> float:
        """Calculate similarity between fingerprints"""
        if fingerprint1 == fingerprint2:
            return 1.0
        
        # Simple character comparison
        matches = sum(
            1 for a, b in zip(fingerprint1, fingerprint2) 
            if a == b
        )
        return matches / max(len(fingerprint1), len(fingerprint2))


class VelocityChecker:
    """Check for velocity-based fraud patterns"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.thresholds = {
            'referrals_per_hour': 10,
            'referrals_per_day': 50,
            'credits_per_hour': 1000,
            'credits_per_day': 5000,
            'unique_ips_per_hour': 20,
            'activities_per_minute': 5
        }
    
    async def check_referral_velocity(
        self,
        user_id: str,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Check referral creation velocity"""
        async with self.db_factory() as db:
            now = datetime.utcnow()
            
            # Check hourly rate
            hour_ago = now - timedelta(hours=1)
            result = await db.execute(
                select(func.count(Referral.id)).where(
                    and_(
                        Referral.referrer_id == user_id,
                        Referral.tenant_id == tenant_id,
                        Referral.created_at >= hour_ago
                    )
                )
            )
            hourly_count = result.scalar() or 0
            
            # Check daily rate
            day_ago = now - timedelta(days=1)
            result = await db.execute(
                select(func.count(Referral.id)).where(
                    and_(
                        Referral.referrer_id == user_id,
                        Referral.tenant_id == tenant_id,
                        Referral.created_at >= day_ago
                    )
                )
            )
            daily_count = result.scalar() or 0
            
            # Calculate risk
            risk_factors = []
            
            if hourly_count > self.thresholds['referrals_per_hour']:
                risk_factors.append({
                    'type': 'high_hourly_referrals',
                    'value': hourly_count,
                    'threshold': self.thresholds['referrals_per_hour'],
                    'severity': 'high'
                })
            
            if daily_count > self.thresholds['referrals_per_day']:
                risk_factors.append({
                    'type': 'high_daily_referrals',
                    'value': daily_count,
                    'threshold': self.thresholds['referrals_per_day'],
                    'severity': 'medium'
                })
            
            return {
                'hourly_count': hourly_count,
                'daily_count': daily_count,
                'risk_factors': risk_factors,
                'risk_score': self._calculate_velocity_risk(risk_factors)
            }
    
    async def check_credit_velocity(
        self,
        user_id: str,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Check credit earning velocity"""
        async with self.db_factory() as db:
            now = datetime.utcnow()
            
            # Check hourly credits
            hour_ago = now - timedelta(hours=1)
            result = await db.execute(
                select(func.sum(CreditTransaction.amount)).where(
                    and_(
                        CreditTransaction.user_id == user_id,
                        CreditTransaction.tenant_id == tenant_id,
                        CreditTransaction.created_at >= hour_ago,
                        CreditTransaction.amount > 0
                    )
                )
            )
            hourly_credits = result.scalar() or 0
            
            # Check activity burst
            minute_ago = now - timedelta(minutes=1)
            result = await db.execute(
                select(func.count(CreditTransaction.id)).where(
                    and_(
                        CreditTransaction.user_id == user_id,
                        CreditTransaction.tenant_id == tenant_id,
                        CreditTransaction.created_at >= minute_ago
                    )
                )
            )
            minute_activities = result.scalar() or 0
            
            risk_factors = []
            
            if hourly_credits > self.thresholds['credits_per_hour']:
                risk_factors.append({
                    'type': 'high_credit_velocity',
                    'value': float(hourly_credits),
                    'threshold': self.thresholds['credits_per_hour'],
                    'severity': 'high'
                })
            
            if minute_activities > self.thresholds['activities_per_minute']:
                risk_factors.append({
                    'type': 'activity_burst',
                    'value': minute_activities,
                    'threshold': self.thresholds['activities_per_minute'],
                    'severity': 'critical'
                })
            
            return {
                'hourly_credits': float(hourly_credits),
                'minute_activities': minute_activities,
                'risk_factors': risk_factors,
                'risk_score': self._calculate_velocity_risk(risk_factors)
            }
    
    def _calculate_velocity_risk(
        self,
        risk_factors: List[Dict[str, Any]]
    ) -> float:
        """Calculate risk score from velocity factors"""
        if not risk_factors:
            return 0.0
        
        severity_scores = {
            'low': 0.2,
            'medium': 0.4,
            'high': 0.6,
            'critical': 0.8
        }
        
        max_score = 0.0
        for factor in risk_factors:
            score = severity_scores.get(factor['severity'], 0.5)
            
            # Adjust based on how much threshold was exceeded
            if 'threshold' in factor and factor['threshold'] > 0:
                multiplier = factor['value'] / factor['threshold']
                score = min(score * multiplier, 1.0)
            
            max_score = max(max_score, score)
        
        return max_score


class SuspiciousPatternDetector:
    """Detect suspicious behavior patterns"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.suspicious_patterns = {
            'rapid_signups': self._check_rapid_signups,
            'same_ip_multiple_users': self._check_same_ip,
            'sequential_actions': self._check_sequential_actions,
            'fake_social_shares': self._check_fake_shares,
            'review_templates': self._check_review_templates
        }
    
    async def detect_patterns(
        self,
        user_id: str,
        tenant_id: str,
        activity_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run all pattern detection checks"""
        detected_patterns = []
        
        for pattern_name, detector in self.suspicious_patterns.items():
            try:
                result = await detector(user_id, tenant_id, activity_data)
                if result['detected']:
                    detected_patterns.append({
                        'pattern': pattern_name,
                        'confidence': result['confidence'],
                        'details': result.get('details', {}),
                        'risk_score': result.get('risk_score', 0.5)
                    })
            except Exception as e:
                logger.error(f"Pattern detection error ({pattern_name}): {e}")
        
        return detected_patterns
    
    async def _check_rapid_signups(
        self,
        user_id: str,
        tenant_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for rapid signup patterns"""
        async with self.db_factory() as db:
            # Get recent referrals
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            result = await db.execute(
                select(Referral).where(
                    and_(
                        Referral.referrer_id == user_id,
                        Referral.tenant_id == tenant_id,
                        Referral.signup_at >= hour_ago
                    )
                ).order_by(Referral.signup_at)
            )
            recent_signups = result.scalars().all()
            
            if len(recent_signups) < 3:
                return {'detected': False}
            
            # Check time intervals
            intervals = []
            for i in range(1, len(recent_signups)):
                interval = (
                    recent_signups[i].signup_at - 
                    recent_signups[i-1].signup_at
                ).total_seconds()
                intervals.append(interval)
            
            # Suspicious if intervals are too regular
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            
            # Low variance indicates automated behavior
            if variance < 10 and avg_interval < 300:  # Less than 5 minutes
                return {
                    'detected': True,
                    'confidence': 0.8,
                    'risk_score': 0.7,
                    'details': {
                        'signup_count': len(recent_signups),
                        'avg_interval_seconds': avg_interval,
                        'variance': variance
                    }
                }
        
        return {'detected': False}
    
    async def _check_same_ip(
        self,
        user_id: str,
        tenant_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for multiple users from same IP"""
        ip_address = data.get('ip_address')
        if not ip_address:
            return {'detected': False}
        
        async with self.db_factory() as db:
            # Count unique users from this IP
            day_ago = datetime.utcnow() - timedelta(days=1)
            
            result = await db.execute(
                select(
                    func.count(func.distinct(Referral.referrer_id))
                ).where(
                    and_(
                        Referral.ip_address == ip_address,
                        Referral.tenant_id == tenant_id,
                        Referral.created_at >= day_ago
                    )
                )
            )
            unique_users = result.scalar() or 0
            
            if unique_users > 5:
                return {
                    'detected': True,
                    'confidence': min(unique_users / 10, 1.0),
                    'risk_score': 0.6,
                    'details': {
                        'ip_address': ip_address,
                        'unique_users': unique_users
                    }
                }
        
        return {'detected': False}
    
    async def _check_sequential_actions(
        self,
        user_id: str,
        tenant_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for sequential/automated actions"""
        async with self.db_factory() as db:
            # Get recent activities
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            result = await db.execute(
                select(ProductHuntActivity).where(
                    and_(
                        ProductHuntActivity.user_id == user_id,
                        ProductHuntActivity.tenant_id == tenant_id,
                        ProductHuntActivity.created_at >= hour_ago
                    )
                ).order_by(ProductHuntActivity.created_at)
            )
            activities = result.scalars().all()
            
            if len(activities) < 5:
                return {'detected': False}
            
            # Check for suspiciously regular timing
            intervals = []
            for i in range(1, len(activities)):
                interval = (
                    activities[i].created_at - 
                    activities[i-1].created_at
                ).total_seconds()
                intervals.append(interval)
            
            # Check if all intervals are similar (±5 seconds)
            base_interval = intervals[0]
            if all(abs(i - base_interval) < 5 for i in intervals):
                return {
                    'detected': True,
                    'confidence': 0.9,
                    'risk_score': 0.8,
                    'details': {
                        'activity_count': len(activities),
                        'interval_seconds': base_interval
                    }
                }
        
        return {'detected': False}
    
    async def _check_fake_shares(
        self,
        user_id: str,
        tenant_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for fake social media shares"""
        share_url = data.get('share_url', '')
        
        # Simple heuristics for fake shares
        suspicious_indicators = []
        
        # Check for URL shorteners often used to hide fake links
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
        for shortener in shorteners:
            if shortener in share_url:
                suspicious_indicators.append('url_shortener')
        
        # Check for non-existent domains
        if 'example.com' in share_url or 'test.com' in share_url:
            suspicious_indicators.append('test_domain')
        
        if len(suspicious_indicators) >= 2:
            return {
                'detected': True,
                'confidence': 0.7,
                'risk_score': 0.6,
                'details': {
                    'indicators': suspicious_indicators
                }
            }
        
        return {'detected': False}
    
    async def _check_review_templates(
        self,
        user_id: str,
        tenant_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for templated/duplicate reviews"""
        content = data.get('content', '')
        if not content or len(content) < 20:
            return {'detected': False}
        
        async with self.db_factory() as db:
            # Get other reviews
            result = await db.execute(
                select(ProductHuntActivity.content).where(
                    and_(
                        ProductHuntActivity.activity_type == 'review',
                        ProductHuntActivity.tenant_id == tenant_id,
                        ProductHuntActivity.content != None,
                        ProductHuntActivity.user_id != user_id
                    )
                ).limit(100)
            )
            other_reviews = [r[0] for r in result if r[0]]
            
            # Check for high similarity
            for other_review in other_reviews:
                similarity = self._calculate_text_similarity(content, other_review)
                if similarity > 0.8:
                    return {
                        'detected': True,
                        'confidence': similarity,
                        'risk_score': 0.7,
                        'details': {
                            'similarity_score': similarity,
                            'template_detected': True
                        }
                    }
        
        return {'detected': False}
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts"""
        # Simple word-based similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)


class FraudDetector:
    """Main fraud detection system"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.device_fingerprinter = DeviceFingerprinter()
        self.velocity_checker = VelocityChecker(db_factory)
        self.pattern_detector = SuspiciousPatternDetector(db_factory)
        
        # IP blacklists and suspicious ranges
        self.suspicious_ip_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),     # Private
            ipaddress.ip_network('172.16.0.0/12'),  # Private
            ipaddress.ip_network('192.168.0.0/16'), # Private
        ]
    
    async def analyze_risk(
        self,
        user_id: str,
        activity_type: str,
        activity_data: Dict[str, Any],
        tenant_id: str
    ) -> Dict[str, Any]:
        """Comprehensive risk analysis"""
        risk_factors = []
        
        # Check velocity
        if activity_type in ['referral', 'credit_action']:
            velocity_result = await self.velocity_checker.check_referral_velocity(
                user_id,
                tenant_id
            )
            if velocity_result['risk_score'] > 0.3:
                risk_factors.append({
                    'type': FraudPattern.VELOCITY_SPIKE,
                    'score': velocity_result['risk_score'],
                    'details': velocity_result
                })
        
        # Check IP
        ip_risk = self._analyze_ip(activity_data.get('ip_address'))
        if ip_risk['risk_score'] > 0.3:
            risk_factors.append({
                'type': FraudPattern.SUSPICIOUS_IP,
                'score': ip_risk['risk_score'],
                'details': ip_risk
            })
        
        # Check device fingerprint
        if 'device_fingerprint' in activity_data:
            device_risk = await self._analyze_device(
                user_id,
                activity_data['device_fingerprint'],
                tenant_id
            )
            if device_risk['risk_score'] > 0.3:
                risk_factors.append({
                    'type': FraudPattern.SAME_DEVICE,
                    'score': device_risk['risk_score'],
                    'details': device_risk
                })
        
        # Check patterns
        patterns = await self.pattern_detector.detect_patterns(
            user_id,
            tenant_id,
            activity_data
        )
        for pattern in patterns:
            if pattern['risk_score'] > 0.3:
                risk_factors.append({
                    'type': FraudPattern.PATTERN_ABUSE,
                    'score': pattern['risk_score'],
                    'details': pattern
                })
        
        # Calculate overall risk score
        overall_score = self._calculate_overall_risk(risk_factors)
        
        return {
            'risk_score': overall_score,
            'risk_level': self._get_risk_level(overall_score),
            'risk_factors': risk_factors,
            'recommended_action': self._recommend_action(overall_score),
            'require_manual_review': overall_score > RiskScore.HIGH
        }
    
    def _analyze_ip(self, ip_address: Optional[str]) -> Dict[str, Any]:
        """Analyze IP address for risk"""
        if not ip_address:
            return {'risk_score': 0.1, 'reason': 'no_ip'}
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check if private/local
            if ip.is_private:
                return {
                    'risk_score': 0.8,
                    'reason': 'private_ip',
                    'ip_address': ip_address
                }
            
            # Check suspicious ranges
            for suspicious_range in self.suspicious_ip_ranges:
                if ip in suspicious_range:
                    return {
                        'risk_score': 0.6,
                        'reason': 'suspicious_range',
                        'ip_address': ip_address
                    }
            
            # Check if VPN/Proxy (would use external service)
            # For now, simple heuristic
            if ip_address.startswith(('104.', '45.')):  # Common VPN ranges
                return {
                    'risk_score': 0.4,
                    'reason': 'possible_vpn',
                    'ip_address': ip_address
                }
            
        except ValueError:
            return {
                'risk_score': 0.7,
                'reason': 'invalid_ip',
                'ip_address': ip_address
            }
        
        return {'risk_score': 0.0, 'ip_address': ip_address}
    
    async def _analyze_device(
        self,
        user_id: str,
        device_fingerprint: str,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Analyze device fingerprint for risk"""
        async with self.db_factory() as db:
            # Check how many users share this device
            result = await db.execute(
                select(
                    func.count(func.distinct(Referral.referrer_id))
                ).where(
                    and_(
                        Referral.device_fingerprint == device_fingerprint,
                        Referral.tenant_id == tenant_id
                    )
                )
            )
            shared_users = result.scalar() or 0
            
            if shared_users > 3:
                return {
                    'risk_score': min(shared_users * 0.2, 0.9),
                    'reason': 'shared_device',
                    'shared_users': shared_users
                }
        
        return {'risk_score': 0.0}
    
    def _calculate_overall_risk(
        self,
        risk_factors: List[Dict[str, Any]]
    ) -> float:
        """Calculate overall risk score"""
        if not risk_factors:
            return 0.0
        
        # Use highest risk factor with slight accumulation
        max_score = max(factor['score'] for factor in risk_factors)
        
        # Add small amount for multiple factors
        additional = len(risk_factors) * 0.05
        
        return min(max_score + additional, 1.0)
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score"""
        if score >= RiskScore.CRITICAL:
            return 'critical'
        elif score >= RiskScore.HIGH:
            return 'high'
        elif score >= RiskScore.MEDIUM:
            return 'medium'
        else:
            return 'low'
    
    def _recommend_action(self, score: float) -> str:
        """Recommend action based on risk score"""
        if score >= RiskScore.CRITICAL:
            return 'block'
        elif score >= RiskScore.HIGH:
            return 'manual_review'
        elif score >= RiskScore.MEDIUM:
            return 'flag_monitor'
        else:
            return 'allow'