"""
Analytics for referral and credit system
"""
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, date
from decimal import Decimal
import statistics
from collections import defaultdict

from sqlalchemy import select, func, and_, or_, case
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Referral, ReferralCampaign, ReferralStatus,
    CreditTransaction, CreditTransactionType,
    UserCredit, Commission, AffiliatePartner,
    ProductHuntActivity
)


class ConversionFunnel:
    """Analyze referral conversion funnel"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.funnel_stages = [
            'clicked',
            'signed_up', 
            'activated',
            'converted',
            'retained'
        ]
    
    async def analyze_funnel(
        self,
        campaign_id: str,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Analyze conversion funnel for campaign"""
        async with self.db_factory() as db:
            # Build date filter
            date_filter = [Referral.campaign_id == campaign_id]
            if start_date:
                date_filter.append(Referral.created_at >= start_date)
            if end_date:
                date_filter.append(Referral.created_at <= end_date)
            
            # Get total referrals
            result = await db.execute(
                select(func.count(Referral.id)).where(and_(*date_filter))
            )
            total_referrals = result.scalar() or 0
            
            # Get stage counts
            stages = {}
            
            # Clicked
            result = await db.execute(
                select(func.count(Referral.id)).where(
                    and_(
                        *date_filter,
                        Referral.click_count > 0
                    )
                )
            )
            stages['clicked'] = result.scalar() or 0
            
            # Signed up
            result = await db.execute(
                select(func.count(Referral.id)).where(
                    and_(
                        *date_filter,
                        Referral.signup_at != None
                    )
                )
            )
            stages['signed_up'] = result.scalar() or 0
            
            # Converted
            result = await db.execute(
                select(func.count(Referral.id)).where(
                    and_(
                        *date_filter,
                        Referral.conversion_at != None
                    )
                )
            )
            stages['converted'] = result.scalar() or 0
            
            # Calculate conversion rates
            funnel = {
                'total_referrals': total_referrals,
                'stages': stages,
                'conversion_rates': {}
            }
            
            if total_referrals > 0:
                funnel['conversion_rates']['click_rate'] = stages['clicked'] / total_referrals
                funnel['conversion_rates']['signup_rate'] = stages['signed_up'] / total_referrals
                funnel['conversion_rates']['conversion_rate'] = stages['converted'] / total_referrals
            
            if stages['clicked'] > 0:
                funnel['conversion_rates']['signup_from_click'] = stages['signed_up'] / stages['clicked']
            
            if stages['signed_up'] > 0:
                funnel['conversion_rates']['conversion_from_signup'] = stages['converted'] / stages['signed_up']
            
            # Calculate drop-off rates
            funnel['dropoff_rates'] = self._calculate_dropoff_rates(stages)
            
            return funnel
    
    def _calculate_dropoff_rates(
        self,
        stages: Dict[str, int]
    ) -> Dict[str, float]:
        """Calculate drop-off between stages"""
        dropoff = {}
        
        if stages.get('clicked', 0) > 0:
            dropoff['click_to_signup'] = 1 - (stages.get('signed_up', 0) / stages['clicked'])
        
        if stages.get('signed_up', 0) > 0:
            dropoff['signup_to_conversion'] = 1 - (stages.get('converted', 0) / stages['signed_up'])
        
        return dropoff
    
    async def get_funnel_by_source(
        self,
        campaign_id: str,
        tenant_id: str
    ) -> Dict[str, Dict[str, Any]]:
        """Get funnel breakdown by referral source"""
        async with self.db_factory() as db:
            # Get funnel by source
            result = await db.execute(
                select(
                    Referral.referral_source,
                    func.count(Referral.id).label('total'),
                    func.sum(case((Referral.click_count > 0, 1), else_=0)).label('clicked'),
                    func.sum(case((Referral.signup_at != None, 1), else_=0)).label('signed_up'),
                    func.sum(case((Referral.conversion_at != None, 1), else_=0)).label('converted')
                ).where(
                    and_(
                        Referral.campaign_id == campaign_id,
                        Referral.tenant_id == tenant_id
                    )
                ).group_by(Referral.referral_source)
            )
            
            funnels_by_source = {}
            
            for row in result:
                source = row.referral_source or 'direct'
                funnels_by_source[source] = {
                    'total': row.total,
                    'clicked': row.clicked or 0,
                    'signed_up': row.signed_up or 0,
                    'converted': row.converted or 0,
                    'conversion_rate': (row.converted or 0) / row.total if row.total > 0 else 0
                }
            
            return funnels_by_source


class CohortAnalyzer:
    """Analyze user cohorts"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
    
    async def analyze_referral_cohorts(
        self,
        tenant_id: str,
        cohort_period: str = 'month',  # day, week, month
        lookback_periods: int = 6
    ) -> Dict[str, Any]:
        """Analyze referral cohorts over time"""
        async with self.db_factory() as db:
            # Determine period truncation
            if cohort_period == 'day':
                date_trunc = func.date_trunc('day', Referral.created_at)
                period_delta = timedelta(days=1)
            elif cohort_period == 'week':
                date_trunc = func.date_trunc('week', Referral.created_at)
                period_delta = timedelta(weeks=1)
            else:  # month
                date_trunc = func.date_trunc('month', Referral.created_at)
                period_delta = timedelta(days=30)
            
            # Get cohorts
            start_date = datetime.utcnow() - (period_delta * lookback_periods)
            
            result = await db.execute(
                select(
                    date_trunc.label('cohort_date'),
                    func.count(func.distinct(Referral.referrer_id)).label('referrers'),
                    func.count(Referral.id).label('total_referrals'),
                    func.sum(case((Referral.signup_at != None, 1), else_=0)).label('signups'),
                    func.sum(case((Referral.conversion_at != None, 1), else_=0)).label('conversions'),
                    func.sum(Referral.conversion_value).label('revenue')
                ).where(
                    and_(
                        Referral.tenant_id == tenant_id,
                        Referral.created_at >= start_date
                    )
                ).group_by('cohort_date').order_by('cohort_date')
            )
            
            cohorts = []
            for row in result:
                cohort = {
                    'period': row.cohort_date.strftime('%Y-%m-%d'),
                    'referrers': row.referrers,
                    'referrals': row.total_referrals,
                    'signups': row.signups or 0,
                    'conversions': row.conversions or 0,
                    'revenue': float(row.revenue or 0),
                    'metrics': {}
                }
                
                # Calculate metrics
                if cohort['referrers'] > 0:
                    cohort['metrics']['referrals_per_referrer'] = cohort['referrals'] / cohort['referrers']
                
                if cohort['referrals'] > 0:
                    cohort['metrics']['signup_rate'] = cohort['signups'] / cohort['referrals']
                    cohort['metrics']['conversion_rate'] = cohort['conversions'] / cohort['referrals']
                
                if cohort['conversions'] > 0:
                    cohort['metrics']['avg_order_value'] = cohort['revenue'] / cohort['conversions']
                
                cohorts.append(cohort)
            
            # Calculate cohort retention
            retention = await self._calculate_cohort_retention(tenant_id, cohorts)
            
            return {
                'cohorts': cohorts,
                'retention': retention,
                'summary': self._summarize_cohorts(cohorts)
            }
    
    async def _calculate_cohort_retention(
        self,
        tenant_id: str,
        cohorts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate retention for cohorts"""
        # Simplified retention calculation
        # In production, would track user activity over time
        
        retention_data = {}
        
        for i, cohort in enumerate(cohorts):
            cohort_key = cohort['period']
            retention_data[cohort_key] = {
                'month_0': 100,  # 100% in first period
                'month_1': 80 - (i * 2),  # Simulated retention
                'month_2': 60 - (i * 3),
                'month_3': 40 - (i * 4)
            }
        
        return retention_data
    
    def _summarize_cohorts(
        self,
        cohorts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Summarize cohort metrics"""
        if not cohorts:
            return {}
        
        # Calculate trends
        conversion_rates = [c['metrics'].get('conversion_rate', 0) for c in cohorts]
        aov_values = [c['metrics'].get('avg_order_value', 0) for c in cohorts if c['metrics'].get('avg_order_value')]
        
        summary = {
            'avg_conversion_rate': statistics.mean(conversion_rates) if conversion_rates else 0,
            'conversion_rate_trend': self._calculate_trend(conversion_rates),
            'avg_order_value': statistics.mean(aov_values) if aov_values else 0,
            'total_revenue': sum(c['revenue'] for c in cohorts),
            'total_conversions': sum(c['conversions'] for c in cohorts)
        }
        
        return summary
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction"""
        if len(values) < 2:
            return 'stable'
        
        # Simple linear regression
        n = len(values)
        if n == 0:
            return 'stable'
            
        x_values = list(range(n))
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        if denominator == 0:
            return 'stable'
        
        slope = numerator / denominator
        
        if slope > 0.01:
            return 'increasing'
        elif slope < -0.01:
            return 'decreasing'
        else:
            return 'stable'


class ReferralAnalytics:
    """Main referral analytics system"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.funnel = ConversionFunnel(db_factory)
        self.cohorts = CohortAnalyzer(db_factory)
    
    async def get_campaign_performance(
        self,
        campaign_id: str,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Get comprehensive campaign performance metrics"""
        async with self.db_factory() as db:
            # Get campaign
            campaign = await db.get(ReferralCampaign, campaign_id)
            if not campaign:
                return {}
            
            # Calculate key metrics
            metrics = {
                'campaign_id': campaign_id,
                'campaign_name': campaign.name,
                'status': 'active' if campaign.is_active else 'inactive',
                'performance': {}
            }
            
            # Get referral stats
            result = await db.execute(
                select(
                    func.count(Referral.id).label('total_referrals'),
                    func.count(func.distinct(Referral.referrer_id)).label('unique_referrers'),
                    func.sum(Referral.click_count).label('total_clicks'),
                    func.sum(case((Referral.signup_at != None, 1), else_=0)).label('signups'),
                    func.sum(case((Referral.conversion_at != None, 1), else_=0)).label('conversions'),
                    func.sum(Referral.conversion_value).label('revenue'),
                    func.sum(Referral.commission_amount).label('commission')
                ).where(
                    and_(
                        Referral.campaign_id == campaign_id,
                        Referral.tenant_id == tenant_id
                    )
                )
            )
            
            stats = result.first()
            
            metrics['performance'] = {
                'referrals': stats.total_referrals or 0,
                'referrers': stats.unique_referrers or 0,
                'clicks': stats.total_clicks or 0,
                'signups': stats.signups or 0,
                'conversions': stats.conversions or 0,
                'revenue': float(stats.revenue or 0),
                'commission_paid': float(stats.commission or 0)
            }
            
            # Calculate rates
            if metrics['performance']['referrals'] > 0:
                metrics['performance']['signup_rate'] = (
                    metrics['performance']['signups'] / metrics['performance']['referrals']
                )
                metrics['performance']['conversion_rate'] = (
                    metrics['performance']['conversions'] / metrics['performance']['referrals']
                )
            
            # ROI calculation
            if metrics['performance']['commission_paid'] > 0:
                metrics['performance']['roi'] = (
                    (metrics['performance']['revenue'] - metrics['performance']['commission_paid']) /
                    metrics['performance']['commission_paid']
                )
            
            # Get top performers
            metrics['top_referrers'] = await self._get_top_referrers(
                campaign_id,
                tenant_id,
                limit=10
            )
            
            return metrics
    
    async def _get_top_referrers(
        self,
        campaign_id: str,
        tenant_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top performing referrers"""
        async with self.db_factory() as db:
            result = await db.execute(
                select(
                    Referral.referrer_id,
                    func.count(Referral.id).label('referral_count'),
                    func.sum(case((Referral.signup_at != None, 1), else_=0)).label('signups'),
                    func.sum(case((Referral.conversion_at != None, 1), else_=0)).label('conversions'),
                    func.sum(Referral.conversion_value).label('revenue')
                ).where(
                    and_(
                        Referral.campaign_id == campaign_id,
                        Referral.tenant_id == tenant_id
                    )
                ).group_by(Referral.referrer_id)
                .order_by(func.sum(Referral.conversion_value).desc())
                .limit(limit)
            )
            
            top_referrers = []
            for row in result:
                referrer = {
                    'referrer_id': row.referrer_id,
                    'referrals': row.referral_count,
                    'signups': row.signups or 0,
                    'conversions': row.conversions or 0,
                    'revenue': float(row.revenue or 0),
                    'conversion_rate': (row.conversions or 0) / row.referral_count if row.referral_count > 0 else 0
                }
                top_referrers.append(referrer)
            
            return top_referrers
    
    async def get_partner_performance(
        self,
        partner_id: str,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get affiliate partner performance"""
        async with self.db_factory() as db:
            # Get partner
            partner = await db.get(AffiliatePartner, partner_id)
            if not partner:
                return {}
            
            # Build date filter
            date_filter = [Commission.partner_id == partner_id]
            if start_date:
                date_filter.append(Commission.created_at >= start_date)
            if end_date:
                date_filter.append(Commission.created_at <= end_date)
            
            # Get commission stats
            result = await db.execute(
                select(
                    func.count(Commission.id).label('total_commissions'),
                    func.sum(Commission.commission_amount).label('total_earned'),
                    func.sum(case((Commission.payout_status == 'completed', Commission.commission_amount), else_=0)).label('paid'),
                    func.sum(case((Commission.payout_status == 'pending', Commission.commission_amount), else_=0)).label('pending')
                ).where(and_(*date_filter))
            )
            
            stats = result.first()
            
            performance = {
                'partner_id': partner_id,
                'company': partner.company_name,
                'tier': partner.tier,
                'performance': {
                    'total_commissions': stats.total_commissions or 0,
                    'total_earned': float(stats.total_earned or 0),
                    'paid': float(stats.paid or 0),
                    'pending': float(stats.pending or 0),
                    'lifetime_value': float(partner.lifetime_revenue)
                }
            }
            
            # Get conversion metrics
            referral_stats = await self._get_partner_referral_stats(
                partner_id,
                tenant_id,
                start_date,
                end_date
            )
            performance['referral_metrics'] = referral_stats
            
            return performance
    
    async def _get_partner_referral_stats(
        self,
        partner_id: str,
        tenant_id: str,
        start_date: Optional[datetime],
        end_date: Optional[datetime]
    ) -> Dict[str, Any]:
        """Get referral statistics for partner"""
        async with self.db_factory() as db:
            # Build query
            date_filter = [
                Referral.referrer_id == partner_id,
                Referral.tenant_id == tenant_id
            ]
            if start_date:
                date_filter.append(Referral.created_at >= start_date)
            if end_date:
                date_filter.append(Referral.created_at <= end_date)
            
            result = await db.execute(
                select(
                    func.count(Referral.id).label('total_referrals'),
                    func.sum(Referral.click_count).label('total_clicks'),
                    func.sum(case((Referral.signup_at != None, 1), else_=0)).label('signups'),
                    func.sum(case((Referral.conversion_at != None, 1), else_=0)).label('conversions'),
                    func.avg(Referral.conversion_value).label('avg_order_value')
                ).where(and_(*date_filter))
            )
            
            stats = result.first()
            
            return {
                'referrals': stats.total_referrals or 0,
                'clicks': stats.total_clicks or 0,
                'signups': stats.signups or 0,
                'conversions': stats.conversions or 0,
                'avg_order_value': float(stats.avg_order_value or 0),
                'conversion_rate': (stats.conversions or 0) / (stats.referrals or 1)
            }


class CreditAnalytics:
    """Analytics for credit system"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
    
    async def get_credit_metrics(
        self,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get credit system metrics"""
        async with self.db_factory() as db:
            # Build date filter
            date_filter = [CreditTransaction.tenant_id == tenant_id]
            if start_date:
                date_filter.append(CreditTransaction.created_at >= start_date)
            if end_date:
                date_filter.append(CreditTransaction.created_at <= end_date)
            
            # Get transaction stats
            result = await db.execute(
                select(
                    CreditTransaction.transaction_type,
                    func.count(CreditTransaction.id).label('count'),
                    func.sum(func.abs(CreditTransaction.amount)).label('total_amount')
                ).where(and_(*date_filter))
                .group_by(CreditTransaction.transaction_type)
            )
            
            transactions_by_type = {}
            for row in result:
                transactions_by_type[row.transaction_type.value] = {
                    'count': row.count,
                    'total': float(row.total_amount or 0)
                }
            
            # Get user stats
            result = await db.execute(
                select(
                    func.count(func.distinct(UserCredit.user_id)).label('total_users'),
                    func.sum(UserCredit.balance).label('total_balance'),
                    func.avg(UserCredit.balance).label('avg_balance'),
                    func.sum(UserCredit.lifetime_earned).label('total_earned'),
                    func.sum(UserCredit.lifetime_spent).label('total_spent')
                ).where(UserCredit.tenant_id == tenant_id)
            )
            
            user_stats = result.first()
            
            # Get action stats
            action_stats = await self._get_credit_action_stats(
                tenant_id,
                start_date,
                end_date
            )
            
            return {
                'transactions': transactions_by_type,
                'users': {
                    'total': user_stats.total_users or 0,
                    'total_balance': float(user_stats.total_balance or 0),
                    'avg_balance': float(user_stats.avg_balance or 0),
                    'lifetime_earned': float(user_stats.total_earned or 0),
                    'lifetime_spent': float(user_stats.total_spent or 0)
                },
                'actions': action_stats,
                'health_metrics': await self._calculate_health_metrics(tenant_id)
            }
    
    async def _get_credit_action_stats(
        self,
        tenant_id: str,
        start_date: Optional[datetime],
        end_date: Optional[datetime]
    ) -> Dict[str, Any]:
        """Get statistics by credit action"""
        async with self.db_factory() as db:
            date_filter = [
                CreditTransaction.tenant_id == tenant_id,
                CreditTransaction.transaction_type == CreditTransactionType.EARNED
            ]
            if start_date:
                date_filter.append(CreditTransaction.created_at >= start_date)
            if end_date:
                date_filter.append(CreditTransaction.created_at <= end_date)
            
            result = await db.execute(
                select(
                    CreditTransaction.action_key,
                    func.count(CreditTransaction.id).label('count'),
                    func.sum(CreditTransaction.amount).label('total_credits')
                ).where(and_(*date_filter))
                .group_by(CreditTransaction.action_key)
                .order_by(func.sum(CreditTransaction.amount).desc())
            )
            
            action_stats = {}
            for row in result:
                if row.action_key:
                    action_stats[row.action_key] = {
                        'count': row.count,
                        'total_credits': float(row.total_credits or 0),
                        'avg_credits': float(row.total_credits or 0) / row.count if row.count > 0 else 0
                    }
            
            return action_stats
    
    async def _calculate_health_metrics(
        self,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Calculate credit system health metrics"""
        async with self.db_factory() as db:
            # Get velocity metrics
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            result = await db.execute(
                select(
                    func.count(CreditTransaction.id).label('hourly_transactions'),
                    func.sum(case((CreditTransaction.amount > 0, CreditTransaction.amount), else_=0)).label('hourly_earned')
                ).where(
                    and_(
                        CreditTransaction.tenant_id == tenant_id,
                        CreditTransaction.created_at >= hour_ago
                    )
                )
            )
            
            velocity = result.first()
            
            # Get engagement rate (users earning in last 7 days)
            week_ago = datetime.utcnow() - timedelta(days=7)
            
            result = await db.execute(
                select(
                    func.count(func.distinct(CreditTransaction.user_id))
                ).where(
                    and_(
                        CreditTransaction.tenant_id == tenant_id,
                        CreditTransaction.created_at >= week_ago,
                        CreditTransaction.amount > 0
                    )
                )
            )
            active_earners = result.scalar() or 0
            
            # Get total users
            result = await db.execute(
                select(func.count(UserCredit.id)).where(
                    UserCredit.tenant_id == tenant_id
                )
            )
            total_users = result.scalar() or 0
            
            return {
                'velocity': {
                    'transactions_per_hour': velocity.hourly_transactions or 0,
                    'credits_per_hour': float(velocity.hourly_earned or 0)
                },
                'engagement': {
                    'weekly_active_earners': active_earners,
                    'engagement_rate': active_earners / total_users if total_users > 0 else 0
                }
            }