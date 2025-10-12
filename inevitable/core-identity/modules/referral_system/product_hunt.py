"""
Product Hunt launch campaign tools
"""
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import aiohttp
import logging
from bs4 import BeautifulSoup

from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    ProductHuntActivity, CreditAction, CreditTransaction,
    UserCredit
)
from .credit_engine import DynamicCreditEngine


logger = logging.getLogger(__name__)


class ProductHuntVerifier:
    """Verify Product Hunt activities"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://api.producthunt.com/v2/api/graphql"
    
    async def verify_upvote(
        self,
        product_id: str,
        user_id: str,
        ph_username: str
    ) -> Dict[str, Any]:
        """Verify user upvoted the product"""
        # In production, would use Product Hunt API
        # For now, return mock verification
        return {
            'verified': True,
            'timestamp': datetime.utcnow(),
            'position': 1  # Product position
        }
    
    async def verify_review(
        self,
        product_id: str,
        user_id: str,
        ph_username: str,
        review_url: str
    ) -> Dict[str, Any]:
        """Verify and analyze review"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(review_url) as response:
                    if response.status != 200:
                        return {'verified': False, 'error': 'Invalid URL'}
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract review content (simplified)
                    review_data = {
                        'verified': True,
                        'timestamp': datetime.utcnow(),
                        'has_screenshot': False,  # Would check for images
                        'word_count': 0,
                        'content': ""
                    }
                    
                    # In production, would parse actual review content
                    # and verify it's from the claimed user
                    
                    return review_data
                    
        except Exception as e:
            logger.error(f"Review verification error: {e}")
            return {'verified': False, 'error': str(e)}
    
    async def verify_share(
        self,
        product_id: str,
        share_url: str,
        platform: str
    ) -> Dict[str, Any]:
        """Verify social media share"""
        if platform == "x_com":
            return await self._verify_x_share(share_url)
        elif platform == "linkedin":
            return await self._verify_linkedin_share(share_url)
        else:
            return {'verified': False, 'error': 'Unsupported platform'}
    
    async def _verify_x_share(self, tweet_url: str) -> Dict[str, Any]:
        """Verify X.com (Twitter) share"""
        # Extract tweet ID from URL
        # Format: https://x.com/username/status/1234567890
        
        # In production, would use X API to verify
        # - Tweet exists
        # - Contains Product Hunt link
        # - From claimed user
        
        return {
            'verified': True,
            'timestamp': datetime.utcnow(),
            'engagement': {
                'likes': 0,
                'retweets': 0,
                'replies': 0
            }
        }
    
    async def _verify_linkedin_share(self, post_url: str) -> Dict[str, Any]:
        """Verify LinkedIn share"""
        # In production, would use LinkedIn API
        return {
            'verified': True,
            'timestamp': datetime.utcnow()
        }


class LaunchDayAutomation:
    """Automate Product Hunt launch day activities"""
    
    def __init__(
        self,
        db_factory,
        credit_engine: DynamicCreditEngine,
        verifier: ProductHuntVerifier
    ):
        self.db_factory = db_factory
        self.credit_engine = credit_engine
        self.verifier = verifier
        self.active_campaigns = {}
    
    async def start_campaign(
        self,
        campaign_config: Dict[str, Any],
        tenant_id: str
    ) -> str:
        """Start automated launch campaign"""
        campaign_id = f"ph_campaign_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Create campaign task
        campaign_task = asyncio.create_task(
            self._run_campaign(campaign_id, campaign_config, tenant_id)
        )
        
        self.active_campaigns[campaign_id] = {
            'task': campaign_task,
            'config': campaign_config,
            'started_at': datetime.utcnow(),
            'tenant_id': tenant_id
        }
        
        return campaign_id
    
    async def _run_campaign(
        self,
        campaign_id: str,
        config: Dict[str, Any],
        tenant_id: str
    ):
        """Run campaign automation"""
        try:
            # Schedule milestone checks
            milestones = config.get('milestones', [])
            for milestone in milestones:
                asyncio.create_task(
                    self._check_milestone(
                        campaign_id,
                        milestone,
                        tenant_id
                    )
                )
            
            # Run periodic leaderboard updates
            while campaign_id in self.active_campaigns:
                await self._update_leaderboard(campaign_id, tenant_id)
                await asyncio.sleep(300)  # Every 5 minutes
                
        except Exception as e:
            logger.error(f"Campaign error: {e}")
    
    async def _check_milestone(
        self,
        campaign_id: str,
        milestone: Dict[str, Any],
        tenant_id: str
    ):
        """Check and reward milestone achievements"""
        position_target = milestone.get('position')
        bonus_credits = milestone.get('bonus', 0)
        distribution = milestone.get('distribution', 'equal')
        
        # Wait for milestone time or position
        # In production, would poll Product Hunt API
        
        async with self.db_factory() as db:
            # Get contributors
            result = await db.execute(
                select(ProductHuntActivity).where(
                    and_(
                        ProductHuntActivity.tenant_id == tenant_id,
                        ProductHuntActivity.verification_status == 'verified'
                    )
                ).order_by(ProductHuntActivity.credits_awarded.desc())
            )
            contributors = result.scalars().all()
            
            if not contributors:
                return
            
            # Distribute bonus
            if distribution == 'equal':
                per_user = bonus_credits / len(contributors)
                for contributor in contributors:
                    await self._award_bonus(
                        contributor.user_id,
                        per_user,
                        f"Milestone bonus - Position {position_target}",
                        tenant_id
                    )
            
            elif distribution == 'proportional':
                total_earned = sum(c.credits_awarded for c in contributors)
                if total_earned > 0:
                    for contributor in contributors:
                        share = contributor.credits_awarded / total_earned
                        bonus = bonus_credits * share
                        await self._award_bonus(
                            contributor.user_id,
                            bonus,
                            f"Milestone bonus - Position {position_target}",
                            tenant_id
                        )
            
            elif distribution == 'top_contributors':
                # Top 10 get bonus
                for i, contributor in enumerate(contributors[:10]):
                    # Decreasing bonus for lower ranks
                    rank_multiplier = 1 - (i * 0.05)  # 5% less per rank
                    bonus = (bonus_credits / 10) * rank_multiplier
                    await self._award_bonus(
                        contributor.user_id,
                        bonus,
                        f"Top contributor bonus - Rank {i+1}",
                        tenant_id
                    )
    
    async def _award_bonus(
        self,
        user_id: str,
        amount: float,
        description: str,
        tenant_id: str
    ):
        """Award bonus credits"""
        try:
            await self.credit_engine.award_credits(
                user_id,
                'milestone_bonus',
                tenant_id,
                {
                    'amount': amount,
                    'description': description
                }
            )
        except Exception as e:
            logger.error(f"Bonus award error: {e}")
    
    async def _update_leaderboard(
        self,
        campaign_id: str,
        tenant_id: str
    ):
        """Update live leaderboard"""
        # This would be called periodically to update rankings
        # and trigger real-time updates to connected clients
        pass


class LeaderboardManager:
    """Manage Product Hunt campaign leaderboards"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.leaderboard_cache = {}
    
    async def get_leaderboard(
        self,
        tenant_id: str,
        limit: int = 50,
        activity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get current leaderboard"""
        async with self.db_factory() as db:
            # Base query
            query = select(
                ProductHuntActivity.user_id,
                ProductHuntActivity.ph_username,
                func.sum(ProductHuntActivity.credits_awarded).label('total_credits'),
                func.count(ProductHuntActivity.id).label('activity_count')
            ).where(
                and_(
                    ProductHuntActivity.tenant_id == tenant_id,
                    ProductHuntActivity.verification_status == 'verified'
                )
            ).group_by(
                ProductHuntActivity.user_id,
                ProductHuntActivity.ph_username
            ).order_by(
                func.sum(ProductHuntActivity.credits_awarded).desc()
            ).limit(limit)
            
            if activity_type:
                query = query.where(
                    ProductHuntActivity.activity_type == activity_type
                )
            
            result = await db.execute(query)
            leaders = result.all()
            
            # Format leaderboard
            leaderboard = []
            for i, leader in enumerate(leaders):
                entry = {
                    'rank': i + 1,
                    'user_id': leader.user_id,
                    'username': leader.ph_username or 'Anonymous',
                    'total_credits': float(leader.total_credits),
                    'activity_count': leader.activity_count,
                    'badge': self._get_badge(i + 1)
                }
                
                # Get activity breakdown
                breakdown = await self._get_activity_breakdown(
                    db,
                    leader.user_id,
                    tenant_id
                )
                entry['activities'] = breakdown
                
                leaderboard.append(entry)
            
            return leaderboard
    
    async def get_user_rank(
        self,
        user_id: str,
        tenant_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get specific user's rank"""
        async with self.db_factory() as db:
            # Get user's total credits
            result = await db.execute(
                select(
                    func.sum(ProductHuntActivity.credits_awarded)
                ).where(
                    and_(
                        ProductHuntActivity.user_id == user_id,
                        ProductHuntActivity.tenant_id == tenant_id,
                        ProductHuntActivity.verification_status == 'verified'
                    )
                )
            )
            user_credits = result.scalar() or 0
            
            if user_credits == 0:
                return None
            
            # Count users with more credits
            result = await db.execute(
                select(func.count(func.distinct(ProductHuntActivity.user_id))).where(
                    and_(
                        ProductHuntActivity.tenant_id == tenant_id,
                        ProductHuntActivity.verification_status == 'verified'
                    )
                ).group_by(ProductHuntActivity.user_id).having(
                    func.sum(ProductHuntActivity.credits_awarded) > user_credits
                )
            )
            higher_count = len(result.all())
            
            rank = higher_count + 1
            
            return {
                'user_id': user_id,
                'rank': rank,
                'total_credits': float(user_credits),
                'badge': self._get_badge(rank)
            }
    
    async def _get_activity_breakdown(
        self,
        db: AsyncSession,
        user_id: str,
        tenant_id: str
    ) -> Dict[str, int]:
        """Get breakdown of user's activities"""
        result = await db.execute(
            select(
                ProductHuntActivity.activity_type,
                func.count(ProductHuntActivity.id)
            ).where(
                and_(
                    ProductHuntActivity.user_id == user_id,
                    ProductHuntActivity.tenant_id == tenant_id,
                    ProductHuntActivity.verification_status == 'verified'
                )
            ).group_by(ProductHuntActivity.activity_type)
        )
        
        breakdown = {}
        for activity_type, count in result:
            breakdown[activity_type] = count
        
        return breakdown
    
    def _get_badge(self, rank: int) -> str:
        """Get badge for rank"""
        if rank == 1:
            return "🏆 Launch Champion"
        elif rank <= 3:
            return "🥇 Launch Hero"
        elif rank <= 10:
            return "🥈 Top Supporter"
        elif rank <= 50:
            return "🥉 Early Supporter"
        else:
            return "⭐ Supporter"


class ProductHuntCampaign:
    """Main Product Hunt campaign manager"""
    
    def __init__(
        self,
        db_factory,
        credit_engine: DynamicCreditEngine,
        campaign_config: Dict[str, Any]
    ):
        self.db_factory = db_factory
        self.credit_engine = credit_engine
        self.config = campaign_config
        self.verifier = ProductHuntVerifier()
        self.automation = LaunchDayAutomation(
            db_factory,
            credit_engine,
            self.verifier
        )
        self.leaderboard = LeaderboardManager(db_factory)
    
    async def process_activity(
        self,
        user_id: str,
        activity_type: str,
        activity_data: Dict[str, Any],
        tenant_id: str
    ) -> Dict[str, Any]:
        """Process Product Hunt activity"""
        async with self.db_factory() as db:
            # Check if activity already recorded
            existing = await db.execute(
                select(ProductHuntActivity).where(
                    and_(
                        ProductHuntActivity.user_id == user_id,
                        ProductHuntActivity.activity_type == activity_type,
                        ProductHuntActivity.tenant_id == tenant_id
                    )
                )
            )
            if existing.scalar_one_or_none():
                return {
                    'success': False,
                    'error': 'Activity already recorded'
                }
            
            # Verify activity
            verification = await self._verify_activity(
                activity_type,
                activity_data
            )
            
            if not verification.get('verified'):
                return {
                    'success': False,
                    'error': verification.get('error', 'Verification failed')
                }
            
            # Create activity record
            activity = ProductHuntActivity(
                user_id=user_id,
                ph_username=activity_data.get('ph_username'),
                activity_type=activity_type,
                activity_timestamp=verification.get('timestamp', datetime.utcnow()),
                verification_status='verified',
                verification_data=verification,
                proof_url=activity_data.get('proof_url'),
                content=activity_data.get('content'),
                has_screenshot=verification.get('has_screenshot', False),
                word_count=verification.get('word_count', 0),
                product_position=verification.get('position'),
                is_top_hunter=activity_data.get('is_top_hunter', False),
                tenant_id=tenant_id
            )
            
            # Calculate credits
            credits = await self._calculate_credits(
                activity_type,
                activity,
                activity_data
            )
            
            # Award credits
            try:
                transaction = await self.credit_engine.award_credits(
                    user_id,
                    f"ph_{activity_type}",
                    tenant_id,
                    {
                        'activity_id': activity.activity_id,
                        'description': f"Product Hunt {activity_type}"
                    }
                )
                
                activity.credits_awarded = transaction.amount
                activity.credit_transaction_id = transaction.transaction_id
                
            except Exception as e:
                logger.error(f"Credit award error: {e}")
                return {
                    'success': False,
                    'error': 'Failed to award credits'
                }
            
            db.add(activity)
            await db.commit()
            
            # Get user's new rank
            rank_info = await self.leaderboard.get_user_rank(user_id, tenant_id)
            
            return {
                'success': True,
                'credits_earned': float(credits),
                'total_credits': float(transaction.balance_after),
                'rank': rank_info.get('rank') if rank_info else None,
                'badge': rank_info.get('badge') if rank_info else None
            }
    
    async def _verify_activity(
        self,
        activity_type: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify activity based on type"""
        product_id = data.get('product_id', 'platform-forge')
        
        if activity_type == 'upvote':
            return await self.verifier.verify_upvote(
                product_id,
                data.get('user_id'),
                data.get('ph_username')
            )
        
        elif activity_type == 'review':
            return await self.verifier.verify_review(
                product_id,
                data.get('user_id'),
                data.get('ph_username'),
                data.get('review_url')
            )
        
        elif activity_type == 'share':
            return await self.verifier.verify_share(
                product_id,
                data.get('share_url'),
                data.get('platform', 'x_com')
            )
        
        else:
            return {'verified': False, 'error': 'Unknown activity type'}
    
    async def _calculate_credits(
        self,
        activity_type: str,
        activity: ProductHuntActivity,
        data: Dict[str, Any]
    ) -> float:
        """Calculate credits for activity"""
        # Get base credits from config
        action_config = self.config.get('credit_actions', {}).get(f"ph_{activity_type}", {})
        base_credits = action_config.get('value', 0)
        
        # Apply multipliers
        multiplier = 1.0
        
        if activity.has_screenshot:
            multiplier *= action_config.get('multipliers', {}).get('with_screenshot', 1.5)
        
        if activity.is_top_hunter:
            multiplier *= action_config.get('multipliers', {}).get('top_hunter', 2.0)
        
        if activity.product_position and activity.product_position <= 5:
            multiplier *= 1.5  # Bonus for top 5 products
        
        return base_credits * multiplier