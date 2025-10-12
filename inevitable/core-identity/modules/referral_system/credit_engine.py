"""
Dynamic credit engine with customer-configurable actions and rules
"""
import re
import ast
import operator
import random
import secrets
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from decimal import Decimal
import logging

from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    CreditAction, UserCredit, CreditTransaction,
    CreditTransactionType
)
from modules.core.security import SecurityUtils


logger = logging.getLogger(__name__)


class ValueCalculator:
    """Calculate dynamic credit values from formulas"""
    
    # Safe operators for formula evaluation
    SAFE_OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    
    # Safe functions
    SAFE_FUNCTIONS = {
        'min': min,
        'max': max,
        'abs': abs,
        'round': round,
        # CRITICAL-010 FIX: Use cryptographically secure random in sandbox
        'random': lambda a, b: secrets.randbelow(b - a + 1) + a,
    }
    
    def __init__(self):
        self.max_formula_length = 500
        self.max_result = 1000000  # Maximum credit value
    
    async def calculate(
        self,
        formula: str,
        context: Dict[str, Any]
    ) -> float:
        """
        Calculate value from formula
        
        Examples:
        - "100" -> 100
        - "10% of purchase.total" -> 0.1 * purchase['total']
        - "user.level * 50" -> user['level'] * 50
        - "min(100, user.referrals * 20)" -> min(100, user['referrals'] * 20)
        """
        if len(formula) > self.max_formula_length:
            raise ValueError("Formula too long")
        
        # Simple numeric value
        try:
            return float(formula)
        except ValueError:
            pass
        
        # Percentage format: "X% of path.to.value"
        percentage_match = re.match(r'(\d+(?:\.\d+)?)\s*%\s*of\s+(.+)', formula)
        if percentage_match:
            percentage = float(percentage_match.group(1)) / 100
            value_path = percentage_match.group(2).strip()
            base_value = self._get_value_from_path(context, value_path)
            return percentage * base_value
        
        # Parse and evaluate expression
        try:
            # Replace context references with values
            processed_formula = self._replace_context_refs(formula, context)
            
            # Parse and evaluate safely
            tree = ast.parse(processed_formula, mode='eval')
            result = self._eval_node(tree.body)
            
            # Ensure result is within bounds
            result = float(result)
            if result < 0:
                result = 0
            elif result > self.max_result:
                result = self.max_result
                
            return result
            
        except Exception as e:
            logger.error(f"Formula evaluation error: {e}")
            raise ValueError(f"Invalid formula: {formula}")
    
    def _get_value_from_path(
        self,
        context: Dict[str, Any],
        path: str
    ) -> float:
        """Get value from nested dictionary path"""
        parts = path.split('.')
        value = context
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                raise ValueError(f"Invalid path: {path}")
        
        return float(value)
    
    def _replace_context_refs(
        self,
        formula: str,
        context: Dict[str, Any]
    ) -> str:
        """Replace context references with actual values"""
        # Find all potential variable references
        pattern = r'\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\b'
        
        def replace_ref(match):
            ref = match.group(1)
            try:
                # Skip function names
                if ref in self.SAFE_FUNCTIONS:
                    return ref
                    
                value = self._get_value_from_path(context, ref)
                return str(value)
            except:
                # If not found in context, leave as is
                return ref
        
        return re.sub(pattern, replace_ref, formula)
    
    def _eval_node(self, node):
        """Safely evaluate AST node"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Num):  # Python < 3.8
            return node.n
        elif isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            op = type(node.op)
            if op in self.SAFE_OPERATORS:
                return self.SAFE_OPERATORS[op](left, right)
            else:
                raise ValueError(f"Unsafe operator: {op}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.SAFE_FUNCTIONS:
                args = [self._eval_node(arg) for arg in node.args]
                return self.SAFE_FUNCTIONS[node.func.id](*args)
            else:
                raise ValueError(f"Unsafe function call")
        else:
            raise ValueError(f"Unsafe node type: {type(node)}")


class CreditMultiplier:
    """Calculate and apply credit multipliers"""
    
    def __init__(self, multiplier_rules: List[Dict[str, Any]]):
        self.rules = multiplier_rules
        self.evaluator = ConditionEvaluator()
    
    async def calculate_multiplier(
        self,
        user_data: Dict[str, Any],
        context: Dict[str, Any]
    ) -> float:
        """Calculate total multiplier based on rules"""
        total_multiplier = 1.0
        
        for rule in self.rules:
            if await self.evaluator.evaluate(rule['condition'], user_data, context):
                # Multiplier can be static or dynamic
                if isinstance(rule['multiplier'], (int, float)):
                    multiplier = rule['multiplier']
                else:
                    # Dynamic multiplier formula
                    calculator = ValueCalculator()
                    multiplier = await calculator.calculate(
                        rule['multiplier'],
                        {'user': user_data, **context}
                    )
                
                # Apply stacking rule
                if rule.get('stacks', True):
                    total_multiplier *= multiplier
                else:
                    total_multiplier = max(total_multiplier, multiplier)
        
        return total_multiplier


class ConditionEvaluator:
    """Evaluate conditions for multipliers and rules"""
    
    def __init__(self):
        self.max_condition_length = 500
    
    async def evaluate(
        self,
        condition: str,
        user_data: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate condition string
        
        Examples:
        - "user.level > 5"
        - "user.total_spent >= 1000 OR user.referral_count > 20"
        - "hour >= 20 OR hour <= 6"
        - "date in holiday_dates"
        """
        if len(condition) > self.max_condition_length:
            raise ValueError("Condition too long")
        
        # Build evaluation context
        eval_context = {
            'user': user_data,
            'hour': datetime.utcnow().hour,
            'date': datetime.utcnow().date().isoformat(),
            'day_of_week': datetime.utcnow().weekday(),
            **context
        }
        
        # Replace context references
        processed = self._process_condition(condition, eval_context)
        
        try:
            # Parse and evaluate safely
            tree = ast.parse(processed, mode='eval')
            return self._eval_bool_node(tree.body, eval_context)
        except Exception as e:
            logger.error(f"Condition evaluation error: {e}")
            return False
    
    def _process_condition(
        self,
        condition: str,
        context: Dict[str, Any]
    ) -> str:
        """Process condition for safe evaluation"""
        # Replace logical operators
        condition = condition.replace(' OR ', ' or ')
        condition = condition.replace(' AND ', ' and ')
        condition = condition.replace(' NOT ', ' not ')
        
        return condition
    
    def _eval_bool_node(self, node, context):
        """Evaluate boolean AST node"""
        if isinstance(node, ast.Compare):
            left = self._eval_value_node(node.left, context)
            
            for op, comp in zip(node.ops, node.comparators):
                right = self._eval_value_node(comp, context)
                
                if isinstance(op, ast.Gt):
                    if not left > right:
                        return False
                elif isinstance(op, ast.GtE):
                    if not left >= right:
                        return False
                elif isinstance(op, ast.Lt):
                    if not left < right:
                        return False
                elif isinstance(op, ast.LtE):
                    if not left <= right:
                        return False
                elif isinstance(op, ast.Eq):
                    if not left == right:
                        return False
                elif isinstance(op, ast.NotEq):
                    if not left != right:
                        return False
                elif isinstance(op, ast.In):
                    if left not in right:
                        return False
                else:
                    raise ValueError(f"Unsafe comparison: {type(op)}")
                    
                left = right
            
            return True
            
        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(self._eval_bool_node(n, context) for n in node.values)
            elif isinstance(node.op, ast.Or):
                return any(self._eval_bool_node(n, context) for n in node.values)
            else:
                raise ValueError(f"Unsafe boolean operator: {type(node.op)}")
                
        else:
            # Try to evaluate as value and convert to bool
            value = self._eval_value_node(node, context)
            return bool(value)
    
    def _eval_value_node(self, node, context):
        """Evaluate value node"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Name):
            return context.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            obj = self._eval_value_node(node.value, context)
            if isinstance(obj, dict):
                return obj.get(node.attr)
            return None
        elif isinstance(node, ast.List):
            return [self._eval_value_node(n, context) for n in node.elts]
        else:
            raise ValueError(f"Unsafe value node: {type(node)}")


class CreditValidator:
    """Validate credit actions and limits"""
    
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
    
    async def validate_action(
        self,
        user_id: str,
        action: CreditAction,
        metadata: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """Validate if user can perform credit action"""
        
        # Check requirements
        if action.requirements:
            for key, value in action.requirements.items():
                if key == 'min_words' and 'content' in metadata:
                    word_count = len(metadata['content'].split())
                    if word_count < value:
                        return False, f"Content must have at least {value} words"
                        
                elif key == 'has_screenshot' and value:
                    if not metadata.get('has_screenshot'):
                        return False, "Screenshot required"
                        
                elif key == 'verified_account' and value:
                    if not metadata.get('user', {}).get('verified'):
                        return False, "Verified account required"
        
        # Check limits
        if action.one_time:
            existing = await self._check_one_time_action(user_id, action.action_key)
            if existing:
                return False, "This action can only be performed once"
        
        if action.daily_limit:
            count = await self._get_action_count(
                user_id,
                action.action_key,
                timedelta(days=1)
            )
            if count >= action.daily_limit:
                return False, f"Daily limit of {action.daily_limit} reached"
        
        if action.weekly_limit:
            count = await self._get_action_count(
                user_id,
                action.action_key,
                timedelta(days=7)
            )
            if count >= action.weekly_limit:
                return False, f"Weekly limit of {action.weekly_limit} reached"
        
        if action.monthly_limit:
            count = await self._get_action_count(
                user_id,
                action.action_key,
                timedelta(days=30)
            )
            if count >= action.monthly_limit:
                return False, f"Monthly limit of {action.monthly_limit} reached"
        
        return True, None
    
    async def _check_one_time_action(
        self,
        user_id: str,
        action_key: str
    ) -> bool:
        """Check if user has already performed one-time action"""
        result = await self.db.execute(
            select(CreditTransaction).where(
                and_(
                    CreditTransaction.user_id == user_id,
                    CreditTransaction.action_key == action_key
                )
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None
    
    async def _get_action_count(
        self,
        user_id: str,
        action_key: str,
        period: timedelta
    ) -> int:
        """Get count of actions in period"""
        since = datetime.utcnow() - period
        
        result = await self.db.execute(
            select(func.count(CreditTransaction.id)).where(
                and_(
                    CreditTransaction.user_id == user_id,
                    CreditTransaction.action_key == action_key,
                    CreditTransaction.created_at >= since
                )
            )
        )
        return result.scalar() or 0


class DynamicCreditEngine:
    """Main credit engine with dynamic configuration"""
    
    def __init__(
        self,
        db_factory,
        credit_config: Dict[str, Any]
    ):
        self.db_factory = db_factory
        self.config = credit_config
        self.value_calculator = ValueCalculator()
        self.fraud_checks_enabled = credit_config.get('anti_fraud', {}).get('enabled', True)
    
    async def load_actions(self, tenant_id: str) -> Dict[str, CreditAction]:
        """Load credit actions from database"""
        async with self.db_factory() as db:
            result = await db.execute(
                select(CreditAction).where(
                    and_(
                        CreditAction.tenant_id == tenant_id,
                        CreditAction.is_active == True
                    )
                )
            )
            actions = result.scalars().all()
            
            return {action.action_key: action for action in actions}
    
    async def award_credits(
        self,
        user_id: str,
        action_type: str,
        tenant_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CreditTransaction:
        """Award credits to user for action"""
        metadata = metadata or {}
        
        async with self.db_factory() as db:
            # Load action configuration
            actions = await self.load_actions(tenant_id)
            action = actions.get(action_type)
            
            if not action:
                raise ValueError(f"Unknown action type: {action_type}")
            
            # Validate action
            validator = CreditValidator(db)
            valid, error = await validator.validate_action(user_id, action, metadata)
            
            if not valid:
                raise ValueError(error)
            
            # Get user data for calculations
            user_credit = await self._get_or_create_user_credit(db, user_id, tenant_id)
            user_data = {
                'id': user_id,
                'balance': float(user_credit.balance),
                'lifetime_earned': float(user_credit.lifetime_earned),
                'tier': user_credit.tier,
                **metadata.get('user', {})
            }
            
            # Calculate base value
            base_value = await self.value_calculator.calculate(
                action.value_formula,
                {'user': user_data, **metadata}
            )
            
            # Apply multipliers
            multiplier = 1.0
            if action.multiplier_rules:
                multiplier_calc = CreditMultiplier(action.multiplier_rules)
                multiplier = await multiplier_calc.calculate_multiplier(
                    user_data,
                    metadata
                )
            
            # Apply user multiplier
            multiplier *= float(user_credit.multiplier)
            
            # Calculate final value
            final_value = Decimal(str(base_value * multiplier))
            
            # Check fraud
            if self.fraud_checks_enabled:
                if await self._check_fraud(user_id, action_type, final_value, metadata):
                    raise ValueError("Action flagged as potentially fraudulent")
            
            # Create transaction
            transaction = await self._create_transaction(
                db,
                user_credit,
                final_value,
                action_type,
                metadata,
                tenant_id
            )
            
            # Update action stats
            action.total_awarded += 1
            action.total_credits += final_value
            
            await db.commit()
            
            return transaction
    
    async def spend_credits(
        self,
        user_id: str,
        amount: Decimal,
        description: str,
        tenant_id: str,
        reference_type: Optional[str] = None,
        reference_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CreditTransaction:
        """Spend user credits"""
        async with self.db_factory() as db:
            user_credit = await self._get_or_create_user_credit(db, user_id, tenant_id)
            
            if user_credit.balance < amount:
                raise ValueError("Insufficient credits")
            
            # Create transaction
            balance_before = user_credit.balance
            user_credit.balance -= amount
            user_credit.lifetime_spent += amount
            
            transaction = CreditTransaction(
                user_id=user_id,
                amount=-amount,  # Negative for spending
                balance_before=balance_before,
                balance_after=user_credit.balance,
                transaction_type=CreditTransactionType.SPENT,
                description=description,
                reference_type=reference_type,
                reference_id=reference_id,
                metadata=metadata or {},
                tenant_id=tenant_id
            )
            
            db.add(transaction)
            await db.commit()
            
            return transaction
    
    async def get_balance(
        self,
        user_id: str,
        tenant_id: str
    ) -> Decimal:
        """Get user credit balance"""
        async with self.db_factory() as db:
            user_credit = await self._get_or_create_user_credit(db, user_id, tenant_id)
            return user_credit.balance
    
    async def transfer_credits(
        self,
        from_user_id: str,
        to_user_id: str,
        amount: Decimal,
        tenant_id: str,
        description: Optional[str] = None
    ) -> tuple[CreditTransaction, CreditTransaction]:
        """Transfer credits between users"""
        async with self.db_factory() as db:
            # Get both user credits
            from_credit = await self._get_or_create_user_credit(db, from_user_id, tenant_id)
            to_credit = await self._get_or_create_user_credit(db, to_user_id, tenant_id)
            
            if from_credit.balance < amount:
                raise ValueError("Insufficient credits")
            
            # Create transactions
            from_before = from_credit.balance
            to_before = to_credit.balance
            
            from_credit.balance -= amount
            to_credit.balance += amount
            
            from_transaction = CreditTransaction(
                user_id=from_user_id,
                amount=-amount,
                balance_before=from_before,
                balance_after=from_credit.balance,
                transaction_type=CreditTransactionType.TRANSFERRED,
                description=description or f"Transfer to {to_user_id}",
                reference_type="transfer",
                reference_id=to_user_id,
                tenant_id=tenant_id
            )
            
            to_transaction = CreditTransaction(
                user_id=to_user_id,
                amount=amount,
                balance_before=to_before,
                balance_after=to_credit.balance,
                transaction_type=CreditTransactionType.TRANSFERRED,
                description=description or f"Transfer from {from_user_id}",
                reference_type="transfer",
                reference_id=from_user_id,
                tenant_id=tenant_id
            )
            
            db.add(from_transaction)
            db.add(to_transaction)
            await db.commit()
            
            return from_transaction, to_transaction
    
    async def _get_or_create_user_credit(
        self,
        db: AsyncSession,
        user_id: str,
        tenant_id: str
    ) -> UserCredit:
        """Get or create user credit record"""
        result = await db.execute(
            select(UserCredit).where(
                and_(
                    UserCredit.user_id == user_id,
                    UserCredit.tenant_id == tenant_id
                )
            )
        )
        user_credit = result.scalar_one_or_none()
        
        if not user_credit:
            user_credit = UserCredit(
                user_id=user_id,
                tenant_id=tenant_id
            )
            db.add(user_credit)
        
        return user_credit
    
    async def _create_transaction(
        self,
        db: AsyncSession,
        user_credit: UserCredit,
        amount: Decimal,
        action_key: str,
        metadata: Dict[str, Any],
        tenant_id: str
    ) -> CreditTransaction:
        """Create credit transaction"""
        balance_before = user_credit.balance
        user_credit.balance += amount
        user_credit.lifetime_earned += amount
        
        # Update daily earned
        if user_credit.daily_limit_reset is None or \
           user_credit.daily_limit_reset < datetime.utcnow():
            user_credit.daily_earned_today = amount
            user_credit.daily_limit_reset = datetime.utcnow() + timedelta(days=1)
        else:
            user_credit.daily_earned_today += amount
        
        transaction = CreditTransaction(
            user_id=user_credit.user_id,
            amount=amount,
            balance_before=balance_before,
            balance_after=user_credit.balance,
            transaction_type=CreditTransactionType.EARNED,
            action_key=action_key,
            description=metadata.get('description', f"Earned from {action_key}"),
            metadata=metadata,
            tenant_id=tenant_id
        )
        
        # Set expiration if configured
        if self.config.get('expiration', {}).get('enabled'):
            period_days = self.config['expiration'].get('period_days', 365)
            transaction.expires_at = datetime.utcnow() + timedelta(days=period_days)
        
        db.add(transaction)
        
        return transaction
    
    async def _check_fraud(
        self,
        user_id: str,
        action_type: str,
        amount: Decimal,
        metadata: Dict[str, Any]
    ) -> bool:
        """Basic fraud checks"""
        # Check velocity
        max_daily = self.config.get('anti_fraud', {}).get('max_daily_earnings', 10000)
        
        async with self.db_factory() as db:
            user_credit = await self._get_or_create_user_credit(
                db,
                user_id,
                metadata.get('tenant_id', 'default')
            )
            
            if user_credit.daily_earned_today + amount > max_daily:
                return True
        
        # More sophisticated fraud checks would go here
        # - IP velocity checks
        # - Device fingerprinting
        # - Pattern analysis
        
        return False