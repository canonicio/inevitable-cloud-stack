"""
Health checking functionality for Platform Forge
"""
import asyncio
import logging
from typing import Dict, Any
from datetime import datetime
from sqlalchemy import text
from modules.core.database import get_db
import redis
import os

logger = logging.getLogger(__name__)


class HealthChecker:
    """Health checking service."""
    
    def __init__(self):
        self.checks = {
            'database': self._check_database,
            'redis': self._check_redis,
            'disk_space': self._check_disk_space,
            'memory': self._check_memory,
        }
    
    async def check_health(self) -> Dict[str, Any]:
        """Perform all health checks."""
        results = {}
        overall_status = "healthy"
        
        for check_name, check_func in self.checks.items():
            try:
                result = await check_func()
                results[check_name] = result
                
                if result.get('status') != 'healthy':
                    overall_status = "unhealthy"
                    
            except Exception as e:
                logger.error(f"Health check {check_name} failed: {e}")
                results[check_name] = {
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }
                overall_status = "unhealthy"
        
        return {
            'status': overall_status,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': results
        }
    
    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity."""
        try:
            # CRITICAL FIX: Properly handle database session generator
            db_gen = get_db()
            db = next(db_gen)
            
            try:
                # Simple query to check connectivity
                result = db.execute(text("SELECT 1")).scalar()
                
                if result == 1:
                    return {
                        'status': 'healthy',
                        'message': 'Database connection successful',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                else:
                    return {
                        'status': 'unhealthy',
                        'message': 'Database query returned unexpected result',
                        'timestamp': datetime.utcnow().isoformat()
                    }
            finally:
                # Ensure database session is closed
                db.close()
                
        except StopIteration:
            # Handle case where generator is exhausted
            return {
                'status': 'unhealthy',
                'message': 'Database session generator exhausted',
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Database connection failed: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def _check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity."""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            r = redis.from_url(redis_url)
            
            # Simple ping test
            result = r.ping()
            
            if result:
                return {
                    'status': 'healthy',
                    'message': 'Redis connection successful',
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'status': 'unhealthy',
                    'message': 'Redis ping failed',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Redis connection failed: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space."""
        try:
            import shutil
            
            # Check root filesystem
            total, used, free = shutil.disk_usage('/')
            
            # Calculate percentage used
            used_percent = (used / total) * 100
            
            # Alert if disk usage is above 80%
            if used_percent > 80:
                status = 'unhealthy'
                message = f'Disk usage high: {used_percent:.1f}%'
            elif used_percent > 70:
                status = 'warning'
                message = f'Disk usage moderate: {used_percent:.1f}%'
            else:
                status = 'healthy'
                message = f'Disk usage normal: {used_percent:.1f}%'
            
            return {
                'status': status,
                'message': message,
                'details': {
                    'total_bytes': total,
                    'used_bytes': used,
                    'free_bytes': free,
                    'used_percent': used_percent
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Disk space check failed: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def _check_memory(self) -> Dict[str, Any]:
        """Check memory usage."""
        try:
            import psutil
            
            # Get memory info
            memory = psutil.virtual_memory()
            
            # Alert if memory usage is above 80%
            if memory.percent > 80:
                status = 'unhealthy'
                message = f'Memory usage high: {memory.percent:.1f}%'
            elif memory.percent > 70:
                status = 'warning'
                message = f'Memory usage moderate: {memory.percent:.1f}%'
            else:
                status = 'healthy'
                message = f'Memory usage normal: {memory.percent:.1f}%'
            
            return {
                'status': status,
                'message': message,
                'details': {
                    'total_bytes': memory.total,
                    'used_bytes': memory.used,
                    'free_bytes': memory.available,
                    'used_percent': memory.percent
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ImportError:
            return {
                'status': 'warning',
                'message': 'psutil not available for memory checking',
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Memory check failed: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }


# Global health checker instance
health_checker = HealthChecker()


async def health_check() -> Dict[str, Any]:
    """Perform health check."""
    return await health_checker.check_health()


async def readiness_check() -> Dict[str, Any]:
    """Check if the application is ready to serve requests."""
    # For now, just check critical dependencies
    critical_checks = ['database', 'redis']
    
    results = {}
    overall_status = "ready"
    
    for check_name in critical_checks:
        try:
            if check_name == 'database':
                result = await health_checker._check_database()
            elif check_name == 'redis':
                result = await health_checker._check_redis()
            else:
                continue
                
            results[check_name] = result
            
            if result.get('status') not in ['healthy', 'warning']:
                overall_status = "not_ready"
                
        except Exception as e:
            logger.error(f"Readiness check {check_name} failed: {e}")
            results[check_name] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
            overall_status = "not_ready"
    
    return {
        'status': overall_status,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': results
    }


async def liveness_check() -> Dict[str, Any]:
    """Check if the application is alive."""
    # Simple liveness check - just return that we're alive
    return {
        'status': 'alive',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'Application is running'
    }