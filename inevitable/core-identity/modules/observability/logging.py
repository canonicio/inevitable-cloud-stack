"""
Logging configuration for Platform Forge
"""
import logging
import logging.config
import os
from typing import Dict, Any
from datetime import datetime
import json


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """
    Set up logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Format type ("json" or "text")
    """
    
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Get log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    if log_format.lower() == "json":
        formatter_class = "modules.observability.logging.JSONFormatter"
    else:
        formatter_class = "logging.Formatter"
    
    # Logging configuration
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": JSONFormatter,
            },
            "text": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level.upper(),
                "formatter": log_format.lower(),
                "stream": "ext://sys.stdout"
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": log_level.upper(),
                "formatter": log_format.lower(),
                "filename": f"{log_dir}/platform-forge.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5
            },
            "error_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": log_format.lower(),
                "filename": f"{log_dir}/platform-forge-error.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5
            },
            "security_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "WARNING",
                "formatter": log_format.lower(),
                "filename": f"{log_dir}/platform-forge-security.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 10
            }
        },
        "loggers": {
            "": {  # Root logger
                "level": log_level.upper(),
                "handlers": ["console", "file", "error_file"]
            },
            "modules.core.security": {
                "level": "WARNING",
                "handlers": ["security_file"],
                "propagate": False
            },
            "modules.billing.webhooks": {
                "level": "INFO",
                "handlers": ["console", "file"],
                "propagate": False
            },
            "modules.admin.audit_logs": {
                "level": "INFO",
                "handlers": ["console", "file", "security_file"],
                "propagate": False
            },
            "uvicorn": {
                "level": "INFO",
                "handlers": ["console", "file"],
                "propagate": False
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": ["console", "file"],
                "propagate": False
            }
        }
    }
    
    logging.config.dictConfig(config)
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info("Platform Forge logging configured", extra={
        "log_level": log_level,
        "log_format": log_format,
        "log_dir": log_dir
    })


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        
        # Base log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ["name", "msg", "args", "levelname", "levelno", "pathname", 
                          "filename", "module", "lineno", "funcName", "created", 
                          "msecs", "relativeCreated", "thread", "threadName", 
                          "processName", "process", "getMessage", "exc_info", 
                          "exc_text", "stack_info"]:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self):
        self.logger = logging.getLogger("modules.core.security")
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          severity: str = "WARNING", tenant_id: str = None) -> None:
        """Log a security event."""
        
        extra = {
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "tenant_id": tenant_id
        }
        
        if severity == "CRITICAL":
            self.logger.critical(f"Security event: {event_type}", extra=extra)
        elif severity == "ERROR":
            self.logger.error(f"Security event: {event_type}", extra=extra)
        elif severity == "WARNING":
            self.logger.warning(f"Security event: {event_type}", extra=extra)
        else:
            self.logger.info(f"Security event: {event_type}", extra=extra)
    
    def log_auth_failure(self, reason: str, user_id: str = None, 
                        tenant_id: str = None, ip_address: str = None) -> None:
        """Log authentication failure."""
        
        details = {
            "reason": reason,
            "user_id": user_id,
            "ip_address": ip_address
        }
        
        self.log_security_event("auth_failure", details, "WARNING", tenant_id)
    
    def log_unauthorized_access(self, resource: str, user_id: str = None,
                               tenant_id: str = None, ip_address: str = None) -> None:
        """Log unauthorized access attempt."""
        
        details = {
            "resource": resource,
            "user_id": user_id,
            "ip_address": ip_address
        }
        
        self.log_security_event("unauthorized_access", details, "ERROR", tenant_id)
    
    def log_tenant_isolation_violation(self, attempted_tenant: str, 
                                     actual_tenant: str, user_id: str = None,
                                     ip_address: str = None) -> None:
        """Log tenant isolation violation."""
        
        details = {
            "attempted_tenant": attempted_tenant,
            "actual_tenant": actual_tenant,
            "user_id": user_id,
            "ip_address": ip_address
        }
        
        self.log_security_event("tenant_isolation_violation", details, "CRITICAL")
    
    def log_rate_limit_exceeded(self, endpoint: str, user_id: str = None,
                              tenant_id: str = None, ip_address: str = None) -> None:
        """Log rate limit exceeded."""
        
        details = {
            "endpoint": endpoint,
            "user_id": user_id,
            "ip_address": ip_address
        }
        
        self.log_security_event("rate_limit_exceeded", details, "WARNING", tenant_id)


class AuditLogger:
    """Specialized logger for audit events."""
    
    def __init__(self):
        self.logger = logging.getLogger("modules.admin.audit_logs")
    
    def log_user_action(self, action: str, user_id: str, resource_type: str,
                       resource_id: str = None, tenant_id: str = None,
                       details: Dict[str, Any] = None) -> None:
        """Log user action for audit trail."""
        
        extra = {
            "action": action,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "tenant_id": tenant_id,
            "details": details or {}
        }
        
        self.logger.info(f"User action: {action}", extra=extra)
    
    def log_admin_action(self, action: str, admin_id: str, target_user_id: str = None,
                        tenant_id: str = None, details: Dict[str, Any] = None) -> None:
        """Log admin action for audit trail."""
        
        extra = {
            "action": action,
            "admin_id": admin_id,
            "target_user_id": target_user_id,
            "tenant_id": tenant_id,
            "details": details or {},
            "is_admin_action": True
        }
        
        self.logger.info(f"Admin action: {action}", extra=extra)
    
    def log_billing_event(self, event_type: str, customer_id: str, 
                         tenant_id: str = None, details: Dict[str, Any] = None) -> None:
        """Log billing event for audit trail."""
        
        extra = {
            "event_type": event_type,
            "customer_id": customer_id,
            "tenant_id": tenant_id,
            "details": details or {},
            "is_billing_event": True
        }
        
        self.logger.info(f"Billing event: {event_type}", extra=extra)


# Global logger instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()