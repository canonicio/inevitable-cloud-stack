"""
Safety Orchestrator - Main entry point for prompt injection protection
Provides a unified interface for the complete safety pipeline
"""
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from .core.content_blob import ContentBlob
from .core.normalizer import ContentNormalizer
from .core.classifier import InstructionalityClassifier
from .core.sanitizer import ContentSanitizer
from .core.instruction_gate import (
    InstructionGate, GateDecision, GateContext, LaneRouter
)

logger = logging.getLogger(__name__)


class SafetyOrchestrator:
    """
    Main orchestrator for the safety pipeline.
    Processes content through: Ingress → Normalize → Classify → Sanitize → Isolate → Gate → Execute
    """
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize the safety orchestrator.
        
        Args:
            strict_mode: If True, applies strictest security policies
        """
        self.normalizer = ContentNormalizer()
        self.classifier = InstructionalityClassifier()
        self.sanitizer = ContentSanitizer()
        self.gate = InstructionGate(strict_mode=strict_mode)
        self.router = LaneRouter(self.gate)
        
        # Metrics tracking
        self.metrics = {
            "total_processed": 0,
            "high_risk_blocked": 0,
            "quarantined": 0,
            "data_only": 0,
            "allowed": 0,
            "errors": 0
        }
    
    def process_content(
        self,
        text: str,
        source: str = "user_input",
        tenant_id: str = "default",
        author_id: str = "unknown",
        signature: Optional[str] = None
    ) -> Tuple[Dict[str, Any], ContentBlob]:
        """
        Process content through the complete safety pipeline.
        
        Args:
            text: The content to process
            source: Source of content (user_input, api, upload, mcp_controller)
            tenant_id: Tenant identifier
            author_id: Author identifier
            signature: Optional cryptographic signature for privileged content
            
        Returns:
            Tuple of (routing_decision, processed_blob)
        """
        try:
            # Step 1: Create content blob (INGRESS)
            blob = ContentBlob.from_user_input(
                text=text,
                tenant_id=tenant_id,
                author_id=author_id,
                source=source
            )
            
            logger.info(f"Processing content from {source} (tenant={tenant_id}, author={author_id})")
            
            # Step 2: NORMALIZE - Canonicalize and clean
            self.normalizer.normalize(blob)
            logger.debug(f"Normalized: {len(blob.raw_text)} → {len(blob.normalized_text)} chars")
            
            # Step 3: CLASSIFY - Detect threats and instructionality
            self.classifier.classify(blob)
            logger.info(
                f"Classification: instructionality={blob.safety_report['instructionality']}, "
                f"exfil_risk={blob.safety_report['exfil_risk']}, "
                f"trust={blob.trust['score']:.2f}"
            )
            
            # Step 4: SANITIZE - Neutralize and wrap
            wrapped_content = self.sanitizer.sanitize(blob)
            logger.debug(f"Sanitized and wrapped content")
            
            # Step 5: ISOLATE & GATE - Route through two-lane architecture
            routing = self.router.route_message(blob, signature)
            logger.info(f"Routing decision: {routing['action']} (lane={routing.get('lane', 'unknown')})")
            
            # Update metrics
            self._update_metrics(routing)
            
            # Step 6: Return routing decision and processed blob
            return routing, blob
            
        except Exception as e:
            logger.error(f"Safety pipeline error: {e}", exc_info=True)
            self.metrics["errors"] += 1
            
            # Create error routing
            error_routing = {
                "action": "error",
                "lane": "blocked",
                "tools_allowed": False,
                "error": str(e)
            }
            
            return error_routing, blob if 'blob' in locals() else None
        
        finally:
            self.metrics["total_processed"] += 1
    
    def process_with_context(
        self,
        text: str,
        context: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], ContentBlob]:
        """
        Process content with additional context.
        
        Args:
            text: The content to process
            context: Additional context including source, tenant, author, etc.
            
        Returns:
            Tuple of (routing_decision, processed_blob)
        """
        return self.process_content(
            text=text,
            source=context.get("source", "user_input"),
            tenant_id=context.get("tenant_id", "default"),
            author_id=context.get("author_id", "unknown"),
            signature=context.get("signature")
        )
    
    def _update_metrics(self, routing: Dict[str, Any]):
        """Update metrics based on routing decision."""
        action = routing.get("action", "unknown")
        
        if action == "require_human_review":
            self.metrics["quarantined"] += 1
        elif action == "process_as_data":
            self.metrics["data_only"] += 1
        elif action == "process_with_tools":
            self.metrics["allowed"] += 1
        elif action in ["reject", "error"]:
            self.metrics["high_risk_blocked"] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        metrics = self.metrics.copy()
        
        # Add calculated metrics
        if metrics["total_processed"] > 0:
            metrics["quarantine_rate"] = metrics["quarantined"] / metrics["total_processed"]
            metrics["block_rate"] = metrics["high_risk_blocked"] / metrics["total_processed"]
            metrics["allow_rate"] = metrics["allowed"] / metrics["total_processed"]
            metrics["error_rate"] = metrics["errors"] / metrics["total_processed"]
        
        # Add gate metrics
        metrics["gate_metrics"] = self.gate.get_metrics()
        
        return metrics
    
    def reset_metrics(self):
        """Reset metrics counters."""
        self.metrics = {
            "total_processed": 0,
            "high_risk_blocked": 0,
            "quarantined": 0,
            "data_only": 0,
            "allowed": 0,
            "errors": 0
        }


class SafetyAPI:
    """
    High-level API for easy integration with Platform Forge.
    """
    
    def __init__(self, strict_mode: bool = True):
        self.orchestrator = SafetyOrchestrator(strict_mode=strict_mode)
    
    def check_prompt(self, prompt: str, tenant_id: str = "default") -> Dict[str, Any]:
        """
        Quick check if a prompt is safe.
        
        Returns:
            Dict with keys: safe, threat_level, action, reason
        """
        routing, blob = self.orchestrator.process_content(
            text=prompt,
            tenant_id=tenant_id
        )
        
        # Determine safety
        safe = routing["action"] not in ["require_human_review", "reject", "error"]
        
        # Get threat level
        if blob and blob.safety_report:
            threat_level = blob.safety_report.get("instructionality", "unknown")
        else:
            threat_level = "unknown"
        
        return {
            "safe": safe,
            "threat_level": threat_level,
            "action": routing["action"],
            "reason": routing.get("reason", ""),
            "trust_score": blob.trust["score"] if blob else 0.0,
            "tools_allowed": routing.get("tools_allowed", False)
        }
    
    def process_mcp_message(
        self,
        message: str,
        is_controller: bool = False,
        signature: Optional[str] = None,
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Process an MCP message with appropriate security controls.
        
        Args:
            message: The message content
            is_controller: Whether this is a controller message
            signature: Cryptographic signature if controller message
            tenant_id: Tenant identifier
            
        Returns:
            Processing result with routing and safety information
        """
        source = "mcp_controller" if is_controller else "user_input"
        
        routing, blob = self.orchestrator.process_content(
            text=message,
            source=source,
            tenant_id=tenant_id,
            signature=signature
        )
        
        return {
            "routing": routing,
            "safe_content": blob.sanitized_text if blob else None,
            "metadata": {
                "trust_score": blob.trust["score"] if blob else 0.0,
                "threat_level": blob.safety_report.get("instructionality") if blob else "unknown",
                "tool_requests": blob.safety_report.get("tool_requests", []) if blob else [],
                "lane": routing.get("lane", "unknown")
            }
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current safety metrics."""
        return self.orchestrator.get_metrics()


# Global API instance for easy access
safety_api = SafetyAPI(strict_mode=True)


# Convenience functions for direct use
def check_prompt_safety(prompt: str, tenant_id: str = "default") -> bool:
    """Quick check if a prompt is safe."""
    result = safety_api.check_prompt(prompt, tenant_id)
    return result["safe"]


def process_user_input(
    text: str,
    tenant_id: str = "default",
    author_id: str = "unknown"
) -> Dict[str, Any]:
    """Process user input through safety pipeline."""
    orchestrator = SafetyOrchestrator(strict_mode=True)
    routing, blob = orchestrator.process_content(
        text=text,
        source="user_input",
        tenant_id=tenant_id,
        author_id=author_id
    )
    
    return {
        "action": routing["action"],
        "safe_content": blob.sanitized_text if blob else text,
        "tools_allowed": routing.get("tools_allowed", False),
        "requires_review": routing["action"] == "require_human_review"
    }