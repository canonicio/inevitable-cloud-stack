"""
Content Blob - Unified data model for all content processing
Tracks content through the entire safety pipeline with full provenance
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib
import json


@dataclass
class ContentBlob:
    """
    Unified content container that tracks data through the safety pipeline.
    Maintains full provenance and safety analysis results.
    """
    # Identity
    id: str
    source: str  # "api" | "upload" | "user_input" | "mcp_context"
    tenant_id: str
    author_id: str
    created_at: str
    
    # Content
    raw_text: str = ""
    media: List[Dict[str, Any]] = field(default_factory=list)
    normalized_text: str = ""
    sanitized_text: str = ""
    
    # Analysis
    labels: List[str] = field(default_factory=list)
    safety_report: Dict[str, Any] = field(default_factory=dict)
    
    # Trust and provenance
    trust: Dict[str, Any] = field(default_factory=lambda: {
        "score": 0.2,
        "rationale": "untrusted ingress",
        "history": []
    })
    provenance: Dict[str, Any] = field(default_factory=lambda: {
        "chain": [],
        "signatures": [],
        "transformations": []
    })
    
    # Processing metadata
    chunk_ids: List[str] = field(default_factory=list)
    processing_flags: Dict[str, Any] = field(default_factory=dict)
    lane: str = "data"  # "data" | "control"
    
    def add_provenance(self, stage: str, action: str, details: Optional[Dict] = None):
        """Add a provenance record for audit trail."""
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "stage": stage,
            "action": action,
            "details": details or {}
        }
        self.provenance["chain"].append(record)
    
    def update_trust(self, new_score: float, rationale: str):
        """Update trust score with history tracking."""
        self.trust["history"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "old_score": self.trust["score"],
            "new_score": new_score,
            "rationale": rationale
        })
        self.trust["score"] = new_score
        self.trust["rationale"] = rationale
    
    def generate_chunk_id(self, text: str) -> str:
        """Generate stable chunk ID using SHA256."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    def to_json(self) -> str:
        """Serialize to JSON for storage/transmission."""
        return json.dumps({
            "id": self.id,
            "source": self.source,
            "tenant_id": self.tenant_id,
            "author_id": self.author_id,
            "created_at": self.created_at,
            "raw_text": self.raw_text[:1000],  # Truncate for safety
            "normalized_text": self.normalized_text[:1000],
            "sanitized_text": self.sanitized_text[:1000],
            "labels": self.labels,
            "trust": self.trust,
            "provenance": self.provenance,
            "safety_report": self.safety_report,
            "lane": self.lane
        }, indent=2)
    
    @classmethod
    def from_user_input(
        cls,
        text: str,
        tenant_id: str,
        author_id: str,
        source: str = "user_input"
    ) -> "ContentBlob":
        """Factory method to create blob from user input."""
        import uuid
        
        blob = cls(
            id=str(uuid.uuid4()),
            source=source,
            tenant_id=tenant_id,
            author_id=author_id,
            created_at=datetime.utcnow().isoformat(),
            raw_text=text
        )
        blob.add_provenance("ingress", "received", {"source": source})
        return blob