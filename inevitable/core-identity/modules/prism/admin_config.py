"""
Dynamic Admin Configuration for PRISM Intelligence Models
Uses Platform Forge's CRUD generator to provide admin interfaces for PRISM data
"""

from modules.admin.crud_generator import CRUDConfig, FieldConfig
from typing import List

# Configure CRUD for PRISM models
def get_prism_crud_configs() -> List[CRUDConfig]:
    """
    Get CRUD configurations for all PRISM models.
    These will be dynamically added to the admin interface.
    """
    return [
        # Belief Analysis Results
        CRUDConfig(
            model_name="BeliefAnalysis",
            table_name="belief_analyses",
            display_name="Belief Analyses",
            description="BeliefLattice epistemic analysis results",
            fields=[
                FieldConfig("id", "UUID", primary_key=True, display_name="Analysis ID"),
                FieldConfig("question", "String", required=True, display_name="Question"),
                FieldConfig("cultural_perspectives", "JSON", display_name="Cultural Perspectives"),
                FieldConfig("belief_shards", "JSON", display_name="Belief Shards"),
                FieldConfig("confidence_score", "Float", display_name="Confidence Score"),
                FieldConfig("result", "JSON", display_name="Full Analysis"),
                FieldConfig("user_email", "String", display_name="Requested By"),
                FieldConfig("created_at", "DateTime", display_name="Created At"),
                FieldConfig("processing_time", "Float", display_name="Processing Time (s)")
            ],
            searchable_fields=["question", "user_email"],
            sortable_fields=["created_at", "confidence_score", "processing_time"],
            filterable_fields=["user_email", "confidence_score"],
            default_sort="created_at",
            default_sort_order="desc"
        ),

        # Causal Analysis Results
        CRUDConfig(
            model_name="CausalAnalysis",
            table_name="causal_analyses",
            display_name="Causal Analyses",
            description="CausalLattice causal inference results",
            fields=[
                FieldConfig("id", "UUID", primary_key=True, display_name="Analysis ID"),
                FieldConfig("question", "String", required=True, display_name="Question"),
                FieldConfig("context", "Text", display_name="Context"),
                FieldConfig("analysis_type", "String", display_name="Analysis Type"),
                FieldConfig("causal_graph", "JSON", display_name="Causal Graph"),
                FieldConfig("interventions", "JSON", display_name="Interventions"),
                FieldConfig("confidence_score", "Float", display_name="Confidence Score"),
                FieldConfig("user_email", "String", display_name="Requested By"),
                FieldConfig("created_at", "DateTime", display_name="Created At"),
                FieldConfig("processing_time", "Float", display_name="Processing Time (s)")
            ],
            searchable_fields=["question", "context", "user_email"],
            sortable_fields=["created_at", "confidence_score", "processing_time"],
            filterable_fields=["user_email", "analysis_type", "confidence_score"],
            default_sort="created_at",
            default_sort_order="desc"
        ),

        # Stakeholder Analysis Results
        CRUDConfig(
            model_name="StakeholderAnalysis",
            table_name="stakeholder_analyses",
            display_name="Stakeholder Analyses",
            description="WithPI stakeholder behavior analysis results",
            fields=[
                FieldConfig("id", "UUID", primary_key=True, display_name="Analysis ID"),
                FieldConfig("question", "String", required=True, display_name="Question"),
                FieldConfig("stakeholders", "JSON", display_name="Stakeholders"),
                FieldConfig("behavior_patterns", "JSON", display_name="Behavior Patterns"),
                FieldConfig("influence_scores", "JSON", display_name="Influence Scores"),
                FieldConfig("recommendations", "JSON", display_name="Recommendations"),
                FieldConfig("user_email", "String", display_name="Requested By"),
                FieldConfig("created_at", "DateTime", display_name="Created At")
            ],
            searchable_fields=["question", "user_email"],
            sortable_fields=["created_at"],
            filterable_fields=["user_email"],
            default_sort="created_at",
            default_sort_order="desc"
        ),

        # API Usage Statistics
        CRUDConfig(
            model_name="PRISMAPIUsage",
            table_name="prism_api_usage",
            display_name="PRISM API Usage",
            description="Track API usage for PRISM endpoints",
            fields=[
                FieldConfig("id", "Integer", primary_key=True, display_name="Usage ID"),
                FieldConfig("user_id", "Integer", display_name="User ID"),
                FieldConfig("user_email", "String", display_name="User Email"),
                FieldConfig("tenant_id", "String", display_name="Tenant ID"),
                FieldConfig("endpoint", "String", display_name="Endpoint"),
                FieldConfig("method", "String", display_name="Method"),
                FieldConfig("status_code", "Integer", display_name="Status Code"),
                FieldConfig("response_time", "Float", display_name="Response Time (s)"),
                FieldConfig("request_size", "Integer", display_name="Request Size (bytes)"),
                FieldConfig("response_size", "Integer", display_name="Response Size (bytes)"),
                FieldConfig("error_message", "Text", display_name="Error Message"),
                FieldConfig("created_at", "DateTime", display_name="Timestamp")
            ],
            searchable_fields=["user_email", "endpoint", "error_message"],
            sortable_fields=["created_at", "response_time", "status_code"],
            filterable_fields=["user_email", "tenant_id", "endpoint", "status_code"],
            default_sort="created_at",
            default_sort_order="desc"
        ),

        # Guatemala Market Analysis (Special)
        CRUDConfig(
            model_name="GuatemalaAnalysis",
            table_name="guatemala_analyses",
            display_name="Guatemala Market Analyses",
            description="Special analyses for Guatemala asphalt market",
            fields=[
                FieldConfig("id", "UUID", primary_key=True, display_name="Analysis ID"),
                FieldConfig("analysis_type", "String", display_name="Type"),
                FieldConfig("belief_analysis", "JSON", display_name="Belief Analysis"),
                FieldConfig("causal_analysis", "JSON", display_name="Causal Analysis"),
                FieldConfig("market_insights", "JSON", display_name="Market Insights"),
                FieldConfig("recommendations", "JSON", display_name="Recommendations"),
                FieldConfig("confidence_score", "Float", display_name="Overall Confidence"),
                FieldConfig("user_email", "String", display_name="Requested By"),
                FieldConfig("created_at", "DateTime", display_name="Created At"),
                FieldConfig("version", "Integer", display_name="Version")
            ],
            searchable_fields=["user_email"],
            sortable_fields=["created_at", "confidence_score", "version"],
            filterable_fields=["user_email", "analysis_type"],
            default_sort="created_at",
            default_sort_order="desc"
        )
    ]


# Export function for admin module integration
def register_prism_admin(admin_router):
    """
    Register PRISM models with the admin interface.
    This will be called by the admin module initialization.
    """
    from modules.admin.crud_generator import generate_crud_router

    configs = get_prism_crud_configs()

    for config in configs:
        try:
            # Generate CRUD router for each model
            crud_router = generate_crud_router(config)

            # Add to admin router with appropriate prefix
            prefix = f"/api/admin/prism/{config.table_name}"
            admin_router.include_router(
                crud_router,
                prefix=prefix,
                tags=[f"Admin - PRISM {config.display_name}"]
            )

            print(f"✅ Registered PRISM admin for {config.display_name} at {prefix}")

        except Exception as e:
            print(f"❌ Failed to register PRISM admin for {config.display_name}: {e}")


# Metrics and dashboard configuration
def get_prism_dashboard_config():
    """
    Get dashboard configuration for PRISM metrics.
    This provides key metrics and charts for the admin dashboard.
    """
    return {
        "title": "PRISM Intelligence Analytics",
        "sections": [
            {
                "title": "Analysis Overview",
                "type": "stats",
                "metrics": [
                    {
                        "label": "Total Belief Analyses",
                        "query": "SELECT COUNT(*) FROM belief_analyses",
                        "format": "number"
                    },
                    {
                        "label": "Total Causal Analyses",
                        "query": "SELECT COUNT(*) FROM causal_analyses",
                        "format": "number"
                    },
                    {
                        "label": "Average Confidence Score",
                        "query": "SELECT AVG(confidence_score) FROM belief_analyses",
                        "format": "percentage"
                    },
                    {
                        "label": "Average Processing Time",
                        "query": "SELECT AVG(processing_time) FROM belief_analyses",
                        "format": "duration"
                    }
                ]
            },
            {
                "title": "Usage Trends",
                "type": "chart",
                "chart_type": "line",
                "data_query": """
                    SELECT
                        DATE(created_at) as date,
                        COUNT(*) as analyses,
                        AVG(confidence_score) as avg_confidence
                    FROM belief_analyses
                    WHERE created_at >= NOW() - INTERVAL '30 days'
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """
            },
            {
                "title": "Top Users",
                "type": "table",
                "data_query": """
                    SELECT
                        user_email,
                        COUNT(*) as total_analyses,
                        AVG(confidence_score) as avg_confidence,
                        AVG(processing_time) as avg_time
                    FROM belief_analyses
                    GROUP BY user_email
                    ORDER BY total_analyses DESC
                    LIMIT 10
                """
            },
            {
                "title": "Cultural Perspectives Distribution",
                "type": "chart",
                "chart_type": "pie",
                "data_query": """
                    SELECT
                        jsonb_array_elements_text(cultural_perspectives) as perspective,
                        COUNT(*) as count
                    FROM belief_analyses
                    GROUP BY perspective
                    ORDER BY count DESC
                """
            }
        ]
    }