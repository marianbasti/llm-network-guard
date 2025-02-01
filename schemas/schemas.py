SECURITY_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "vulnerability": {"type": "string"},
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "description": {"type": "string"},
                    "recommendation": {"type": "string"}
                },
                "required": ["vulnerability", "severity", "description", "recommendation"]
            }
        }
    },
    "required": ["summary", "risk_level", "findings"]
}

LOG_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["secure", "suspicious", "critical", "error", "no_logs"]
        },
        "summary": {
            "type": "string",
            "description": "Overall assessment of log analysis"
        },
        "suspicious_events": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "timestamp": {"type": "string"},
                    "source": {"type": "string"},
                    "event_type": {
                        "type": "string",
                        "enum": [
                            "authentication_failure",
                            "brute_force_attempt",
                            "suspicious_connection",
                            "privilege_escalation",
                            "malware_activity",
                            "system_modification",
                            "other"
                        ]
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    },
                    "description": {"type": "string"},
                    "source_log": {"type": "string"},
                    "evidence": {"type": "string"},
                    "recommended_action": {"type": "string"}
                },
                "required": [
                    "timestamp",
                    "event_type",
                    "severity",
                    "description",
                    "source_log",
                    "recommended_action"
                ]
            }
        },
        "metrics": {
            "type": "object",
            "properties": {
                "total_events_analyzed": {"type": "integer"},
                "suspicious_event_count": {"type": "integer"},
                "analysis_period": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string"},
                        "end": {"type": "string"}
                    }
                }
            }
        },
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                    "category": {
                        "type": "string",
                        "enum": [
                            "system_hardening",
                            "monitoring",
                            "authentication",
                            "network_security",
                            "incident_response",
                            "other"
                        ]
                    },
                    "description": {"type": "string"},
                    "action_items": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                "required": ["priority", "category", "description", "action_items"]
            }
        }
    },
    "required": ["status", "summary", "suspicious_events", "metrics", "recommendations"]
}
