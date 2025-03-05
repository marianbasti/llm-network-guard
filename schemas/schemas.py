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
                    "known_exploits": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "impact": {
                        "type": "object",
                        "properties": {
                            "business": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                            "technical": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                            "data": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}
                        }
                    },
                    "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                    "threat_category": {
                        "type": "string",
                        "enum": ["APT", "Ransomware", "Data Exfiltration", "Insider Threat", "Zero-day", "Other"]
                    }
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
        },
        "correlation_analysis": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pattern_id": {"type": "string"},
                    "related_events": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                    "attack_chain_phase": {
                        "type": "string",
                        "enum": ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command_and_control", "actions"]
                    }
                }
            }
        }
    },
    "required": ["status", "summary", "suspicious_events", "metrics", "recommendations"]
}

ANALYSIS_CONTEXT_SCHEMA = {
    "type": "object",
    "properties": {
        "environment": {
            "type": "object",
            "properties": {
                "industry": {"type": "string"},
                "business_criticality": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                "compliance_requirements": {"type": "array", "items": {"type": "string"}},
                "asset_classification": {"type": "string"},
                "threat_profile": {"type": "string"}
            }
        },
        "historical_data": {
            "type": "object",
            "properties": {
                "previous_incidents": {"type": "array", "items": {"type": "string"}},
                "known_vulnerabilities": {"type": "array", "items": {"type": "string"}},
                "baseline_metrics": {"type": "object"}
            }
        },
        "custom_rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_type": {"type": "string"},
                    "criteria": {"type": "object"},
                    "priority": {"type": "integer", "minimum": 1, "maximum": 5}
                }
            }
        }
    }
}
