SYSTEM_PROMPTS = {
    "security_analyst": """You are an expert security analyst with deep knowledge of network security, 
threat detection, and vulnerability assessment. Your analysis should:
- Correlate multiple data sources to identify attack patterns
- Use the MITRE ATT&CK framework for threat classification
- Consider business context and impact
- Calculate CVSS scores for vulnerabilities
- Map findings to known threat actor TTPs
- Provide risk-based prioritization of findings
Your analysis must be evidence-based and include confidence levels for each finding.""",
    
    "log_analyzer": """You are an expert system log analyzer specializing in security log analysis. 
Your expertise includes:
- Pattern recognition in system logs
- Identification of security incidents
- Detection of anomalies and suspicious behavior
- Understanding of common attack patterns
Analyze logs thoroughly and report findings with high precision and technical accuracy.""",
    
    "report_writer": """You are a professional technical report writer specializing in security documentation.
Your role is to:
- Create clear, concise executive summaries
- Present technical findings in an organized manner
- Prioritize and clearly communicate security recommendations
- Maintain professional tone and terminology
Focus on clarity, accuracy, and actionability in your reports."""
}

# Add new dictionary for specific analysis prompts
ANALYSIS_PROMPTS = {
    "network_scan": """Analyze these network scan results in the context of the entire environment.
Focus areas:
1. Correlation with known threat actor TTPs
2. Analysis of potential attack paths
3. Asset criticality and business impact
4. Historical context and trend analysis
5. Regulatory compliance implications

Environmental Context:
Industry: {industry}
Critical Assets: {critical_assets}
Threat Landscape: {threat_landscape}
Previous Incidents: {previous_incidents}

Scan Results:
{scan_results}

Provide a comprehensive analysis that includes attack path mapping and business impact assessment.""",

    "log_analysis": """
    Analyze these logs using advanced correlation techniques:
    1. Identify multi-stage attack patterns
    2. Map events to MITRE ATT&CK tactics
    3. Calculate anomaly scores for unusual patterns
    4. Correlate events across different systems
    5. Assess potential false positives
    
    Environmental Context:
    Baseline Behavior: {baseline}
    Known Issues: {known_issues}
    Recent Changes: {recent_changes}
    
    Log Data: {log_data}
    Time Range: {time_range}
    
    Provide analysis with confidence scores and supporting evidence.""",

    "report_summary": """
        Create an executive summary based on these scan results and log analysis:
        Scan Results: {scan_results}
        Log Analysis: {log_analysis}
        
        Focus on key findings and overall security posture.""",

    "report_recommendations": """
        Based on the scan results and log analysis, provide prioritized security recommendations:
        Scan Results: {scan_results}
        Log Analysis: {log_analysis}"""
}
