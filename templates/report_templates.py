REPORT_TEMPLATES = {
    "html": """
    <!DOCTYPE html>
    <html>
    <head><title>Network Security Analysis Report</title></head>
    <body>
        <h1>Network Security Analysis Report</h1>
        <h2>Executive Summary</h2>
        {{summary}}
        <h2>Network Scan Results</h2>
        {{scan_results}}
        <h2>Log Analysis</h2>
        {{log_analysis}}
        <h2>Recommendations</h2>
        {{recommendations}}
    </body>
    </html>
    """,
    "markdown": """
    # Network Security Analysis Report
    
    ## Executive Summary
    {{summary}}
    
    ## Network Scan Results
    {{scan_results}}
    
    ## Log Analysis
    {{log_analysis}}
    
    ## Recommendations
    {{recommendations}}
    """
}
