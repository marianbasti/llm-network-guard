import json
import subprocess
import nmap
from typing import Dict, List
from openai import OpenAI
import os
import sys
import ipaddress
import socket
import netifaces
import logging
import time
import traceback
import platform
import psutil
from datetime import datetime
from dotenv import load_dotenv

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG level
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'network_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.FileHandler(f'network_scan_detailed_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def check_environment():
    """Check and validate required environment variables"""
    required_vars = {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "OPENAI_BASE_URL": os.getenv("OPENAI_BASE_URL")
    }
    
    missing_vars = [var for var, value in required_vars.items() if not value]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        logger.info("Please set them in your environment or create a .env file with the following format:")
        logger.info("OPENAI_API_KEY=your_api_key_here")
        logger.info("OPENAI_BASE_URL=your_base_url_here (optional)")
        sys.exit(1)
    
    return required_vars

# Define the response schema
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

# Add new constants after SECURITY_REPORT_SCHEMA
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

SYSTEM_PROMPTS = {
    "security_analyst": """You are an expert security analyst with deep knowledge of network security, 
threat detection, and vulnerability assessment. Your task is to analyze network data and provide 
professional, detailed security assessments. Focus on:
- Identifying security vulnerabilities and threats
- Assessing risk levels based on industry standards
- Providing actionable recommendations
- Using precise technical terminology
Your analysis should be thorough, precise, and follow security best practices.""",
    
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

class NetworkSecurityAnalyzer:
    def __init__(self, openai_key: str, openai_base_url: str = None):
        logger.info("Initializing NetworkSecurityAnalyzer")
        self.nm = nmap.PortScanner()
        
        # Configure OpenAI with custom client
        if openai_base_url:
            self.client = OpenAI(
                api_key=openai_key,
                base_url=openai_base_url
            )
            logger.info(f"Using custom OpenAI base URL: {openai_base_url}")
        else:
            self.client = OpenAI(api_key=openai_key)
        
        logger.debug(f"OpenAI Configuration - API Key: {'*' * len(openai_key)}, Base URL: {openai_base_url or 'default'}")
        self._check_sudo()
        self._log_system_info()

    def _check_sudo(self):
        """Check if script has sudo privileges"""
        logger.debug("Checking sudo privileges")
        if os.geteuid() != 0:
            logger.warning("Script running without sudo privileges")
            print("This script requires sudo privileges for network scanning.")
            print("Attempting to re-run with sudo...")
            try:
                args = ['sudo', sys.executable] + sys.argv
                os.execvp('sudo', args)
            except Exception as e:
                raise PermissionError(f"Failed to obtain sudo privileges: {str(e)}")

    def _log_system_info(self):
        """Log detailed system information"""
        system_info = {
            "platform": platform.platform(),
            "python_version": sys.version,
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available
            },
            "network_interfaces": self._get_network_interfaces(),
            "timestamp": datetime.now().isoformat()
        }
        logger.info(f"System Information:\n{json.dumps(system_info, indent=2)}")

    def _get_network_interfaces(self) -> Dict:
        """Get detailed network interface information"""
        interfaces = {}
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            iface_info = {
                "addresses": {
                    "ipv4": addrs.get(netifaces.AF_INET, []),
                    "ipv6": addrs.get(netifaces.AF_INET6, []),
                    "mac": addrs.get(netifaces.AF_LINK, [])
                }
            }
            interfaces[iface] = iface_info
        return interfaces

    def _log_memory_usage(self):
        """Log current memory usage"""
        memory = psutil.Process(os.getpid()).memory_info()
        logger.debug(f"Memory Usage - RSS: {memory.rss / 1024 / 1024:.2f}MB, VMS: {memory.vms / 1024 / 1024:.2f}MB")

    def get_local_network(self) -> str:
        """Get the local network CIDR"""
        logger.info("Detecting local network")
        try:
            gateways = netifaces.gateways()
            logger.debug(f"Found gateways: {gateways}")
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                interface = gateways['default'][netifaces.AF_INET][1]
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    netmask = addrs[netifaces.AF_INET][0]['netmask']
                    network = ipaddress.IPv4Network(f'{ip}/{netmask}', strict=False)
                    logger.info(f"Detected local network: {network}")
                    return str(network)
        except Exception as e:
            logger.error(f"Failed to determine local network: {e}")
            raise RuntimeError("Could not determine local network")

    def perform_network_scan(self) -> List[Dict]:
        """Scan all hosts in the local network"""
        start_time = time.time()
        scan_metadata = {
            "start_time": datetime.now().isoformat(),
            "scan_config": {
                "scanner_version": self.nm.nmap_version(),
                "arguments": "-sV -sS -A",
                "timing": time.time()
            }
        }
        logger.info(f"Scan metadata:\n{json.dumps(scan_metadata, indent=2)}")
        try:
            network_cidr = self.get_local_network()
            logger.info(f"Starting network scan on {network_cidr}")
            
            # Perform host discovery
            logger.info("Performing initial host discovery")
            self.nm.scan(hosts=network_cidr, arguments='-sn')
            hosts_list = self.nm.all_hosts()
            logger.info(f"Found {len(hosts_list)} active hosts")
            
            results = []
            for i, host in enumerate(hosts_list, 1):
                logger.info(f"Scanning host {i}/{len(hosts_list)}: {host}")
                scan_start = time.time()
                self.nm.scan(host, arguments='-sV -sS -A')
                
                if host in self.nm.all_hosts():
                    scan_results = self._process_host_scan(host)
                    results.append(scan_results)
                    logger.info(f"Completed scan of {host} in {time.time() - scan_start:.2f} seconds")
                    logger.debug(f"Scan results for {host}: {json.dumps(scan_results, indent=2)}")
            
            total_time = time.time() - start_time
            logger.info(f"Network scan completed in {total_time:.2f} seconds")
            return results

        except Exception as e:
            logger.error(f"Network scan failed: {str(e)}")
            logger.debug(f"Stack trace: {traceback.format_exc()}")
            raise RuntimeError(f"Network scan failed: {str(e)}")

    def _process_host_scan(self, host: str) -> Dict:
        """Process scan results for a single host"""
        self._log_memory_usage()
        host_start_time = time.time()
        
        scan_results = {
            "ip": host,
            "hostname": socket.getfqdn(host),
            "timestamp": datetime.now().isoformat(),
            "ports": [],
            "os_detection": str(self.nm[host].get("osmatch", "Unknown")),
            "services": [],
            "metrics": {
                "scan_duration": 0,
                "ports_found": 0
            }
        }

        try:
            if 'tcp' in self.nm[host]:
                tcp_ports = self.nm[host]['tcp']
                scan_results["metrics"]["ports_found"] = len(tcp_ports)
                
                for port in tcp_ports:
                    service_info = tcp_ports[port]
                    port_info = {
                        "port": port,
                        "state": service_info["state"],
                        "service": service_info["name"],
                        "version": service_info["version"],
                        "protocol": "tcp",
                        "extra": {
                            "product": service_info.get("product", ""),
                            "extrainfo": service_info.get("extrainfo", ""),
                            "cpe": service_info.get("cpe", [])
                        }
                    }
                    scan_results["ports"].append(port_info)
                    logger.debug(f"Detailed port info for {host}:{port}:\n{json.dumps(port_info, indent=2)}")

            if 'udp' in self.nm[host]:
                tcp_ports = self.nm[host]['udp']
                scan_results["metrics"]["ports_found"] = len(tcp_ports)
                
                for port in tcp_ports:
                    service_info = tcp_ports[port]
                    port_info = {
                        "port": port,
                        "state": service_info["state"],
                        "service": service_info["name"],
                        "version": service_info["version"],
                        "protocol": "tcp",
                        "extra": {
                            "product": service_info.get("product", ""),
                            "extrainfo": service_info.get("extrainfo", ""),
                            "cpe": service_info.get("cpe", [])
                        }
                    }
                    scan_results["ports"].append(port_info)
                    logger.debug(f"Detailed port info for {host}:{port}:\n{json.dumps(port_info, indent=2)}")


            # Add host scripts results if available
            if 'hostscript' in self.nm[host]:
                scan_results["host_scripts"] = self.nm[host]["hostscript"]
                logger.debug(f"Host scripts for {host}:\n{json.dumps(self.nm[host]['hostscript'], indent=2)}")

        except Exception as e:
            logger.error(f"Error processing host {host}: {str(e)}")
            logger.debug(traceback.format_exc())

        scan_results["metrics"]["scan_duration"] = time.time() - host_start_time
        return scan_results

    def analyze_results(self, scan_results: Dict) -> Dict:
        logger.info(f"Analyzing results for host: {scan_results['ip']}")
        self._log_memory_usage()
        
        prompt = f"""Given these network scan results, provide a comprehensive security assessment.
Focus areas:
1. Vulnerability identification in open ports and services
2. Configuration issues and misconfigurations
3. Potential security risks and exposure levels
4. Compliance concerns with security standards

Context:
Host IP: {scan_results['ip']}
Total Ports Scanned: {len(scan_results['ports'])}
OS Detection: {scan_results['os_detection']}

Scan Results:
{json.dumps(scan_results, indent=2)}

Provide detailed security findings and recommendations based on the scan results.
"""

        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS["security_analyst"]},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object", "json_schema": SECURITY_REPORT_SCHEMA }
        )

        try:
            analysis = json.loads(response.choices[0].message.content)
            logger.debug(f"Security analysis: {json.dumps(analysis, indent=2)}")
            return analysis
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            logger.debug(f"Stack trace: {traceback.format_exc()}")
            raise ValueError(f"Invalid LLM response format: {str(e)}")

    def test_llm_connection(self) -> bool:
        """Test LLM connection and response format with a simple case"""
        logger.info("Testing LLM connection and response format...")
        test_data = {
            "ip": "test.local",
            "hostname": "test.local",
            "timestamp": datetime.now().isoformat(),
            "ports": [
                {
                    "port": 80,
                    "state": "open",
                    "service": "http",
                    "version": "Apache/2.4.41",
                    "protocol": "tcp"
                }
            ],
            "os_detection": "Unknown"
        }

        try:
            logger.debug("Sending test analysis request to LLM")
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPTS["security_analyst"]},
                    {"role": "user", "content": f"Test analysis request. Provide a security assessment for this minimal scan:\n{json.dumps(test_data, indent=2)}"}
                ],
                response_format={ "type": "json_object", "json_schema": SECURITY_REPORT_SCHEMA }
            )
    
            analysis = json.loads(response.choices[0].message.content)
            logger.debug(f"Test response:\n{json.dumps(analysis, indent=2)}")
            return True

        except Exception as e:
            logger.error(f"LLM test failed: {str(e)}")
            logger.debug(f"Stack trace: {traceback.format_exc()}")
            return False

    def analyze_network_logs(self, log_paths: List[str] = None) -> Dict:
        """Analyze network logs for security insights"""
        logger.info("Analyzing network logs")
        
        if not log_paths:
            # Default to common log locations
            log_paths = [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages"
            ]
        
        log_data = []
        start_time = None
        end_time = datetime.now().isoformat()
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r') as f:
                        log_content = f.read()
                        if not start_time:
                            # Try to extract earliest timestamp from first log
                            try:
                                start_time = datetime.fromtimestamp(os.path.getctime(log_path)).isoformat()
                            except:
                                start_time = "unknown"
                        log_data.append({
                            "path": log_path,
                            "content": log_content[-10000:]  # Last 10K characters
                        })
                except Exception as e:
                    logger.error(f"Failed to read log {log_path}: {str(e)}")
        
        if not log_data:
            logger.warning("No log files were accessible")
            return {
                "status": "no_logs",
                "summary": "No log files were accessible for analysis",
                "suspicious_events": [],
                "metrics": {
                    "total_events_analyzed": 0,
                    "suspicious_event_count": 0,
                    "analysis_period": {"start": None, "end": None}
                },
                "recommendations": []
            }
        
        prompt = f"""
        Analyze these network and system logs for security concerns.
        Provide a detailed analysis following this structure:
        1. Overall status of system security based on logs
        2. List all suspicious events with timestamps and severity
        3. Provide specific evidence for each finding
        4. Include actionable recommendations
        
        Log Data to analyze:
        {json.dumps(log_data, indent=2)}
        
        Analysis period:
        Start: {start_time}
        End: {end_time}
        
        Provide the analysis in a structured JSON format matching the specified schema.
        Focus on accuracy and actionable insights.
        """
        
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS["log_analyzer"]},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object", "json_schema": LOG_ANALYSIS_SCHEMA }
        )
        
        try:
            analysis = json.loads(response.choices[0].message.content)
            # Ensure metrics are properly set
            analysis["metrics"]["analysis_period"] = {
                "start": start_time,
                "end": end_time
            }
            logger.debug(f"Log analysis results: {json.dumps(analysis, indent=2)}")
            return analysis
        except Exception as e:
            logger.error(f"Log analysis failed: {str(e)}")
            return {
                "status": "error",
                "summary": f"Analysis failed: {str(e)}",
                "suspicious_events": [],
                "metrics": {
                    "total_events_analyzed": 0,
                    "suspicious_event_count": 0,
                    "analysis_period": {"start": start_time, "end": end_time}
                },
                "recommendations": []
            }

    def generate_report(self, scan_results: List[Dict], log_analysis: Dict, format: str = "markdown") -> str:
        """Generate a comprehensive security report"""
        logger.info(f"Generating {format} report")
        
        # Prepare data for the report
        summary_prompt = f"""
        Create an executive summary based on these scan results and log analysis:
        Scan Results: {json.dumps(scan_results, indent=2)}
        Log Analysis: {json.dumps(log_analysis, indent=2)}
        
        Focus on key findings and overall security posture.
        """
        
        summary_response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS["report_writer"]},
                {"role": "user", "content": summary_prompt}
            ]
        )
        
        recommendations_prompt = f"""
        Based on the scan results and log analysis, provide prioritized security recommendations:
        Scan Results: {json.dumps(scan_results, indent=2)}
        Log Analysis: {json.dumps(log_analysis, indent=2)}
        """
        
        recommendations_response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS["report_writer"]},
                {"role": "user", "content": recommendations_prompt}
            ]
        )
        
        # Format the report
        template = REPORT_TEMPLATES.get(format, REPORT_TEMPLATES["markdown"])
        report = template.replace(
            "{{summary}}", summary_response.choices[0].message.content
        ).replace(
            "{{scan_results}}", json.dumps(scan_results, indent=2)
        ).replace(
            "{{log_analysis}}", json.dumps(log_analysis, indent=2)
        ).replace(
            "{{recommendations}}", recommendations_response.choices[0].message.content
        )
        
        # Save the report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"security_report_{timestamp}.{format}"
        with open(report_path, 'w') as f:
            f.write(report)
        
        logger.info(f"Report saved to {report_path}")
        return report_path

def main():
    logger.info("Starting Network Security Analysis")
    
    # Check environment variables
    env_vars = check_environment()
    
    try:
        analyzer = NetworkSecurityAnalyzer(
            openai_key=env_vars["OPENAI_API_KEY"],
            openai_base_url=env_vars["OPENAI_BASE_URL"]
        )
        
        # Test LLM connection before proceeding
        if not analyzer.test_llm_connection():
            logger.error("LLM test failed - aborting network scan")
            sys.exit(1)
        
        logger.info("LLM test passed - proceeding with network scan")
        
        # Perform network scan
        scan_results = analyzer.perform_network_scan()
        
        # Analyze each host's results
        analyzed_results = []
        for host_result in scan_results:
            logger.info(f"\nAnalyzing results for {host_result['ip']}:")
            security_report = analyzer.analyze_results(host_result)
            analyzed_results.append({
                "host": host_result,
                "analysis": security_report
            })
        
        # Analyze network logs
        log_analysis = analyzer.analyze_network_logs()
        
        # Generate final report
        report_path = analyzer.generate_report(analyzed_results, log_analysis)
        print(f"\nFinal report generated: {report_path}")

    except Exception as e:
        logger.error(f"Failed to complete analysis: {str(e)}")
        logger.debug(f"Stack trace: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
