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
from jsonschema import validate

# Simplified logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'network_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def check_environment():
    """Check and validate required environment variables"""
    required_vars = {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "OPENAI_BASE_URL": os.getenv("OPENAI_BASE_URL"),
        "MODEL": os.getenv("MODEL", "gpt-4")  # Default to gpt-4 if not specified
    }
    
    missing_vars = [var for var, value in required_vars.items() if not value and var == "OPENAI_API_KEY"]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        logger.info("Please set them in your environment or create a .env file")
        sys.exit(1)
    
    return required_vars

# Import constants from external modules
from schemas.schemas import SECURITY_REPORT_SCHEMA, LOG_ANALYSIS_SCHEMA, ANALYSIS_CONTEXT_SCHEMA
from prompts.prompts import SYSTEM_PROMPTS, ANALYSIS_PROMPTS, ANALYSIS_PIPELINE_PROMPTS
from templates.report_templates import REPORT_TEMPLATES
from intermediate_agents import IntermediateScanAgent, LogAnalysisAgent

class NetworkSecurityAnalyzer:
    def __init__(self, openai_key: str, openai_base_url: str = None):
        logger.info("Initializing NetworkSecurityAnalyzer")
        self.nm = nmap.PortScanner()
        
        # Configure OpenAI client and model
        self.client = OpenAI(
            api_key=openai_key,
            base_url=openai_base_url if openai_base_url else None
        )
        self.model = os.getenv("MODEL", "gpt-4")
        
        self._check_sudo()
        self._log_system_info()
        self.default_context = {
            "industry": "general",
            "critical_assets": [],
            "threat_landscape": "standard",
            "previous_incidents": []
        }
        self.analysis_context = self.default_context.copy()
        self.confidence_thresholds = {
            "HIGH": 0.8,
            "MEDIUM": 0.6,
            "LOW": 0.4
        }
        
        # Initialize scan agent with batch size of 5 hosts
        self.scan_agent = IntermediateScanAgent(self.client, batch_size=5)
        
        # Initialize log analysis agent
        self.log_agent = LogAnalysisAgent(self.client, chunk_size=5000)

    def set_analysis_context(self, context_data: Dict) -> None:
        """Set context for analysis customization"""
        if not self._validate_context(context_data):
            raise ValueError("Invalid context data format")
        # Merge with defaults, keeping user-provided values
        self.analysis_context = {**self.default_context, **context_data}
        logger.info(f"Analysis context updated")

    def _validate_context(self, context_data: Dict) -> bool:
        """Validate context data against schema"""
        try:
            validate(instance=context_data, schema=ANALYSIS_CONTEXT_SCHEMA)
            return True
        except Exception as e:
            logger.error(f"Context validation failed: {str(e)}")
            return False

    async def perform_analysis_pipeline(self, data: Dict) -> Dict:
        """Execute multi-stage analysis pipeline"""
        try:
            # Context Analysis
            context_analysis = await self._analyze_context(self.analysis_context)
            
            # Initial Triage
            triage_results = await self._perform_triage(data, context_analysis)
            
            # Deep Analysis
            analysis_results = await self._perform_deep_analysis(
                data, triage_results, context_analysis
            )
            
            # Cross Validation
            validated_results = await self._cross_validate_findings(analysis_results)
            
            # Confidence Scoring
            final_results = await self._score_confidence(validated_results)
            
            return self._prepare_final_report(final_results)

        except Exception as e:
            logger.error(f"Analysis pipeline failed: {str(e)}")
            raise

    async def _analyze_context(self, context: Dict) -> Dict:
        """Analyze context and establish baseline expectations"""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS["security_analyst"]},
                {"role": "user", "content": ANALYSIS_PIPELINE_PROMPTS["context_analysis"].format(
                    env_data=json.dumps(context.get("environment", {})),
                    historical_data=json.dumps(context.get("historical_data", {})),
                    custom_rules=json.dumps(context.get("custom_rules", []))
                )}
            ]
        )
        return json.loads(response.choices[0].message.content)

    # Add similar async methods for other pipeline stages...

    def _prepare_final_report(self, results: Dict) -> Dict:
        """Prepare final report with confidence scores and context-aware insights"""
        return {
            "results": results,
            "context_summary": self.analysis_context.get("summary", ""),
            "confidence_metrics": {
                "overall_confidence": self._calculate_overall_confidence(results),
                "validation_status": self._get_validation_status(results)
            },
            "meta": {
                "analysis_timestamp": datetime.now().isoformat(),
                "context_version": self.analysis_context.get("version", "1.0"),
                "pipeline_stages_completed": self._get_completed_stages()
            }
        }

    def _check_sudo(self):
        """Check if script has sudo privileges"""
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
        """Log basic system information"""
        system_info = {
            "platform": platform.platform(),
            "python_version": sys.version,
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available
            },
            "network_interfaces": {},
            "timestamp": datetime.now().isoformat()
        }
        
        # Get detailed network interface info
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            system_info["network_interfaces"][interface] = {"addresses": {}}
            
            # IPv4 addresses
            if netifaces.AF_INET in addrs:
                system_info["network_interfaces"][interface]["addresses"]["ipv4"] = addrs[netifaces.AF_INET]
                
            # IPv6 addresses
            if netifaces.AF_INET6 in addrs:
                system_info["network_interfaces"][interface]["addresses"]["ipv6"] = addrs[netifaces.AF_INET6]
                
            # MAC addresses
            if netifaces.AF_LINK in addrs:
                system_info["network_interfaces"][interface]["addresses"]["mac"] = addrs[netifaces.AF_LINK]
                
        logger.info(f"System Information: {json.dumps(system_info, indent=2)}")

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
        """Scan all hosts in the local network using batch processing"""
        start_time = time.time()
        try:
            # Log scan metadata
            logger.info("Scan metadata:")
            logger.info(json.dumps({
                "start_time": datetime.now().isoformat(),
                "scan_config": {
                    "scanner_version": self.nm.nmap_version(),
                    "arguments": "-sV -sS -A",
                    "timing": time.time()
                }
            }, indent=2))
            
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
                self._log_memory_usage()
                
                # Perform detailed scan on the host
                self.nm.scan(host, arguments='-sV -sS -A')
                
                if host in self.nm.all_hosts():
                    scan_results = self._process_host_scan(host)
                    
                    # Update scan duration
                    scan_duration = time.time() - start_time
                    logger.info(f"Completed scan of {host} in {scan_duration:.2f} seconds")
                    logger.debug(f"Scan results for {host}: {json.dumps(scan_results, indent=2)}")
                    
                    # Process with intermediate agent
                    batch_completed = self.scan_agent.process_host(scan_results)
                    if batch_completed:
                        logger.info(f"Batch processing completed for {self.scan_agent.batch_size} hosts")
                    
                    results.append(scan_results)
            
            # Finalize scan processing and get the summary
            logger.info("Finalizing scan analysis")
            final_summary, host_statistics = self.scan_agent.finalize()
            
            total_time = time.time() - start_time
            logger.info(f"Network scan completed in {total_time:.2f} seconds")
            logger.info(f"Scan summary: {final_summary[:200]}...")
            
            return results

        except Exception as e:
            logger.error(f"Network scan failed: {str(e)}")
            raise RuntimeError(f"Network scan failed: {str(e)}")

    def _log_memory_usage(self):
        """Log current memory usage"""
        memory = psutil.Process(os.getpid()).memory_info()
        logger.debug(f"Memory Usage - RSS: {memory.rss / (1024 * 1024):.2f}MB, VMS: {memory.vms / (1024 * 1024):.2f}MB")

    def _process_host_scan(self, host: str) -> Dict:
        """Process scan results for a single host"""
        start_time = time.time()
        
        scan_results = {
            "ip": host,
            "hostname": socket.getfqdn(host),
            "timestamp": datetime.now().isoformat(),
            "ports": [],
            "os_detection": str(self.nm[host].get("osmatch", "Unknown")),
            "services": [],
            "metrics": {
                "scan_duration": None,
                "ports_found": 0
            }
        }

        try:
            # Process TCP ports
            if 'tcp' in self.nm[host]:
                for port, service_info in self.nm[host]['tcp'].items():
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
                    logger.debug(f"Detailed port info for {host}:{port}:\n{json.dumps(port_info, indent=2)}")
                    scan_results["ports"].append(port_info)

            # Process UDP ports
            if 'udp' in self.nm[host]:
                for port, service_info in self.nm[host]['udp'].items():
                    scan_results["ports"].append({
                        "port": port,
                        "state": service_info["state"],
                        "service": service_info["name"],
                        "version": service_info["version"],
                        "protocol": "udp",
                        "extra": {
                            "product": service_info.get("product", ""),
                            "extrainfo": service_info.get("extrainfo", ""),
                            "cpe": service_info.get("cpe", [])
                        }
                    })

            # Add host scripts results if available
            if 'hostscript' in self.nm[host]:
                logger.debug(f"Host scripts for {host}:\n{json.dumps(self.nm[host]['hostscript'], indent=2)}")
                scan_results["host_scripts"] = self.nm[host]["hostscript"]

            # Update metrics
            scan_results["metrics"]["scan_duration"] = time.time() - start_time
            scan_results["metrics"]["ports_found"] = len(scan_results["ports"])

        except Exception as e:
            logger.error(f"Error processing host {host}: {str(e)}")

        return scan_results

    def analyze_results(self, scan_results: Dict) -> Dict:
        """Analyze individual host scan results with context"""
        logger.info(f"Analyzing results for host: {scan_results['ip']}")
        
        try:
            # Format prompt with context values, using defaults if not provided
            prompt = ANALYSIS_PROMPTS["network_scan"].format(
                ip=scan_results['ip'],
                port_count=len(scan_results['ports']),
                os_detection=scan_results['os_detection'],
                scan_results=json.dumps(scan_results, indent=2),
                industry=self.analysis_context.get('industry', self.default_context['industry']),
                critical_assets=json.dumps(self.analysis_context.get('critical_assets', self.default_context['critical_assets'])),
                threat_landscape=self.analysis_context.get('threat_landscape', self.default_context['threat_landscape']),
                previous_incidents=json.dumps(self.analysis_context.get('previous_incidents', self.default_context['previous_incidents']))
            )

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPTS["security_analyst"]},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object", "json_schema": SECURITY_REPORT_SCHEMA }
            )

            analysis = json.loads(response.choices[0].message.content)
            return analysis

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise ValueError(f"Analysis failed: {str(e)}")

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
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPTS["security_analyst"]},
                    {"role": "user", "content": f"Test analysis request. Provide a security assessment for this minimal scan:\n{json.dumps(test_data, indent=2)}"}
                ],
                response_format={ "type": "json_object", "json_schema": SECURITY_REPORT_SCHEMA }
            )
            logger.debug(f"Test response:\n{response.choices[0].message.content}")
            json.loads(response.choices[0].message.content)
            return True
        except Exception as e:
            logger.error(f"LLM test failed: {str(e)}")
            return False

    def analyze_network_logs(self, log_paths: List[str] = None) -> Dict:
        """Analyze network logs using the LogAnalysisAgent"""
        logger.info("Analyzing network logs")
        
        if not log_paths:
            # Default to common log locations
            log_paths = [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages"
            ]
        
        try:
            # Process each log file using the log agent
            log_summaries = []
            for log_path in log_paths:
                if os.path.exists(log_path):
                    logger.info(f"Processing log file: {log_path}")
                    summary = self.log_agent.process_log_file(log_path)
                    log_summaries.append(summary)
                else:
                    logger.warning(f"Log file not found: {log_path}")
            
            # Get final summary
            if log_summaries:
                final_summary, statistics = self.log_agent.finalize()
                return {
                    "status": "analyzed",
                    "summary": final_summary,
                    "statistics": statistics,
                    "log_summaries": log_summaries
                }
            else:
                logger.warning("No log files were processed")
                return {
                    "status": "no_logs",
                    "summary": "No log files were accessible for analysis",
                    "statistics": {
                        "total_logs_processed": 0,
                        "suspicious_events": 0
                    },
                    "log_summaries": []
                }
        
        except Exception as e:
            logger.error(f"Log analysis failed: {str(e)}")
            traceback.print_exc()
            return {
                "status": "error",
                "summary": f"Analysis failed: {str(e)}",
                "statistics": {},
                "log_summaries": []
            }

    def generate_report(self, scan_results: List[Dict], log_analysis: Dict, format: str = "markdown") -> str:
        """Generate a comprehensive security report using intermediate summaries"""
        logger.info(f"Generating {format} report")
        
        try:
            # Get scan summary from the scan agent
            scan_summary, scan_statistics = self.scan_agent.finalize()
            
            # Format the report with the summaries
            template = REPORT_TEMPLATES.get(format, REPORT_TEMPLATES["markdown"])
            
            # Get log analysis summary
            log_summary = log_analysis.get("summary", "No log analysis available")
            
            # Generate recommendations based on summaries
            recommendations_prompt = f"""
                Based on the following network scan summary and log analysis, provide prioritized security recommendations:
                
                SCAN SUMMARY:
                {scan_summary}
                
                LOG ANALYSIS:
                {log_summary}
                
                Provide a comprehensive set of prioritized recommendations to address the security issues identified.
            """
            
            recommendations_response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPTS["report_writer"]},
                    {"role": "user", "content": recommendations_prompt}
                ]
            )
            
            # Create the report
            report = template.replace(
                "{{summary}}", scan_summary
            ).replace(
                "{{scan_results}}", json.dumps(scan_statistics, indent=2)
            ).replace(
                "{{log_analysis}}", log_summary
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

        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            traceback.print_exc()
            # Create a minimal error report
            error_report = f"""
            # Network Security Analysis Error Report
            
            ## Error Information
            
            Error occurred during report generation: {str(e)}
            
            ## Partial Data
            
            The scan was completed but the report could not be fully generated.
            Please check the individual scan result files for details.
            """
            
            error_path = f"error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(error_path, 'w') as f:
                f.write(error_report)
                
            return error_path

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
        
        # Perform network scan - this will now use the intermediate agent
        scan_results = analyzer.perform_network_scan()
        
        # Analyze network logs using chunks
        log_analysis = analyzer.analyze_network_logs()
        
        # Generate final report using the summaries
        report_path = analyzer.generate_report(scan_results, log_analysis)
        print(f"\nFinal report generated: {report_path}")

    except Exception as e:
        logger.error(f"Failed to complete analysis: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
