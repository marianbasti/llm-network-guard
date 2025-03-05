import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from openai import OpenAI
import os

logger = logging.getLogger(__name__)

class IntermediateScanAgent:
    """
    Agent that processes scan results in batches, creating intermediate summaries 
    to manage context window limitations in LLMs.
    """
    
    def __init__(self, client: OpenAI, batch_size: int = 5):
        """
        Initialize the intermediate scan agent.
        
        Args:
            client: OpenAI client for making API calls
            batch_size: Number of hosts to process before creating an intermediate summary
        """
        self.client = client
        self.model = os.getenv("MODEL", "gpt-4")
        self.batch_size = batch_size
        self.summaries = []
        self.current_batch = []
        self.total_hosts_processed = 0
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.host_statistics = {
            "total_hosts": 0,
            "hosts_with_open_ports": 0,
            "total_open_ports": 0,
            "services_found": set(),
            "os_distribution": {}
        }

    def process_host(self, host_data: Dict[str, Any]) -> bool:
        """
        Process a single host's scan data and add it to the current batch.
        Returns True if a batch was completed and summarized.
        
        Args:
            host_data: Dictionary containing host scan results
        
        Returns:
            bool: True if batch was processed, False otherwise
        """
        self.current_batch.append(host_data)
        self.total_hosts_processed += 1
        self._update_statistics(host_data)
        
        if len(self.current_batch) >= self.batch_size:
            self._create_batch_summary()
            self._save_intermediate_data()
            self.current_batch = []
            return True
        return False

    def _update_statistics(self, host_data: Dict[str, Any]) -> None:
        """Update global statistics with data from this host"""
        self.host_statistics["total_hosts"] += 1
        
        # Count open ports
        open_ports = [p for p in host_data.get("ports", []) if p.get("state") == "open"]
        if open_ports:
            self.host_statistics["hosts_with_open_ports"] += 1
            self.host_statistics["total_open_ports"] += len(open_ports)
        
        # Track services found
        for port in host_data.get("ports", []):
            if port.get("service"):
                self.host_statistics["services_found"].add(port.get("service"))
        
        # Track OS distribution
        os_detection = host_data.get("os_detection", "Unknown")
        if isinstance(os_detection, str):
            # Try to extract OS family from the string
            os_family = "Unknown"
            if "Windows" in os_detection:
                os_family = "Windows"
            elif "Linux" in os_detection:
                os_family = "Linux"
            elif "embedded" in os_detection:
                os_family = "Embedded"
            
            self.host_statistics["os_distribution"][os_family] = \
                self.host_statistics["os_distribution"].get(os_family, 0) + 1

    def _create_batch_summary(self) -> None:
        """Create a summary of the current batch of hosts"""
        try:
            # Prepare batch data for summarization
            batch_json = json.dumps(self.current_batch, indent=2)
            
            # Create a prompt for summarizing this batch
            prompt = f"""
            Summarize the scan results for the following {len(self.current_batch)} hosts:
            
            ```json
            {batch_json}
            ```
            
            Focus on:
            1. Key security findings
            2. Notable open ports and services
            3. Common patterns
            4. Potential vulnerabilities
            5. Unusual configurations
            
            Provide a concise summary that captures the essential security details.
            """
            
            # Get summary from LLM
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security analysis assistant that creates concise summaries of network scan results."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Add summary with metadata
            summary = {
                "batch_id": len(self.summaries) + 1,
                "host_count": len(self.current_batch),
                "host_ips": [host.get("ip") for host in self.current_batch],
                "timestamp": datetime.now().isoformat(),
                "summary": response.choices[0].message.content
            }
            
            self.summaries.append(summary)
            logger.info(f"Created summary for batch {summary['batch_id']} with {summary['host_count']} hosts")
            
        except Exception as e:
            logger.error(f"Error creating batch summary: {str(e)}")
            # Add a placeholder summary to maintain batch tracking
            self.summaries.append({
                "batch_id": len(self.summaries) + 1,
                "host_count": len(self.current_batch),
                "host_ips": [host.get("ip", "unknown") for host in self.current_batch],
                "timestamp": datetime.now().isoformat(),
                "summary": f"Error generating summary: {str(e)}",
                "error": True
            })

    def _save_intermediate_data(self) -> None:
        """Save intermediate data to disk"""
        try:
            # Save the batch summary
            with open(f"batch_summary_{self.timestamp}_{len(self.summaries)}.json", "w") as f:
                json.dump(self.summaries[-1], f, indent=2)
            
            # Save full batch data
            with open(f"batch_data_{self.timestamp}_{len(self.summaries)}.json", "w") as f:
                json.dump(self.current_batch, f, indent=2)
            
            logger.debug(f"Saved intermediate data for batch {len(self.summaries)}")
        except Exception as e:
            logger.error(f"Error saving intermediate data: {str(e)}")

    def finalize(self) -> Tuple[str, Dict[str, Any]]:
        """
        Process any remaining hosts and generate a final summary of all batches.
        
        Returns:
            Tuple containing the final summary text and statistics dictionary
        """
        # Process any remaining hosts in the last batch
        if self.current_batch:
            self._create_batch_summary()
            self._save_intermediate_data()
            self.current_batch = []
        
        # Update statistics to include service counts
        self.host_statistics["services_found"] = list(self.host_statistics["services_found"])
        self.host_statistics["service_count"] = len(self.host_statistics["services_found"])
        
        # Generate the final summary
        try:
            # Create a summary of summaries
            summaries_text = "\n\n".join([
                f"Batch {s['batch_id']} ({len(s['host_ips'])} hosts):\n{s['summary']}"
                for s in self.summaries
            ])
            
            stats_json = json.dumps(self.host_statistics, indent=2)
            
            prompt = f"""
            Create a comprehensive final summary of this network scan.
            
            Network Statistics:
            ```json
            {stats_json}
            ```
            
            Batch Summaries:
            {summaries_text}
            
            Provide a unified security assessment that synthesizes the key findings from all batches,
            highlights the most significant security concerns, and gives an overall security posture.
            """
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security analysis assistant that creates comprehensive security assessments."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            final_summary = response.choices[0].message.content
            
            # Save the final summary
            with open(f"final_scan_summary_{self.timestamp}.txt", "w") as f:
                f.write(final_summary)
            
            # Save all summaries and statistics
            with open(f"all_scan_data_{self.timestamp}.json", "w") as f:
                json.dump({
                    "statistics": self.host_statistics,
                    "batch_summaries": self.summaries,
                    "final_summary": final_summary
                }, f, indent=2)
            
            return final_summary, self.host_statistics
            
        except Exception as e:
            logger.error(f"Error generating final summary: {str(e)}")
            return f"Error generating final summary: {str(e)}", self.host_statistics

class LogAnalysisAgent:
    """
    Agent that processes log files in chunks, creating intermediate summaries
    to manage context window limitations in LLMs.
    """
    
    def __init__(self, client: OpenAI, chunk_size: int = 5000):
        """
        Initialize the log analysis agent.
        
        Args:
            client: OpenAI client for making API calls
            chunk_size: Maximum size of log chunks to process at once
        """
        self.client = client
        self.model = os.getenv("MODEL", "gpt-4")
        self.chunk_size = chunk_size
        self.log_summaries = []
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.event_statistics = {
            "total_logs_processed": 0,
            "suspicious_events": 0,
            "error_events": 0,
            "authentication_events": 0,
            "period_start": None,
            "period_end": None
        }

    def process_log_file(self, log_path: str) -> Dict[str, Any]:
        """
        Process a log file in chunks and generate summaries.
        
        Args:
            log_path: Path to the log file
        
        Returns:
            Dict: Summary of findings from the log file
        """
        try:
            with open(log_path, 'r') as f:
                log_content = f.read()
                
            # Update statistics
            self.event_statistics["total_logs_processed"] += 1
            
            # Process in chunks if the file is large
            if len(log_content) > self.chunk_size:
                chunks = self._split_log_into_chunks(log_content)
                
                # Process each chunk
                chunk_summaries = []
                for i, chunk in enumerate(chunks):
                    summary = self._analyze_log_chunk(chunk, f"{log_path} (chunk {i+1}/{len(chunks)})")
                    chunk_summaries.append(summary)
                    
                # Combine chunk summaries
                combined_summary = self._combine_chunk_summaries(chunk_summaries, log_path)
                self.log_summaries.append(combined_summary)
                return combined_summary
            else:
                # Process the entire file at once
                summary = self._analyze_log_chunk(log_content, log_path)
                self.log_summaries.append(summary)
                return summary
                
        except Exception as e:
            logger.error(f"Error processing log file {log_path}: {str(e)}")
            error_summary = {
                "log_path": log_path,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "summary": "Failed to analyze log file."
            }
            self.log_summaries.append(error_summary)
            return error_summary

    def _split_log_into_chunks(self, log_content: str) -> List[str]:
        """Split log content into manageable chunks"""
        # Try to split at natural log entry boundaries
        lines = log_content.splitlines()
        chunks = []
        current_chunk = []
        current_size = 0
        
        for line in lines:
            line_size = len(line)
            if current_size + line_size > self.chunk_size and current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = [line]
                current_size = line_size
            else:
                current_chunk.append(line)
                current_size += line_size
                
        if current_chunk:
            chunks.append("\n".join(current_chunk))
            
        return chunks

    def _analyze_log_chunk(self, log_chunk: str, log_identifier: str) -> Dict[str, Any]:
        """Analyze a chunk of log data"""
        try:
            prompt = f"""
            Analyze this log chunk from {log_identifier} for security-relevant events:
            
            ```
            {log_chunk[:self.chunk_size]}
            ```
            
            Identify:
            1. Authentication events (successful and failed)
            2. Suspicious activities
            3. Error patterns
            4. Access to sensitive resources
            5. Unusual network connections
            
            Provide a concise summary of security-relevant findings.
            """
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a log analysis assistant specialized in security event detection."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Update statistics based on the analysis
            # This is simplified and should be more sophisticated in a real implementation
            if "authentication failure" in response.choices[0].message.content.lower():
                self.event_statistics["authentication_events"] += 1
            if "suspicious" in response.choices[0].message.content.lower():
                self.event_statistics["suspicious_events"] += 1
            if "error" in response.choices[0].message.content.lower():
                self.event_statistics["error_events"] += 1
                
            summary = {
                "log_path": log_identifier,
                "timestamp": datetime.now().isoformat(),
                "summary": response.choices[0].message.content,
                "chunk_size": len(log_chunk)
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error analyzing log chunk: {str(e)}")
            return {
                "log_path": log_identifier,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "summary": "Failed to analyze log chunk."
            }

    def _combine_chunk_summaries(self, chunk_summaries: List[Dict[str, Any]], log_path: str) -> Dict[str, Any]:
        """Combine multiple chunk summaries into a unified summary"""
        try:
            summaries_text = "\n\n".join([
                f"Chunk {i+1}:\n{s['summary']}"
                for i, s in enumerate(chunk_summaries)
            ])
            
            prompt = f"""
            Create a unified summary of the log file {log_path} based on these chunk analyses:
            
            {summaries_text}
            
            Provide a comprehensive security assessment that synthesizes key findings from all chunks.
            Identify patterns, recurring issues, and security implications.
            """
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a log analysis assistant specialized in security event detection."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            combined_summary = {
                "log_path": log_path,
                "timestamp": datetime.now().isoformat(),
                "summary": response.choices[0].message.content,
                "chunk_count": len(chunk_summaries)
            }
            
            # Save the combined summary
            with open(f"log_summary_{self.timestamp}_{log_path.replace('/', '_')}.txt", "w") as f:
                f.write(combined_summary["summary"])
                
            return combined_summary
            
        except Exception as e:
            logger.error(f"Error combining chunk summaries: {str(e)}")
            return {
                "log_path": log_path,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "summary": "Failed to combine chunk summaries."
            }

    def finalize(self) -> Tuple[str, Dict[str, Any]]:
        """
        Generate a final summary of all log analyses.
        
        Returns:
            Tuple containing the final summary text and statistics dictionary
        """
        try:
            if not self.log_summaries:
                return "No logs were analyzed.", self.event_statistics
                
            # Create a summary of summaries
            summaries_text = "\n\n".join([
                f"Log: {s['log_path']}\n{s['summary']}"
                for s in self.log_summaries
            ])
            
            stats_json = json.dumps(self.event_statistics, indent=2)
            
            prompt = f"""
            Create a comprehensive final summary of all log analyses.
            
            Log Statistics:
            ```json
            {stats_json}
            ```
            
            Log Summaries:
            {summaries_text}
            
            Provide a unified security assessment that synthesizes the key findings from all logs,
            highlights the most significant security concerns, correlates events across logs,
            and gives an overall security assessment.
            """
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security analysis assistant that creates comprehensive security assessments."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            final_summary = response.choices[0].message.content
            
            # Save the final summary
            with open(f"final_log_summary_{self.timestamp}.txt", "w") as f:
                f.write(final_summary)
            
            return final_summary, self.event_statistics
            
        except Exception as e:
            logger.error(f"Error generating final log summary: {str(e)}")
            return f"Error generating final log summary: {str(e)}", self.event_statistics