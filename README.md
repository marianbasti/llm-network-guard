# Network Security Analyzer

An AI-powered network security analysis tool that combines Nmap scanning with LLM-based vulnerability assessment.

## Features

- Automated network discovery and port scanning
- Service and OS detection
- AI-powered security analysis
- System log analysis
- Comprehensive security reports
- Multiple report formats (Markdown, HTML)

## Prerequisites

- Python 3.8+
- Sudo/Administrator privileges
- Nmap installed
- OpenAI (or compatible) API LLM endpoint
- `.env` file with credentials (template provided)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd llm-guard
```

2. Copy the example .env file and configure your credentials:
```bash
cp .env.example .env
# Edit .env with your actual OpenAI API credentials
```

The .env file should contain:
```ini
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=your_base_url_here  # Optional - remove if using default OpenAI endpoint
```

3. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

## Usage

Run the analyzer with:
```bash
./run_analyzer.sh
```

The script will:
1. Scan your local network
2. Analyze open ports and services
3. Check system logs for security issues
4. Generate a comprehensive security report

## Output

The analyzer generates several files:
- `security_report_YYYYMMDD_HHMMSS.[md|html]`: Main security report
- `network_scan_YYYYMMDD_HHMMSS.log`: Scan logs
- `network_scan_detailed_YYYYMMDD_HHMMSS.json`: Detailed scan data

## Security Considerations

- Requires sudo privileges for network scanning
- Only scan networks you have permission to analyze
- Keep your OpenAI API key secure
- Review generated reports for sensitive information before sharing

## Technical Details

### Components

- **Network Scanner**: Uses Nmap for network discovery and port scanning
- **AI Analysis**: Leverages OpenAI GPT-4 for security assessment
- **Log Analyzer**: Examines system logs for security issues
- **Report Generator**: Creates detailed security reports

### Dependencies

- `python-nmap`: Network scanning
- `openai`: AI-powered analysis
- `netifaces`: Network interface detection
- `psutil`: System information
- `python-dotenv`: Environment configuration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
