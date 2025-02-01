#!/bin/bash

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install -r requirements.txt

# Check for sudo access
if [ "$EUID" -ne 0 ]; then
    echo "Please run the network analyzer with sudo privileges when scanning."
    echo "Example: sudo .venv/bin/python network_security_analyzer.py"
fi

# Create convenience script
cat > run_analyzer.sh << 'EOF'
#!/bin/bash
source .venv/bin/activate
sudo .venv/bin/python network_security_analyzer.py "$@"
EOF

chmod +x run_analyzer.sh

echo "Setup complete!"
echo "To run the analyzer, use: ./run_analyzer.sh"
