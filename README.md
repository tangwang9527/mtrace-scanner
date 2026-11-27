# mtrace-scanner
A tool for detecting high-privilege vulnerabilities caused by metadata.

# Directory Structure
mtrace-scanner/
├── .github/
│   └── workflows/
│       ├── scan.yml          # Single-project scanning
│       └── batch-scan.yml    # Batch scanning
├── config/
│   └── repositories.json    # List of projects to scan
├── scripts/
│   └── batch.py ​​            # Grouping, scanning, aggregation, and reporting
└── mtrace.go                # Original detector
