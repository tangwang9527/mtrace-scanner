# mtrace-scanner

A static and semantic analysis tool for detecting high-privilege vulnerabilities and boundary violations caused by untrusted metadata in Kubernetes controllers and operators.

## Directory Structure

```text
mtrace-scanner/
├── .github/
│   └── workflows/
│       ├── scan.yml          # Single-project scanning workflow
│       └── batch-scan.yml    # Sharded batch scanning workflow (supports 1000+ repos)
├── config/
│   └── repositories.json     # Target repository list for batch scanning
├── scripts/
│   └── batch.py              # Sharding, scanning orchestration, aggregation, and reporting
└── mtrace.go                 # Core detector implementation
