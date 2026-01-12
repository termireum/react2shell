# React2Shell (Go Version)

React2Shell is a high-performance vulnerability scanner written in Go, specifically designed to detect Server-Side Remote Code Execution (RCE) vulnerabilities in Next.js applications (CVE-2025-55182 & CVE-2025-66478).

This tool improves upon existing proof-of-concept scripts by leveraging Go's native concurrency (Goroutines) and integrating automated reconnaissance via Subfinder.

## Key Features
- Automated Recon: Running -u with a domain automatically triggers Subfinder to discover and scan subdomains.
- High Concurrency: Uses a worker pool pattern to handle hundreds of targets simultaneously.
- Accurate Payloads: Implements specific character encoding (\x60) to ensure the Next.js server-side logic triggers the RCE correctly.
- Flexible Input: Supports single URL targets or bulk scanning via a text file.

## Prerequisites
- Go 1.19 or higher.
- Subfinder (optional but recommended):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

## Installation
1. Clone the repository:
   git clone https://github.com/termireum/react2shell.git
2. Build the binary:
   go build react2shell.go

## Usage
Scan a single domain (automatic subdomain discovery):
./react2shell -u target.com

Scan a list of targets:
./react2shell -l targets.txt -threads 50

## Flags
-u          Target URL or Domain.
-l          Path to a file containing list of hosts.
-threads    Number of concurrent workers (default: 20).

## Disclaimer
This tool is for educational purposes and authorized security testing only. The developer assumes no liability for misuse or damage caused by this tool.

Special Thanks to https://github.com/assetnote/
