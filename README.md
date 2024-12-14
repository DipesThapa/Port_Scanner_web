# Advanced Nmap Web-Based Port Scanner

This project provides a **web interface** for running advanced Nmap scans against a specified target, integrating functionalities like OS detection, version detection, and vulnerability checks. It leverages the power of Nmap’s `-A` and `--script=vuln` options, while providing a user-friendly and visually appealing interface using Bootstrap.

**Key Features:**
- **Web Interface:** Run Nmap scans from a browser-based form rather than the command line.
- **OS and Version Detection:** Identify the operating system and service versions running on open ports.
- **Vulnerability Checks:** Leverage `--script=vuln` to scan for known vulnerabilities.
- **Interactive Results:** Displays structured data, including open ports, associated services, and script outputs in a readable, tabular format.
- **Disclaimer & Legal Notice:** Built-in modal to remind users about the importance of authorized and ethical usage.

## Prerequisites
- **Python 3.x**
- **Nmap Installed**  
  Install Nmap using your system’s package manager:
  - Debian/Ubuntu: `sudo apt-get install nmap`
  - Fedora/CentOS: `sudo yum install nmap`
  - macOS (with Homebrew): `brew install nmap`
  
- **Flask Installed:**  
  Install Flask via pip:
  ```bash
  pip3 install flask



