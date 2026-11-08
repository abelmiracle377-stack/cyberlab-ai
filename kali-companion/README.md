# CyberLab AI Kali Companion

A small offline Python companion for Kali Linux and other Linux distributions.

## Requirements

- Python 3.9 or newer
- No pip packages or API keys required

## Usage

From the root of the CyberLab AI repository:

```bash
python3 kali-companion/cyberlab.py --help
python3 kali-companion/cyberlab.py triage /path/to/sample.bin
python3 kali-companion/cyberlab.py nmap-xml /path/to/authorised-scan.xml
```

The commands print JSON to standard output. Redirect it to a file if you want to retain the result:

```bash
python3 kali-companion/cyberlab.py triage ./sample.bin > triage-report.json
python3 kali-companion/cyberlab.py nmap-xml ./scan.xml > network-report.json
```

## Safety and limitations

- This companion is offline and does not connect to CyberLab AI or any remote service.
- It does not run Nmap, invoke a shell, execute samples, unpack archives, exploit hosts or make network requests.
- Static indicators and entropy are clues, not a malware verdict.
- Nmap XML parsing accepts an existing report only. Use Nmap only against systems you own or are explicitly authorised to assess.
- File triage is limited to 10 MB; Nmap XML is limited to 2 MB.
