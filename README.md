# Web Vulnerability Detection Tool

## Overview

This project implements an automated web vulnerability detection tool capable of identifying common security issues such as SQL injection, XXE, XSS, and SSRF attacks. The tool employs concurrent processing, logging, and caching to enhance the efficiency of vulnerability assessments.

## File Structure

- *Main.py*: The main script containing the vulnerability detection algorithms.
- *Cache.py*: A module for caching responses and optimizing subsequent scans.
- *vulnerability_scan1.log*: Log file to store detailed information about the vulnerability scans.

## Usage

1. *Run the Main Script*: Execute the `Main.py` script and provide the target URL for vulnerability detection when prompted.

   ```bash
   python Main.py
## Usage

- *Input URL*: Enter the URL of the web application you wish to scan for vulnerabilities.

- *Analysis Results*: The tool will perform vulnerability tests and display the results on the console. Detected vulnerabilities are logged in the `vulnerability_scan1.log` file.

- *Overall Time Taken*: At the end of the scan, the script will provide the overall time taken for vulnerability detection.

- *Review Log File*: Check the `vulnerability_scan1.log` file for detailed information on the scan process and detected vulnerabilities.

## Dependencies

- *requests*: For making HTTP requests.
- *BeautifulSoup*: For HTML parsing.
- *concurrent.futures*: For concurrent processing.
- *pickle*: For caching responses.

## Notes

- The tool's efficiency is enhanced through concurrent processing, logging, and caching.
- Customize the SQL injection payloads and other testing functions in `Main.py` as needed.
- The cache is stored in `cache.pickle`, and the log file is stored in `vulnerability_scan1.log`.
