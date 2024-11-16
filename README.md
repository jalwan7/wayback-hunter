# Wayback Hunter

A tool for crawling URLs from the Wayback Machine and hunting for vulnerabilities like SQL Injection, XSS, and Open Redirects.

## Features
- Fetch URLs from the Wayback Machine.
- Scan for vulnerabilities: SQLi, XSS, and Open Redirect.
- Generate a vulnerability report in HTML format.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/jalwan7/Wayback-Hunter.git
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:

   ```bash
   python main.py
   ```

## Dependencies

- `requests`
- `aiohttp`
- `tqdm`
- `colorama`
- `aiofiles`


