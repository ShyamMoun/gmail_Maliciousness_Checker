# Gmail Maliciousness Checker

A Python-based email security tool that analyzes email sender details, subject lines, message content, and URLs for potentially suspicious indicators.

## Features

- Detects selected urgency and social-engineering phrases.
- Examines URLs for potentially suspicious characteristics.
- Produces a simple risk score and severity label.
- Explains the indicators that contributed to the result.
- Includes automated unit tests.

## Technologies

- Python 3
- Regular Expressions
- Python Standard Library
- `unittest`

## Limitations

This tool uses simple heuristic rules. It may produce false positives and false negatives. A low-risk result does not guarantee that an email is safe, and a high-risk result does not prove maliciousness. The initial version does not access Gmail, execute attachments, visit URLs, or authenticate senders.
