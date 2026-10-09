# Education Portal Security tasks

An educational Flask and SQLite web application demonstrating common web security vulnerabilities and their secure fixes.

## Project Versions

- `vulnerable_version/` - intentionally vulnerable version for local testing
- `safe_version/` - secured version using defensive controls
- `csrf_demo/` - local CSRF demonstration page
- `evidence/` - screenshots and assessment evidence

## Demonstrated Vulnerabilities

- Reflected XSS
- Stored XSS
- DOM-based XSS
- Cross-Site Request Forgery (CSRF)
- SQL Injection: easy
- SQL Injection: intermediate
- SQL Injection: advanced

## Security Fixes

- Jinja autoescaping
- `textContent` instead of unsafe `innerHTML`
- CSRF token validation
- Parameterized SQL queries
- Password confirmation for profile updates
- Input validation

## Local Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
