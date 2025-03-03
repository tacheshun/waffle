# Waffle default rules

Waffle is a Web Application Firewall (WAF) and the default rules  cover common web threats like:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- User-Agent Filtering (Blocking Bots)
- Rate Limiting

## Where do we get the Default Rules?
Reliable sources for security rules that were leveraged when building Waffle are:

### OWASP ModSecurity Core Rule Set (CRS)
OWASP provides mod_security CRS with hundreds of regex patterns to detect malicious requests.
Official repo: https://github.com/coreruleset/coreruleset
We can convert the regex patterns from ModSecurity into Go's regex format (regexp package).

### Cloudflare WAF Rules
Cloudflare has documented attack patterns that can be used as inspiration.
Reference: https://developers.cloudflare.com/waf/managed-rulesets

### Project Honeypot / AbuseIPDB (IP Blacklists)
- These services maintain lists of known malicious IPs.
- We can pull and update these dynamically.
- AbuseIPDB API: https://www.abuseipdb.com/
