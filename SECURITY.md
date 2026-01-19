# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this package, please report it through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/tgies/client-certificate-auth/security) of this repository
2. Click **"Report a vulnerability"**
3. Fill out the form with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- Confirmation that your report was received
- Regular updates on the fix progress
- Credit in the security advisory (unless you prefer to remain anonymous)
- A CVE will be requested for confirmed vulnerabilities when appropriate

## Security Best Practices

When using this middleware:

1. **Always strip certificate headers** at your reverse proxy to prevent spoofing
2. **Use `verifyHeader`/`verifyValue`** as defense-in-depth when using header-based auth
3. **Keep dependencies updated** - run `npm audit` regularly
4. **Validate certificate fields** beyond just checking if authentication passed
