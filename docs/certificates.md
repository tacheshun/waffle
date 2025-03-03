# TLS Certificate Management

This document describes how to manage TLS certificates for the Waffle WAF.

## Development Certificates

For development and testing, you can generate self-signed certificates using OpenSSL:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName = DNS:localhost,IP:127.0.0.1"
```

Alternatively, for a better development experience with locally-trusted certificates, you can use [mkcert](https://github.com/FiloSottile/mkcert):

```bash
# Install mkcert
brew install mkcert  # macOS with Homebrew
mkcert -install      # Set up the local CA

# Generate certificates
mkdir -p certs
mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1
```

## Production Certificates

For production environments, you should use certificates from a trusted Certificate Authority (CA) such as:

- Let's Encrypt (free, automated)
- Commercial CAs (DigiCert, Sectigo, etc.)

### Using Let's Encrypt

1. Install [certbot](https://certbot.eff.org/)
2. Generate certificates:
   ```bash
   certbot certonly --standalone -d yourdomain.com
   ```
3. Configure Waffle to use the generated certificates:
   ```bash
   ./waffle -listen :443 -backend http://your-backend -tls-cert /etc/letsencrypt/live/yourdomain.com/fullchain.pem -tls-key /etc/letsencrypt/live/yourdomain.com/privkey.pem
   ```

## Certificate Rotation

Certificates should be rotated regularly:

- Development certificates: When they expire or as needed
- Production certificates: Automatically with Let's Encrypt, or according to your security policy

## Security Considerations

1. **Private Key Protection**
   - Restrict access to private keys with appropriate file permissions
   - In production, use a secure key management system if possible

2. **Certificate Validation**
   - Ensure certificates are valid for the domains they protect
   - Verify certificate chain and expiration dates

3. **Cipher Suites**
   - Use modern, secure cipher suites
   - Disable outdated protocols (SSLv3, TLS 1.0, TLS 1.1)

## Certificate Management in CI/CD

For CI/CD pipelines, you can:

1. Generate temporary certificates for testing
2. Use environment variables to specify certificate paths
3. Use a secrets management system to securely provide certificates to your application

## Never Commit Certificates to Version Control

Certificates, especially private keys, should never be committed to version control. The project is configured to prevent this:

- The `certs/` directory is in `.gitignore`
- A pre-commit hook checks for certificate files
- Certificate files are marked as binary in `.gitattributes` 