# Security Best Practices

**Last Updated**: 2025-10-06  
**Version**: 1.0

---

## Table of Contents

1. [Credential Management](#credential-management)
2. [Password Security](#password-security)
3. [Environment Variables](#environment-variables)
4. [File Permissions](#file-permissions)
5. [Network Security](#network-security)
6. [Common Mistakes](#common-mistakes)
7. [Security Checklist](#security-checklist)

---

## Credential Management

### ❌ NEVER DO THIS

These practices expose your credentials and should be avoided:

#### 1. Plaintext Password on Command Line
```bash
# ❌ BAD: Password visible in process list, shell history, logs
vpnclient -u myuser -P mypassword123
```

**Why it's bad**: Anyone with access to the system can see your password in:
- Process list (`ps aux`)
- Shell history (`~/.bash_history`, `~/.zsh_history`)
- System logs
- Process monitoring tools

#### 2. Hardcoded Credentials in Scripts
```bash
# ❌ BAD: Credentials stored in plaintext files
#!/bin/bash
USERNAME="admin"
PASSWORD="secret123"
vpnclient -u "$USERNAME" -P "$PASSWORD"
```

**Why it's bad**:
- Scripts often have loose permissions
- Credentials in version control (git history)
- Shared with team members
- Backed up to insecure locations

#### 3. Credentials in Config Files with Wrong Permissions
```bash
# ❌ BAD: World-readable config file
-rw-r--r-- 1 user user 123 Oct 6 config.txt

password=secret123
```

**Why it's bad**: Any user on the system can read your password

---

## Password Security

### ✅ RECOMMENDED: Use Pre-hashed Passwords

SoftEther VPN supports password hashing using SHA-0. This is the **recommended method**.

#### Step 1: Generate Password Hash
```bash
# Generate hash (do this once)
./vpnclient --gen-hash myuser mypassword123

# Output:
# Username: myuser
# Password: mypassword123
# Password Hash: "T2kl2mB84H5y2tn7n9qf65/8jXI="
```

#### Step 2: Use Hash Instead of Password
```bash
# ✅ GOOD: Use hash, not plaintext password
vpnclient -u myuser --password-hash "T2kl2mB84H5y2tn7n9qf65/8jXI="
```

**Benefits**:
- Hash is safe to store (cannot be reversed to plaintext)
- Can be committed to version control (if needed)
- Can be shared with team members
- Server never sees plaintext password

**Important Note**: The hash is tied to the username. If you change the username, you must regenerate the hash.

---

## Environment Variables

### ✅ RECOMMENDED: Environment Variables

The most secure and convenient method is to use environment variables.

#### Method 1: Session Variables (Temporary)
```bash
# Set for current session
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_PORT="443"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="T2kl2mB84H5y2tn7n9qf65/8jXI="

# Connect (reads from environment)
./vpnclient
```

**Pros**: Simple, no files to secure  
**Cons**: Must set every session

#### Method 2: Shell Profile (Persistent)
```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile
# (Use ~/.bash_profile for login shells)

# SoftEther VPN Credentials
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="T2kl2mB84H5y2tn7n9qf65/8jXI="

# Reload shell config
source ~/.zshrc  # or ~/.bashrc
```

**Pros**: Automatic, no need to set every time  
**Cons**: Visible to all processes run by your user

#### Method 3: Separate Credentials File
```bash
# Create secure credentials file
cat > ~/.softether-vpn-env <<'EOF'
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="T2kl2mB84H5y2tn7n9qf65/8jXI="
EOF

# Secure the file
chmod 600 ~/.softether-vpn-env

# Source before connecting
source ~/.softether-vpn-env
./vpnclient
```

**Pros**: Secure file permissions, separate from shell profile  
**Cons**: Must source before each use

### Supported Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SOFTETHER_SERVER` | VPN server hostname | `vpn.example.com` |
| `SOFTETHER_PORT` | VPN server port | `443` |
| `SOFTETHER_HUB` | Virtual hub name | `VPN` |
| `SOFTETHER_USER` | Username | `myuser` |
| `SOFTETHER_PASSWORD` | Plaintext password (not recommended) | `mypassword` |
| `SOFTETHER_PASSWORD_HASH` | Pre-hashed password (recommended) | `base64hash...` |

### Variable Precedence

Command-line arguments **override** environment variables:

```bash
export SOFTETHER_SERVER="vpn1.example.com"

# Will connect to vpn2.example.com (CLI overrides env)
./vpnclient -s vpn2.example.com
```

---

## File Permissions

### Config Files

If you store credentials in files, they **MUST** have restricted permissions:

#### ✅ Secure Permissions
```bash
# Owner read/write only
-rw------- (600)  # Recommended
chmod 600 ~/.softether-vpn-env

# Owner read-only
-r-------- (400)  # Also acceptable
chmod 400 ~/.softether-vpn-env
```

#### ❌ Insecure Permissions
```bash
# Group/others can read
-rw-r--r-- (644)  # ❌ BAD
-rw-rw-r-- (664)  # ❌ BAD
-rwxrwxrwx (777)  # ❌ VERY BAD
```

### Check File Permissions
```bash
# Check current permissions
ls -l ~/.softether-vpn-env

# Output examples:
-rw-------  # ✅ Secure (600)
-rw-r--r--  # ❌ Insecure (644)
```

### Fix Insecure Permissions
```bash
# Make file owner-only
chmod 600 ~/.softether-vpn-env

# Remove from group and others
chmod go-rwx ~/.softether-vpn-env
```

---

## Network Security

### TLS/SSL Encryption

- ✅ **Always use encryption** (default: enabled)
- ❌ **Never disable encryption** unless absolutely necessary

```bash
# ✅ GOOD: Encryption enabled (default)
./vpnclient -s vpn.example.com ...

# ❌ BAD: Encryption disabled (insecure!)
./vpnclient -s vpn.example.com ... --no-encrypt
```

### Server Certificate Validation

**Current Status**: Certificate validation is disabled by default for compatibility.

**Future Enhancement**: Enable certificate validation for production:
```c
// In softether_bridge.c:
account->CheckServerCert = true;  // Validate server certificate
```

### Port Selection

- ✅ **Use standard HTTPS port** (443) - most likely to work through firewalls
- ✅ **Use alternative port** (992, 8443) if 443 is blocked
- ❌ **Avoid unencrypted ports** (80, 8080) unless absolutely necessary

---

## Common Mistakes

### Mistake 1: Password in Shell History
```bash
# ❌ BAD: This will be saved in ~/.bash_history
./vpnclient -u myuser -P mypassword123
```

**Solution**: Use `--password-hash` or environment variables

### Mistake 2: Password in Process List
```bash
# While running, anyone can see:
ps aux | grep vpnclient
# Output: vpnclient -u myuser -P mypassword123  ← Visible!
```

**Solution**: Use environment variables (not visible in process list)

### Mistake 3: Credentials in Git
```bash
# ❌ BAD: Committed script with credentials
git add scripts/connect.sh  # Contains PASSWORD="secret"
git commit -m "Add VPN script"
git push
```

**Solution**: 
- Use `.gitignore` for credential files
- Use environment variables instead
- If accidentally committed, remove from git history

### Mistake 4: Sudo Without -E Flag
```bash
# ❌ BAD: Environment variables not passed to sudo
export SOFTETHER_PASSWORD_HASH="hash..."
sudo ./vpnclient  # Won't see the environment variable!
```

**Solution**: Use `sudo -E` to preserve environment:
```bash
sudo -E ./vpnclient  # ✅ Passes environment variables
```

### Mistake 5: Plaintext Password with --log-level debug
```bash
# ❌ BAD: Debug logs may contain passwords
./vpnclient -P mypassword --log-level debug
```

**Solution**: Use `--password-hash` and appropriate log level

---

## Security Checklist

Use this checklist to ensure your deployment is secure:

### Credentials
- [ ] Never use plaintext passwords on command line
- [ ] Use pre-hashed passwords (`--gen-hash`)
- [ ] Store credentials in environment variables
- [ ] Don't commit credentials to version control

### Files
- [ ] Credential files have `600` or `400` permissions
- [ ] Shell profile has `600` permissions (`chmod 600 ~/.zshrc`)
- [ ] Scripts with credentials have `700` permissions
- [ ] Add credential files to `.gitignore`

### Network
- [ ] Encryption enabled (don't use `--no-encrypt`)
- [ ] Use TLS/SSL (port 443 or 992)
- [ ] Verify server hostname matches certificate (future)
- [ ] Use strong passwords (12+ characters, mixed case, numbers, symbols)

### Monitoring
- [ ] Check shell history for leaked passwords (`history | grep password`)
- [ ] Check git history for leaked credentials (`git log -p | grep password`)
- [ ] Monitor process list for password arguments (`ps aux | grep password`)
- [ ] Review system logs for credential exposure

### Best Practices
- [ ] Change passwords regularly (every 90 days)
- [ ] Use unique passwords per system
- [ ] Enable multi-factor authentication if available
- [ ] Document security procedures for team
- [ ] Regular security audits

---

## Example: Complete Secure Setup

Here's a complete example of secure VPN setup:

```bash
# 1. Generate password hash
HASH=$(./vpnclient --gen-hash myuser mypassword | grep "Password Hash:" | cut -d'"' -f2)

# 2. Create secure credentials file
cat > ~/.softether-vpn-env <<EOF
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="$HASH"
EOF

# 3. Secure the file
chmod 600 ~/.softether-vpn-env

# 4. Add to .gitignore (if in git repo)
echo ".softether-vpn-env" >> .gitignore

# 5. Create connection script
cat > scripts/vpn-connect.sh <<'EOF'
#!/bin/bash
source ~/.softether-vpn-env
sudo -E ./vpnclient
EOF

chmod 700 scripts/vpn-connect.sh

# 6. Connect
./scripts/vpn-connect.sh
```

---

## Getting Help

If you discover a security vulnerability, please:

1. **Do not** create a public GitHub issue
2. Email security concerns to: [security contact]
3. Allow time for patches before public disclosure

---

## Additional Resources

- [SoftEther VPN Security Features](https://www.softether.org/4-docs/1-manual/3._SoftEther_VPN_Server_Manual/3.4_vpn_Server_Management#3.4.22_Security_Features)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Remember**: Security is not a one-time setup, it's an ongoing process. Regular audits and updates are essential.

🔒 **Stay secure!**
