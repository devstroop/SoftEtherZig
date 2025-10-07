# Configuration Guide

SoftEtherZig VPN Client supports three configuration methods with the following priority:

**Priority Order (highest to lowest):**
1. **Command-line arguments** (highest priority)
2. **Environment variables** (medium priority)
3. **Configuration file** (lowest priority)

## Configuration File

### Default Location

The default configuration file location is:
```
~/.config/softether-zig/config.json
```

You can also specify a custom config file location using the `--config` flag:
```bash
vpnclient --config /path/to/custom/config.json
```

### File Format

The configuration file uses JSON format. All fields are optional - any missing values will fall back to environment variables or command-line defaults.

### Minimal Example

Create `~/.config/softether-zig/config.json`:

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "base64-hashed-password"
}
```

Then run:
```bash
vpnclient  # Uses config file
```

### Complete Example

See `config.example.json` in the project root for a fully documented example with all available options.

## Configuration Schema

### Server Connection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server` | string | *required* | VPN server hostname or IP |
| `port` | number | 443 | VPN server port |
| `hub` | string | *required* | Virtual hub name |
| `account` | string | username | Account name (defaults to username) |

### Authentication

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `username` | string | *required* | Username for authentication |
| `password` | string | null | Plaintext password (NOT recommended) |
| `password_hash` | string | null | Pre-hashed password (recommended) |

**Security Note:** Use `password_hash` instead of `password`. Generate hash with:
```bash
vpnclient --gen-hash myuser mypassword
```

### Connection Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `use_encrypt` | boolean | true | Enable encryption |
| `use_compress` | boolean | true | Enable compression |
| `max_connection` | number | 0 | Max connections (0=server policy, 1-32=force) |

### IP Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ip_version` | string | "auto" | IP version: "auto", "ipv4", "ipv6", "dual" |

### Static IPv4 Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `static_ipv4` | string | null | Static IPv4 address (e.g., "10.0.0.2") |
| `static_ipv4_netmask` | string | null | IPv4 netmask (e.g., "255.255.255.0") |
| `static_ipv4_gateway` | string | null | IPv4 gateway (e.g., "10.0.0.1") |

### Static IPv6 Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `static_ipv6` | string | null | Static IPv6 address (e.g., "2001:db8::1") |
| `static_ipv6_prefix` | number | null | IPv6 prefix length (e.g., 64) |
| `static_ipv6_gateway` | string | null | IPv6 gateway (e.g., "fe80::1") |

### DNS Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dns_servers` | array[string] | null | DNS servers (e.g., ["8.8.8.8", "8.8.4.4"]) |

### Reconnection Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `reconnect` | boolean | true | Enable automatic reconnection |
| `max_reconnect_attempts` | number | 0 | Max retry attempts (0=infinite) |
| `min_backoff` | number | 5 | Minimum backoff delay (seconds) |
| `max_backoff` | number | 300 | Maximum backoff delay (seconds) |

## Configuration Methods

### Method 1: Configuration File Only

**Setup:**
```bash
mkdir -p ~/.config/softether-zig
cat > ~/.config/softether-zig/config.json <<EOF
{
  "server": "vpn.example.com",
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "$(vpnclient --gen-hash myuser mypassword)"
}
EOF
```

**Usage:**
```bash
vpnclient  # All settings from config file
```

### Method 2: Config File + Environment Variables

**Setup:**
```bash
# config.json
{
  "server": "vpn.example.com",
  "hub": "VPN"
}

# Environment variables (override config file)
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="base64hash"
```

**Usage:**
```bash
vpnclient  # Server/hub from file, auth from env vars
```

### Method 3: Config File + CLI Override

**Setup:**
```bash
# config.json contains default server
{
  "server": "vpn-default.example.com",
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "hash"
}
```

**Usage:**
```bash
# Override server via CLI
vpnclient --server vpn-backup.example.com

# Override IP version
vpnclient --ip-version ipv4

# Override multiple settings
vpnclient --server vpn2.example.com --port 8443 --no-compress
```

## Use Cases

### Development Environment

Store common settings in config file, override per-connection:

```json
{
  "hub": "DEV",
  "username": "developer",
  "password_hash": "devhash",
  "ip_version": "ipv4",
  "use_compress": false
}
```

```bash
vpnclient --server dev1.vpn.com  # Use dev1
vpnclient --server dev2.vpn.com  # Use dev2
```

### Production Deployment

Use config file for base settings, sensitive data from env vars:

```json
{
  "server": "vpn.production.com",
  "port": 443,
  "hub": "PROD",
  "use_encrypt": true,
  "use_compress": true,
  "reconnect": true,
  "max_reconnect_attempts": 0
}
```

```bash
export SOFTETHER_USER="${PROD_VPN_USER}"
export SOFTETHER_PASSWORD_HASH="${PROD_VPN_HASH}"
vpnclient  # Credentials from env, config from file
```

### Static IP Configuration

```json
{
  "server": "vpn.example.com",
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "hash",
  "ip_version": "dual",
  "static_ipv4": "10.0.0.50",
  "static_ipv4_netmask": "255.255.255.0",
  "static_ipv4_gateway": "10.0.0.1",
  "static_ipv6": "2001:db8::50",
  "static_ipv6_prefix": 64,
  "static_ipv6_gateway": "2001:db8::1",
  "dns_servers": ["8.8.8.8", "2001:4860:4860::8888"]
}
```

## Security Best Practices

### 1. File Permissions

Protect your config file from unauthorized access:
```bash
chmod 600 ~/.config/softether-zig/config.json
```

### 2. Use Password Hash

**Never** store plaintext passwords:
```bash
# Generate hash
HASH=$(vpnclient --gen-hash myuser mypassword)

# Store in config
{
  "username": "myuser",
  "password_hash": "$HASH"
}
```

### 3. Sensitive Data in Environment

For highly sensitive environments, use environment variables for credentials:
```json
{
  "server": "vpn.example.com",
  "hub": "VPN"
}
```

```bash
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="$(vpnclient --gen-hash myuser mypassword)"
vpnclient
```

### 4. Multiple Configurations

Use different config files for different environments:
```bash
vpnclient --config ~/.config/softether-zig/dev.json
vpnclient --config ~/.config/softether-zig/staging.json
vpnclient --config ~/.config/softether-zig/prod.json
```

## Troubleshooting

### Config File Not Found

The client will silently ignore missing config files and fall back to environment variables and CLI arguments:

```bash
# This works even without config file
vpnclient -s vpn.example.com -H VPN -u myuser -P mypass
```

### Invalid JSON

If the config file contains invalid JSON, you'll see:
```
Error loading config file: invalid JSON
```

Validate your JSON:
```bash
python3 -m json.tool ~/.config/softether-zig/config.json
```

### Priority Confusion

Remember the priority order:
```
CLI > Environment Variables > Config File
```

To see which settings are active, use verbose mode:
```bash
vpnclient --log-level debug
```

### Permission Denied

If you get "Permission denied" when reading config:
```bash
chmod 600 ~/.config/softether-zig/config.json
```

## Migration Guide

### From Environment Variables

**Before:**
```bash
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD_HASH="hash"
vpnclient
```

**After:**
```bash
# Create config.json
{
  "server": "vpn.example.com",
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "hash"
}

# Simply run
vpnclient
```

### From CLI Arguments

**Before:**
```bash
vpnclient -s vpn.example.com -p 443 -H VPN -u myuser --password-hash hash --ip-version ipv4
```

**After:**
```bash
# Create config.json with all options
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "hash",
  "ip_version": "ipv4"
}

# Simply run
vpnclient
```

## Examples Repository

See the project root for example configurations:
- `config.example.json` - Full configuration with all options
- `config.minimal.json` - Minimal working configuration

Copy and modify these for your needs:
```bash
cp config.example.json ~/.config/softether-zig/config.json
nano ~/.config/softether-zig/config.json  # Edit as needed
```
