# 1. CLEAN UP old routes/interfaces
sudo route -n flush
sudo ifconfig utun8 down 2>/dev/null || true

# 2. START VPN (if not running)
sudo pkill -9 vpnclient 
sudo ./zig-out/bin/vpnclient --server worxvpn.662.cloud --port 443 --hub VPN --user devstroop --password-hash "T2kl2mB84H5y2tn7n9qf65/8jXI="

# Wait for "TUN device: utunX" message, then:

# 3. CONFIGURE THE CORRECT INTERFACE (utun6 in this case)
sudo ifconfig utun6 10.21.255.100 10.21.0.1 netmask 255.255.0.0

# 4. ADD ROUTE TO VPN NETWORK
sudo route add -net 10.21.0.0/16 10.21.0.1

# 5. VERIFY CONFIGURATION
ifconfig utun6
netstat -rn | grep 10.21

# 6. TEST CONNECTIVITY
ping -c 10 10.21.0.1

# 7. CHANGE DEFAULT ROUTE (optional)
sudo route change default 10.21.0.1

# 8. TO RESTORE INTERNET ACCESS VIA HOME ROUTER
sudo route change default 192.168.1.1