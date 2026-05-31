# 1. Start everything
sudo systemctl start suricata
python3 suricata_dashboard.py

# 2. Check alerts
sudo tail -f /var/log/suricata/fast.log

# 3. Update rules
sudo suricata-update

# 4. Test configuration
sudo suricata -T

# 5. Restart after changes
sudo systemctl restart suricata

# 6. Check port 8080
sudo lsof -i :8080

# 7. Stop everything
sudo systemctl stop suricata
# Press Ctrl+C on dashboard
