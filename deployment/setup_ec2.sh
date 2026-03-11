#!/bin/bash
# Run this entire script on your freshly created Ubuntu EC2 instance
set -e

echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "Installing required dependencies..."
sudo apt install -y python3-pip python3-venv python3-dev nginx git

echo "Cloning repository..."
cd /home/ubuntu
if [ ! -d "CTF-Recon-Web" ]; then
    git clone https://github.com/rudrapatel3504/CTF-Recon-Web.git
else
    cd CTF-Recon-Web
    git pull origin main
    cd ..
fi

echo "Setting up Python virtual environment..."
cd /home/ubuntu/CTF-Recon-Web
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Configuring Systemd..."
sudo cp deployment/ctfrecon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start ctfrecon
sudo systemctl enable ctfrecon

echo "Configuring Nginx..."
sudo rm -f /etc/nginx/sites-enabled/default
sudo cp deployment/nginx.conf /etc/nginx/sites-available/ctfrecon
if [ ! -f "/etc/nginx/sites-enabled/ctfrecon" ]; then
    sudo ln -s /etc/nginx/sites-available/ctfrecon /etc/nginx/sites-enabled/
fi

echo "Restarting Nginx..."
sudo systemctl restart nginx
sudo chown -R ubuntu:www-data /home/ubuntu/CTF-Recon-Web

echo "---------------------------------------------------------"
echo "App setup complete!"
echo "Your app should be accessible at http://$(curl -s ifconfig.me)"
echo "Make sure Port 80 is open in your EC2 Security Group!"
echo "---------------------------------------------------------"
