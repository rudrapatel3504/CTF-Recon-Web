#!/bin/bash
# Run this script on your Amazon Linux EC2 instance
set -e

echo "Updating system packages..."
sudo yum update -y

echo "Installing required dependencies..."
sudo yum install -y python3 python3-pip python3-devel gcc git nginx

echo "Cloning repository..."
cd /home/ec2-user
if [ ! -d "CTF-Recon-Web" ]; then
    git clone https://github.com/rudrapatel3504/CTF-Recon-Web.git
else
    cd CTF-Recon-Web
    git pull origin main
    cd ..
fi

echo "Setting up Python virtual environment..."
cd /home/ec2-user/CTF-Recon-Web
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
sudo cp deployment/nginx.conf /etc/nginx/conf.d/ctfrecon.conf

echo "Restarting Nginx..."
sudo systemctl enable nginx
sudo systemctl restart nginx
sudo chown -R ec2-user:nginx /home/ec2-user/CTF-Recon-Web

# Nginx needs permission to enter ec2-user home directory to reach the sock file
sudo chmod 711 /home/ec2-user

echo "---------------------------------------------------------"
echo "App setup complete!"
echo "Your app should be accessible at http://$(curl -s ifconfig.me)"
echo "Make sure Port 80 is open in your EC2 Security Group!"
echo "---------------------------------------------------------"
