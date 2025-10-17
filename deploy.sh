#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <username> <server_ip>"
    exit 1
fi

USERNAME=$1
SERVER_IP=$2
BINARY_NAME="staticgate"
SERVICE_NAME="staticgate"

# Build the Go binary for Linux x86_64
echo "Building staticgate binary..."
GOOS=linux GOARCH=amd64 go build -o $BINARY_NAME

# Copy the binary to the server
echo "Copying binary to server..."
scp $BINARY_NAME $USERNAME@$SERVER_IP:/tmp/ > /dev/null
ssh $USERNAME@$SERVER_IP "sudo mv /tmp/$BINARY_NAME /usr/local/bin/$BINARY_NAME && sudo chmod +x /usr/local/bin/$BINARY_NAME" > /dev/null

# Set permissions and capabilities on the server
echo "Setting up binary on server..."
ssh $USERNAME@$SERVER_IP << EOF > /dev/null
    # Stop the existing service if it is running
    if systemctl is-active --quiet $SERVICE_NAME; then
        sudo systemctl stop $SERVICE_NAME
    fi

    # Set capabilities on the binary
    sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/$BINARY_NAME
EOF

# Copy the .env file to the server (if it exists)
if [ -f ".env" ]; then
    echo "Copying .env file to server..."
    scp .env $USERNAME@$SERVER_IP:/tmp/.env > /dev/null
    ssh $USERNAME@$SERVER_IP << EOF > /dev/null
        sudo mkdir -p /etc/staticgate
        sudo mv /tmp/.env /etc/staticgate/.env
        sudo chown root:root /etc/staticgate/.env
        sudo chmod 600 /etc/staticgate/.env
EOF
else
    echo "Warning: .env file not found. Make sure to set STATICGATE_API_KEY on the server."
fi

# Copy the service file to the server
echo "Copying service file to server..."
scp staticgate.service $USERNAME@$SERVER_IP:~/ > /dev/null

# Update the service file on the server
echo "Updating service configuration..."
ssh $USERNAME@$SERVER_IP << EOF > /dev/null
    sudo mv ~/staticgate.service /etc/systemd/system/staticgate.service
    sudo chown root:root /etc/systemd/system/staticgate.service
    sudo chmod 644 /etc/systemd/system/staticgate.service
    
    # Enable persistent journaling
    echo "Enabling persistent journaling..."
    sudo mkdir -p /var/log/journal
    sudo chown root:systemd-journal /var/log/journal
    sudo chmod 2755 /var/log/journal
    sudo systemctl restart systemd-journald
    
    sudo systemctl daemon-reload
    sudo systemctl enable $SERVICE_NAME
    sudo systemctl start $SERVICE_NAME
    echo "Service status:"
    sudo systemctl status $SERVICE_NAME
    echo "Recent logs:"
    sudo journalctl -u $SERVICE_NAME --lines=20
EOF

echo "Deployment complete!"
