# This scripts installs the floss binary into the users /usr/bin
# This makes it available to run and avoids some of the complexity with finding the binary at runtime.

set -e

# Remove previous install
rm -f floss-v3.1.1-linux.zip
rm -f /usr/bin/floss

# Download latest version of Floss (last updated June 2025)
wget https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip
# Extract zip files and move it into /usr/bin
unzip -o floss-v3.1.1-linux.zip
rm -f floss-v3.1.1-linux.zip
mv floss /usr/bin/floss
chmod +x /usr/bin/floss
echo "floss installed"