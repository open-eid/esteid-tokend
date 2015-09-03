#!/bin/bash
echo "Clean token cache!"
sudo rm -rf /var/db/TokenCache/tokens/
sudo mkdir /var/db/TokenCache/tokens/
echo "Remove the old version!"
sudo rm -rf /Library/Security/tokend/EstEID.tokend/
echo "Build and install!"
sudo xcodebuild -project EstEID.tokend/Tokend.xcodeproj -configuration Development clean install DSTROOT=/