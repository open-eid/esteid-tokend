# EstEID tokend

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority

## Building
[![Build Status](https://travis-ci.org/open-eid/esteid-tokend.svg?branch=master)](https://travis-ci.org/open-eid/esteid-tokend)
        
### OSX

1. Fetch the source

        git clone https://github.com/open-eid/esteid-tokend
        cd esteid-tokend

2. Build & Install (clears token cache & does a clean install)

        sudo sh clean_install.sh
        
3. Or do it manually
        
 3.1 Build

        xcodebuild -project EstEID.tokend/Tokend.xcodeproj
        
 3.2 Install
        
        xcodebuild -project EstEID.tokend/Tokend.xcodeproj clean install DSTROOT=/

4. Execute

        open /Application/Safari.app

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
