NATIVE_PATH = /Library/Security/tokend
ifeq ($(BUILD_NUMBER),)
	BUILD_NUMBER = 0
endif
include VERSION.mk
SIGNCERT ?= Developer ID Application: Riigi Infosüsteemi Amet
INSTCERT ?= Developer ID Installer: Riigi Infosüsteemi Amet
OPENSSL ?= $(PWD)/../target

build:
	xcodebuild -project EstEID.tokend/Tokend.xcodeproj VERSION=$(VERSION) BUILD_NUMBER=$(BUILD_NUMBER) OPENSSL=$(OPENSSL) -configuration Deployment  clean build

codesign: build
	codesign -f -s "$(SIGNCERT)" EstEID.tokend/build/EstEID.tokend

package: build
	 pkgbuild --version $(VERSIONEX) \
                --identifier ee.ria.esteid-tokend \
                --root "EstEID.tokend/build/EstEID.tokend" \
                --install-location "$(NATIVE_PATH)/EstEID.tokend" \
                esteid-tokend_$(VERSIONEX).pkg

signedpackage: codesign
	 pkgbuild --version $(VERSIONEX) \
                --identifier ee.ria.esteid-tokend \
                --root "EstEID.tokend/build/EstEID.tokend" \
                --sign "$(INSTCERT)" \
                --install-location "$(NATIVE_PATH)/EstEID.tokend" \
                esteid-tokend_$(VERSIONEX).pkg

