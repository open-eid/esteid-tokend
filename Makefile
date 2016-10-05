NATIVE_PATH = /Library/Security/tokend
ifeq ($(BUILD_NUMBER),)
	BUILD_NUMBER = 0
endif
include VERSION.mk
SIGNCERT ?= Developer ID Application: Riigi Infosüsteemi Amet
INSTCERT ?= Developer ID Installer: Riigi Infosüsteemi Amet
PROJ = xcodebuild -project EstEID.tokend/Tokend.xcodeproj VERSION=$(VERSION) BUILD_NUMBER=$(BUILD_NUMBER) -configuration Deployment -target EstEID

pkg:
	$(PROJ) clean build

	codesign -f -s "$(SIGNCERT)" "EstEID.tokend/build/EstEID.tokend"

	pkgbuild --version $(VERSIONEX) \
		--identifier ee.ria.esteid-tokend \
		--root "EstEID.tokend/build/EstEID.tokend" \
		--sign "$(INSTCERT)" \
		--install-location "$(NATIVE_PATH)/EstEID.tokend" \
		esteid-tokend_$(VERSIONEX).pkg

	pkgbuild --component EstEID.tokend/build/EstEID.tokend.dSYM \
		--sign "$(INSTCERT)" \
		--identifier "ee.ria.esteid-tokend-dbg" --version "$(VERSIONEX)" \
		--install-location $(NATIVE_PATH) \
		esteid-tokend-dbg_$(VERSIONEX).pkg
