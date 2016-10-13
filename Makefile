BUILD_NUMBER ?= 0
include VERSION.mk

SIGNER ?= Riigi Infosüsteemi Amet

OPENSSL ?= $(PWD)/target

TMPROOT = $(PWD)/tmp
TARGET = $(TMPROOT)/Library/Security/tokend/EstEID.tokend

default: pkg

clean:
	rm -rf $(TMPROOT)
	git clean -dfx

$(TARGET): $(OPENSSL)
	xcodebuild -project EstEID.tokend/Tokend.xcodeproj VERSION=$(VERSION) BUILD_NUMBER=$(BUILD_NUMBER) OPENSSL=$(OPENSSL) DSTROOT=$(TMPROOT) -configuration Deployment build install

codesign: $(TARGET)
	codesign -f -s "$(SIGNER)" $(TARGET)

esteid-tokend.pkg: $(TARGET)
	pkgbuild --version $(VERSIONEX) \
		--identifier ee.ria.esteid-tokend \
		--root $(TMPROOT) \
		--scripts scripts \
		--install-location / \
		esteid-tokend.pkg

pkg: esteid-tokend.pkg

dist: codesign pkg

signed: codesign
	pkgbuild --version $(VERSIONEX) \
		--identifier ee.ria.esteid-tokend \
		--root $(TMPROOT) \
		--scripts scripts \
		--install-location / \
		--sign "$(SIGNER)" \
		esteid-tokend.pkg

$(OPENSSL):
	test -e openssl || git clone --depth=1 https://github.com/openssl/openssl.git -b OpenSSL_1_0_2-stable
	(cd openssl \
	&& KERNEL_BITS=64 ./config --prefix=$(OPENSSL) -mmacosx-version-min=10.9 no-shared no-ssl2 no-idea no-dtls no-psk no-srp no-apps \
	&& make depend \
	&& make \
	&& make install_sw)
