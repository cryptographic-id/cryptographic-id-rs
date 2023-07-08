BIN := target/release/cryptographic-id-rs
DRACUTDIR := usr/lib/dracut/modules.d/90cryptographic-id
ETC := $(DESTDIR)/etc/cryptographic_id
INITCPIODIR := usr/lib/initcpio/install
SERVICEDIR := usr/lib/systemd/system

all: $(BIN)

$(BIN):
	cargo build --release

install: $(BIN)
	install -dm 755 $(ETC)
	install -dm 700 $(ETC)/initramfs
	install -dm 700 $(ETC)/initramfs/{insecure,age,cryptsetup,tpm2}
	install -dm 755 $(DESTDIR)/usr/bin $(DESTDIR)/usr/lib/cryptographic_id
	install -dm 755 $(DESTDIR)/$(DRACUTDIR)
	install -dm 755 $(DESTDIR)/$(INITCPIODIR)
	install -dm 755 $(DESTDIR)/$(SERVICEDIR)
	install -m 600 /dev/null $(ETC)/initramfs/font
	install -Dm 755 usr/bin/* $(DESTDIR)/usr/bin
	install -Dm 644 usr/lib/cryptographic_id/* \
		$(DESTDIR)/usr/lib/cryptographic_id
	install -Dm 755 $(BIN) $(DESTDIR)/usr/lib/cryptographic_id
	install -Dm 644 $(DRACUTDIR)/* $(DESTDIR)/$(DRACUTDIR)
	install -Dm 644 $(INITCPIODIR)/* $(DESTDIR)/$(INITCPIODIR)
	install -Dm 644 $(SERVICEDIR)/* $(DESTDIR)/$(SERVICEDIR)
