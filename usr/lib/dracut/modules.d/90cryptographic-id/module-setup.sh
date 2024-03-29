#!/bin/bash
DIR="/etc/cryptographic_id/initramfs"

depends() {
	echo "dracut-systemd"
	echo "systemd-initrd"
	echo "tpm2-tss"
	return 0
}

installkernel() {
	if [ -n "$(ls -A "${DIR}/cryptsetup")" ]; then
		instmods dm-crypt
		instmods '/crypto/'
	fi
	if [ -n "$(ls -A "${DIR}/tpm2")" ]; then
		instmods '=drivers/char/tpm'
	fi
}

install() {
	inst_binary cat
	inst_binary date
	inst_binary mkdir
	inst_binary mount
	inst_binary rm
	inst_binary systemd-escape
	inst_binary umount
	inst_binary /usr/lib/cryptographic_id/cryptographic-id-rs
	inst /usr/lib/cryptographic_id/initramfs_helper
	inst /usr/lib/cryptographic_id/show_identities
	# shellcheck disable=SC2154
	mkdir -p "${initdir}"/tmp/cryptographic_id
	if [ "$(find "${DIR}" -perm -o=r)" != "" ]; then
		derror "ERR: There are world readable files in ${DIR}\\n"
		exit 1
	fi
	inst_multiple "${DIR}"/*/*

	font="$(tr -d ' \t\n' < "${DIR}/font")"
	printf "%s" "${font}" > "${initdir}/${DIR}/font"
	if [ "${font}" != "" ]; then
		inst_multiple "/usr/share/kbd/consolefonts/${font}"*
		inst_binary gzip
		inst_binary setfont
	fi
	if [ -n "$(ls -A "${DIR}/age")" ]; then
		inst_binary age
	fi
	if [ -n "$(ls -A "${DIR}/cryptsetup")" ]; then
		inst_binary /usr/lib/systemd/systemd-cryptsetup
		inst_binary dd
		inst_libdir_file 'libtss2-tcti-device.so*'
	fi
	if [ -n "$(ls -A "${DIR}/tpm2")" ]; then
		inst_multiple "${DIR}"/tpm2/*/*
		inst_libdir_file 'libtss2-tcti-device.so*'
	fi
	# shellcheck disable=SC2154
	local ssud="${systemdsystemunitdir}"
	inst /usr/lib/systemd/system/cryptographic_id.service
	inst /usr/lib/systemd/system/cryptographic_id_helper@.service
	# shellcheck disable=SC2154
	inst "${moddir}/systemd_wants.conf" \
		"${ssud}/systemd-cryptsetup@.service.d/cryptographic_id.conf"
	# shellcheck disable=SC2154
	inst "${moddir}/systemd_wants.conf" \
		"${ssud}/dracut-pre-pivot.service.d/cryptographic_id.conf"
}
