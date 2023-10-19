#!/usr/bin/env bash
set -e -x
export TCTI="tabrmd:bus_type=session"
export TPM2TOOLS_TCTI="${TCTI}"
DIR="$(pwd)/tests/swtpm"
TMPDIR="$(mktemp -d)"
KILL_PIDS=()
cleanup_pids() {
	for pid in "${KILL_PIDS[@]}"; do
		if kill -0 "${pid}" &> /dev/null; then
			kill "${pid}" || true
		fi
	done
}
cleanup() {
	local pid
	swtpm_ioctl --tcp 127.0.0.1:2322 -s
	cleanup_pids
	cleanup_pids -9
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT
cp -r "${DIR}" "${TMPDIR}"
# To create a new persistent state:
# swtpm_setup --tpm2 --tpmstate "${DIR}" --pcr-banks sha1,sha256 --display
swtpm socket \
	--tpm2 \
	--tpmstate dir="${TMPDIR}/swtpm" \
	--flags startup-clear \
	--ctrl type=tcp,port=2322 \
	--server type=tcp,port=2321 &
KILL_PIDS+=("$!")
sleep 0.1 # Wait until started
# in gitlab container, tests are running as root
/usr/sbin/tpm2-abrmd --session --allow-root --tcti=swtpm &
KILL_PIDS+=("$!")
sha256="0000000000000000000000000000000000000000000000000000000000000000"
tpm2_pcrextend \
	"5:sha256=0x${sha256}" \
	"7:sha256=0x${sha256}"
"${@}"
