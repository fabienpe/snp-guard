#!/bin/bash

set -e

TMP_FILE=$(mktemp)
echo $HOSTS_FILE

SCRIPT_DIR=$(dirname $0)
VERIFY_REPORT_BIN=$(realpath $SCRIPT_DIR/../build/bin/verify_report)
SSH_HOSTS_FILE=$(realpath $SCRIPT_DIR/../build/known_hosts)

VM_CONFIG=""
HOST=localhost
PORT=2222
USER=ubuntu

IN_REPORT=/etc/report*  # .bin and .json
OUT_REPORT_FOLDER=build/verity/
TOML_VM_CONFIG=build/guest/vm-config.toml  # Needed to get processor model

usage() {
  echo "$0 [options]"
  echo " -vm-config <path>                      path to VM config file [Mandatory]"
  echo " -host <string>                         hostname or IP address of the VM (default: $HOST)"
  echo " -port <int>                            SSH port of the VM (default: $PORT)"
  echo " -user <string>                         VM user to login to (default: $USER)"
  echo " -out <path>                            Folder path to output attestation reports (default: $OUT_REPORT_FOLDER)"
  exit
}

while [ -n "$1" ]; do
	case "$1" in
		-vm-config) VM_CONFIG="$2"
			shift
			;;
		-host) HOST="$2"
			shift
			;;
		-port) PORT="$2"
			shift
			;;
		-user) USER="$2"
			shift
			;;
		-out) OUT_REPORT_FOLDER="$2"
			shift
			;;
		*) 		usage
				;;
	esac

	shift
done

OUT_REPORT_BIN="$OUT_REPORT_FOLDER/report.bin"
OUT_REPORT_JSON="$OUT_REPORT_FOLDER/report.json"
CERT_FOLDER=$OUT_REPORT_FOLDER

if [ ! -f "$VM_CONFIG" ]; then
    echo "Invalid VM config file: $VM_CONFIG"
    usage
fi

# clean up known_hosts file before running the script
rm -rf $SSH_HOSTS_FILE

echo "Fetching attestation report via SCP.."
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=$SSH_HOSTS_FILE -P $PORT $USER@$HOST:$IN_REPORT $OUT_REPORT_FOLDER || {
    echo "Failed to connect to VM"
	rm -rf $SSH_HOSTS_FILE
    exit 1
}

echo "Verifying attestation report.."
FINGERPRINT=$(ssh-keygen -lf $SSH_HOSTS_FILE | awk '{ print $2 }' | cut -d ":" -f 2)
$VERIFY_REPORT_BIN --input $OUT_REPORT_JSON --vm-definition $VM_CONFIG --report-data $FINGERPRINT || {
	echo "Failed to attest the VM"
	rm -rf $SSH_HOSTS_FILE
	exit 1
}

echo "Done! You can safely connect to the CVM using the following command:"
echo "ssh -p $PORT -o UserKnownHostsFile=$SSH_HOSTS_FILE $USER@$HOST"
echo "Guest SSH fingerprint: $(ssh-keygen -lf $SSH_HOSTS_FILE | awk '{ printf ("%s %s", $2, $4) }' )"

if command -v "snpguest" >/dev/null 2>&1; then
	# If snpguest tool in PATH, then use it to verify
	printf "\nChecking using AMD's snpguest tool:"
    PROCESSOR_MODEL=$(awk -F'=' '/^host_cpu_family/ {gsub(/^[[:space:]]+|[[:space:]]+$|"/, "", $2); print $2; exit}' $TOML_VM_CONFIG | tr '[:upper:]' '[:lower:]')
	snpguest fetch ca pem  $CERT_FOLDER $PROCESSOR_MODEL
	snpguest fetch vcek -p $PROCESSOR_MODEL pem $CERT_FOLDER $OUT_REPORT_BIN
	snpguest verify attestation $CERT_FOLDER $OUT_REPORT_BIN
	REPORT_DATA=$(snpguest display report $OUT_REPORT_BIN | \
	              awk '/Report Data:/ {flag=1; next} /^$/ {flag=0} flag {print}' | \
				  tr -d '[:space:]' | \
				  sed 's/00*$//' | \
				  xxd -r -p | \
				  base64 | \
				  sed 's/=*$//')
	if [ "$REPORT_DATA" = "$FINGERPRINT" ]; then
    	echo "Report data matches SSH key fingerprint ($FINGERPRINT)."
	else
    	echo "Report data does not math SSH key fingerprint:"
		echo "Report data: $REPORT_DATA"
		echo "Fingerprint: $FINGERPRINT"
	fi
fi