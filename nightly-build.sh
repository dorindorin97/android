#!/bin/bash

# Copyleft (C) 2014 The cSploit Project
#
# Licensed under the GNU GENERAL PUBLIC LICENSE version 3 'or later'
# The GNU General Public License is a free, copyleft license for software and other kinds of works.
# see the LICENSE file distributed with this work for a full version of the License.

set -euo pipefail

CYAN="\\033[1;36m"
GREEN="\\033[1;32m"
YELLOW="\\033[1;33m"
RED="\\033[1;31m"
RESET="\\033[0m"

DATE=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${DIR}/logs"
BUILD_LOG="${LOG_DIR}/${TIMESTAMP}.log"
MAX_DAYS=15

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"

# Log function
log() {
    echo -e "${1}" | tee -a "${BUILD_LOG}"
}

# Error handler
die() {
    log "${RED}An error occurred while building the nightly APK${RESET}"
    log "${RED}See ${BUILD_LOG} for more info${RESET}"
    exit 1
}

# Trap errors
trap die ERR

# Clean old logs
log "${YELLOW}Cleaning old log files (older than ${MAX_DAYS} days)${RESET}"
find "${LOG_DIR}" -name "*.log" -mtime "+${MAX_DAYS}" -delete 2>/dev/null || true

# Initialize build directory
export NIGHTLY_BUILD=1
NIGHTLIES_OUT_DIR="${NIGHTLIES_OUT_DIR:-${DIR}/cSploit/build}"
mkdir -p "${NIGHTLIES_OUT_DIR}"

cd "${DIR}" || die

log "${YELLOW}[$(date +'%H:%M:%S')] Starting nightly build${RESET}"
log "${CYAN}Build date: ${DATE}${RESET}"
log "${CYAN}Build timestamp: ${TIMESTAMP}${RESET}"
LAST_APK=$(readlink "${NIGHTLIES_OUT_DIR}/cSploit-lastest.apk")
# find $NIGHTLIES_OUT_DIR -type f -a -mtime +${MAX_DAYS} -a ! -name "${LAST_APK}" -exec rm -f "{}" \; >&3 2>&1
find $LOG_DIR -type f -a -mtime +${MAX_DAYS} -exec rm -f "{}" \; >&3 2>&1

echo -n -e "${CYAN}Syncing git repo...${RESET}\n" | tee >(cat - >&3)
git fetch --all && git reset --hard origin/develop && git submodule update --recursive --init >&3 2>&1 || die

LAST_COMMIT=$(git rev-parse HEAD)

if [ -n "${PREVIOUS_COMMIT}" -a "${PREVIOUS_COMMIT}" == "${LAST_COMMIT}" ]; then
    echo -n -e "${YELLOW}Nothing changed${RESET}" | tee >(cat - >&3)
    echo -n -e "${GREEN}Done" | tee >(cat - >&3)
    exit 0
fi

export NIGHTLY_BUILD_COMMIT=$LAST_COMMIT

echo -n -e "${CYAN}Building cSploit...${RESET}\n" | tee >(cat - >&3)
rm -f $(find . -name "cSploit-release.apk" -type f)
oldpwd=$(pwd)
cd cSploit/jni >&3 2>&1 || die
./build.sh  >&3 2>&1 || jni_die
cd "$oldpwd" >&3 2>&1 || die
./gradlew assembleRelease >&3 2>&1 || die

echo -n -e "${GREEN}Copying signed apk to output directory${RESET}\n" | tee >(cat - >&3)
cp $(find . -name "cSploit-release.apk" -type f) $NIGHTLIES_OUT_DIR/cSploit-$LAST_COMMIT.apk >&3 2>&1 || die
ln -sf "cSploit-${LAST_COMMIT}.apk" $NIGHTLIES_OUT_DIR/cSploit-nightly.apk >&3 2>&1 || die
echo "${LAST_COMMIT}" > "${LOG_DIR}last_commit" 2>&3 || die

echo -n -e "${GREEN}Done.${RESET}\n\n" | tee >(cat - >&3)
