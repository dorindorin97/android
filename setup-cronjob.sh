#!/bin/bash

# Copyleft (C) 2014 The cSploit Project
#
# Licensed under the GNU GENERAL PUBLIC LICENSE version 3 'or later'
# The GNU General Public License is a free, copyleft license for software and other kinds of works.
# see the LICENSE file distributed with this work for a full version of the License.

set -euo pipefail

CYAN="\\033[1;36m"
GREEN="\\033[1;32m"
RED="\\033[1;31m"
RESET="\\033[0m"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRONJOB_FILE="${DIR}/cronjob.txt"
NIGHTLY_SCRIPT="${DIR}/nightly-build.sh"

# Verify nightly-build.sh exists and is executable
if [[ ! -f "${NIGHTLY_SCRIPT}" ]]; then
    echo -e "${RED}Error: nightly-build.sh not found at ${NIGHTLY_SCRIPT}${RESET}"
    exit 1
fi

if [[ ! -x "${NIGHTLY_SCRIPT}" ]]; then
    echo -e "${CYAN}Making nightly-build.sh executable...${RESET}"
    chmod +x "${NIGHTLY_SCRIPT}"
fi

# Clean old cronjob file if it exists
if [[ -f "${CRONJOB_FILE}" ]]; then
    rm -f "${CRONJOB_FILE}"
fi

# Generate cronjob entry (runs daily at midnight)
echo -e "${CYAN}Generating cronjob configuration...${RESET}"
cat > "${CRONJOB_FILE}" << EOF
# Nightly cSploit build job (generated: $(date))
0 0 * * * /bin/bash ${NIGHTLY_SCRIPT} > /dev/null 2>&1

EOF

# Check if crontab exists and user has permissions
if ! command -v crontab &> /dev/null; then
    echo -e "${RED}Error: crontab not found. Please install cron service.${RESET}"
    echo -e "${CYAN}You can manually add the following line to your crontab:${RESET}"
    cat "${CRONJOB_FILE}"
    exit 1
fi

# Add to crontab with proper error handling
echo -e "${CYAN}Adding job to crontab...${RESET}"
if crontab "${CRONJOB_FILE}"; then
    echo -e "${GREEN}✓ Cronjob successfully installed${RESET}"
    echo -e "${CYAN}Nightly builds will run daily at 00:00 UTC${RESET}"
else
    echo -e "${RED}Error: Failed to add cronjob${RESET}"
    echo -e "${CYAN}Manual setup: crontab ${CRONJOB_FILE}${RESET}"
    exit 1
fi

# Clean up
rm -f "${CRONJOB_FILE}"

echo -e "${GREEN}Setup complete!${RESET}"
