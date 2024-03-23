# --------------  blinQ Custom Entry Point Start -------------------------
# Add support for Azure Key Vault Secret ref for GitHub App Private Key
# Source the helper functions
source ./blinQ-functions.sh
# Check for required dependencies and execute the main function
check_dependencies
runner_token
# --------------  blinQ Custom Entry Point End --------------------------
