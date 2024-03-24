# --------------  blinQ Custom Entry Point Start -------------------------
# Add support for Azure Key Vault Secret ref for GitHub App Private Key
# Source the helper functions
if [[ -z "$APP_PRIVATE_KEY"]];then
  source ./blinQ-functions.sh
  fetch_azure_access_token
  get_private_key_from_azure_keyvault
  if [[ -n "$PRIVATE_KEY" ]];then
    APP_PRIVATE_KEY=$PRIVATE_KEY
  else
    echo "Failed to get APP_PRIVATE_KEY from Azure Key Vault"
    exit 1
  fi  
fi
# --------------  blinQ Custom Entry Point End --------------------------
