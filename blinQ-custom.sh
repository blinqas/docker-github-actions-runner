# --------------  blinQ Custom Entry Point Start -------------------------
# Add support for Azure Key Vault Secret ref for GitHub App Private Key
# Source the helper functions
if [[ -n "$AZURE_KEYVAULT_NAME" ]] && [[ -n "$AZURE_KEYVAULT_SECRET" ]] && [[ -n "$APP_ID" ]] && [[ -z "$APP_PRIVATE_KEY" ]];then
  source ./blinQ-functions.sh
  fetch_azure_access_token
  get_private_key_from_azure_keyvault
  if [[ -n "$PRIVATE_KEY" ]];then
    APP_PRIVATE_KEY=$PRIVATE_KEY
  else
    unset APP_PRIVATE_KEY
  fi  
fi
# --------------  blinQ Custom Entry Point End --------------------------
