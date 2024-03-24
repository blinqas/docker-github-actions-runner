# --------------  blinQ Custom Entry Point Start -------------------------
# Add support for Azure Key Vault Secret ref for GitHub App Private Key
# Source the helper functions
if [[ -n "$AZURE_KEYVAULT_NAME" ]] && [[ -n "$AZURE_KEYVAULT_SECRET" ]] && [[ -n "$APP_ID" ]] && [[ -z "$APP_PRIVATE_KEY" ]];then  
  source /blinQ-functions.sh
  if [[ -z "$AZURE_ACCESS_TOKEN" ]];then
    fetch_access_token_from_imds
  fi
  get_private_key_from_azure_keyvault
  if [[ -n "$PRIVATE_KEY" ]];then
    PRIVATE_KEY_MULTILINE=$(echo -e "${PRIVATE_KEY}")
    APP_PRIVATE_KEY=$PRIVATE_KEY_MULTILINE
  else
    unset APP_PRIVATE_KEY
  fi  
fi
# --------------  blinQ Custom Entry Point End --------------------------
