# Fetches the access token from Azure Instance Metadata Service (IMDS) using either system-assigned or user-assigned managed identity.
function fetch_access_token_from_imds() {
    if [[ -z "$AZURE_MSI_ID" ]]; then
      local client_id="$AZURE_MSI_ID"
      AZURE_ACCESS_TOKEN=$(curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&client_id=$client_id" -H Metadata:true -s | jq -r '.access_token')
    else
      AZURE_ACCESS_TOKEN=$(curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net" -H Metadata:true -s | jq -r '.access_token')
    fi
}

# Download the private key from Azure Key Vault using the provided secret name.
function get_private_key_from_azure_keyvault() {
    if [[ -z "$APP_PRIVATE_KEY" ]] && [[ -n "$AZURE_KEYVAULT_NAME" ]] && [[ -n "$AZURE_KEYVAULT_SECRET" ]]; then
        echo "GitHub App Private key not provided as input; attempting to download from Azure Key Vault..."                       
        local secret=$(curl  https://${AZURE_KEYVAULT_NAME}.vault.azure.net/secrets/${AZURE_KEYVAULT_SECRET}/?api-version=7.4 -H "Authorization: Bearer $AZURE_ACCESS_TOKEN")
        PRIVATE_KEY=$(echo $secret | jq -r .value)
        if [[ -z "$PRIVATE_KEY" ]]; then
            echo "Failed to download private key from Azure Key Vault."
            exit 1
        fi
    fi
}