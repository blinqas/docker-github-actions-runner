# Fetches the access token from Azure Instance Metadata Service (IMDS) using either system-assigned or user-assigned managed identity.
function fetch_access_token_from_imds() {
    echo "Fetch access token from IMDS"
    local resource="https://vault.azure.net"
    local token_endpoint="http://169.254.169.254/metadata/identity/oauth2/token"
    local api_version="api-version=2018-02-01"
    
    # Construct the request URL. Include client_id if using user-assigned managed identity.
    local request_url
    if [[ -n "${AZURE_MSI_ID}" ]]; then
        echo "Using user-assigned managed identity ${AZURE_MSI_ID}"
        local encoded_client_id=$(printf '%s' "${AZURE_MSI_ID}" | jq -sRr @uri)  # URL-encode the client_id
        request_url="${token_endpoint}?resource=${resource}&${api_version}&client_id=${encoded_client_id}"
    else
        echo "Using system-assigned managed identity"
        request_url="${token_endpoint}?resource=${resource}&${api_version}"
    fi

    # Fetch the token and check for successful retrieval.
    local response=$(curl -H "Metadata: true" -s -w "%{http_code}" -o temp.json "${request_url}")
    if [ "$response" -ne 200 ]; then
        echo "Failed to fetch access token, HTTP status code: $response."
        cat temp.json  # Output error response for diagnostics.
        exit 1
    fi
    AZURE_ACCESS_TOKEN=$(jq -r '.access_token' temp.json)
    rm temp.json  # Clean up temporary file.
    if [[ -z "$AZURE_ACCESS_TOKEN" ]]; then
        echo "Failed to fetch access token."
        exit 1
    else
      echo "Access token fetched successfully"
    fi
}

# Download the private key from Azure Key Vault using the provided secret name.
function get_private_key_from_azure_keyvault() {
    if [[ -z "$APP_PRIVATE_KEY" ]] && [[ -n "$AZURE_KEYVAULT_NAME" ]] && [[ -n "$AZURE_KEYVAULT_SECRET" ]]; then
        echo "GitHub App Private key not provided as input; attempting to download from Azure Key Vault..."
        local secret=$(curl -s -H "Authorization: Bearer ${AZURE_ACCESS_TOKEN}" "https://${AZURE_KEYVAULT_NAME}.vault.azure.net/secrets/${AZURE_KEYVAULT_SECRET}?api-version=7.1")
        PRIVATE_KEY=$(echo $secret | jq -r .value)
        if [[ -z "$PRIVATE_KEY" ]]; then
            echo "Failed to download private key from Azure Key Vault."
            exit 1
        fi
    fi
}