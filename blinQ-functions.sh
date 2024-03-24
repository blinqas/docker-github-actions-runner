# Checks for the existence of required commands.
function check_dependencies() {
    # Always check for openssl, jq, and curl.
    local dependencies=("openssl" "jq" "curl")
    
    # Check for az cli if AZURE_MSI_ID is provided and not AZURE_MSI_ID.
    if [[ -n "${AZURE_MSI_ID}" ]] && [[ -z "${AZURE_MSI_ID}" ]]; then
        dependencies+=("az")
    fi

    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: $cmd is not installed." >&2
            exit 1
        fi
    done
}

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

# Fetches the access token using Azure CLI, supports both system-assigned and user-assigned managed identity.
function fetch_access_token_from_az_cli() {
    # Use Azure CLI to obtain an access token for the Key Vault.
    echo "Fetch access token from Azure CLI"
    if [[ -n "${AZURE_MSI_ID}" ]]; then
        echo "Using user-assigned managed identity ${AZURE_MSI_ID}"
        az login --identity -u "${AZURE_MSI_ID}"  # Login with user-assigned managed identity.
    else
        echo "Using system-assigned managed identity"
        az login --identity  # Login with system-assigned managed identity.
    fi
    AZURE_ACCESS_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
    if [[ -z "$AZURE_ACCESS_TOKEN" ]]; then
        echo "Failed to fetch access token."
        exit 1
    else
      echo "Access token fetched successfully"
    fi
}

# Fetch Azure Access Token, prefer imds before az cli
function fetch_azure_access_token() {
  if [[ -n "$AZURE_MSI_ID"]];then
  # Authenticate with userassigned managed identity
    # Check if AZURE_MSI_ID contains a client_id, ex: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx or a managed identity resource id, ex: /subscriptions/xxxxxxx/resourceGroups/xxxxxxx/providers/Microsoft.ManagedIdentity/userAssignedIdentities/xxxxxxx
    resource_id = $(echo $AZURE_MSI_ID | grep Microsoft.ManagedIdentity)
    if [[ -n "$resource_id" ]]; then
      # If AZURE_MSI_ID contains resource_id we use imds to fetch azure access token
      fetch_access_token_from_imds
    else
      # If AZURE_MSI_ID not contains resource_id we assume it's a client_id, we use az cli to fetch access token
      fetch_access_token_from_az_cli
    fi
  else
  # Authenticate with systemassigned managed identity using imds
    fetch_access_token_from_imds
  fi  
}

# Signs the JWT using the private key.
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