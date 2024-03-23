# Checks for the existence of required commands.
function check_dependencies() {
    # Always check for openssl, jq, and curl.
    local dependencies=("openssl" "jq" "curl")
    
    # Check for az cli if MSI_ID is provided and not MSI_CLIENT_ID.
    if [[ -n "${MSI_ID}" ]] && [[ -z "${MSI_CLIENT_ID}" ]]; then
        dependencies+=("az")
    fi

    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: $cmd is not installed." >&2
            exit 1
        fi
    done
}

# Encode input to base64 URL safe format.
function b64enc() { 
    openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n';  # Remove padding, replace URL-unsafe chars, remove newlines.
}

# Fetches the access token from Azure Instance Metadata Service (IMDS) using either system-assigned or user-assigned managed identity.
function fetch_access_token_from_imds() {
    echo "Fetch access token from IMDS"
    local resource="https://vault.azure.net"
    local token_endpoint="http://169.254.169.254/metadata/identity/oauth2/token"
    local api_version="api-version=2018-02-01"
    
    # Construct the request URL. Include client_id if using user-assigned managed identity.
    local request_url
    if [[ -n "${MSI_CLIENT_ID}" ]]; then
        echo "Using user-assigned managed identity ${MSI_CLIENT_ID}"
        local encoded_client_id=$(printf '%s' "${MSI_CLIENT_ID}" | jq -sRr @uri)  # URL-encode the client_id
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
    ACCESS_TOKEN=$(jq -r '.access_token' temp.json)
    rm temp.json  # Clean up temporary file.
    if [[ -z "$ACCESS_TOKEN" ]]; then
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
    if [[ -n "${MSI_ID}" ]]; then
        echo "Using user-assigned managed identity ${MSI_ID}"
        az login --identity -u "${MSI_ID}"  # Login with user-assigned managed identity.
    else
        echo "Using system-assigned managed identity"
        az login --identity  # Login with system-assigned managed identity.
    fi
    ACCESS_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
    if [[ -z "$ACCESS_TOKEN" ]]; then
        echo "Failed to fetch access token."
        exit 1
    else
      echo "Access token fetched successfully"
    fi
}

# Generates JWT header and payload for GitHub App authentication.
function jwt_header_payload() {
    echo "Generate JWT header and payload"
    local header_json='{ "typ":"JWT", "alg":"RS256" }'
    header=$( echo -n "${header_json}" | b64enc )
    local now=$(date +%s)
    local iat=$((${now} - 60))
    local exp=$((${now} + 600))
    local payload_json='{ "iat":'"${iat}"', "exp":'"${exp}"', "iss":'"${GH_APP_ID}"' }'
    payload=$( echo -n "${payload_json}" | b64enc )
    header_payload="${header}.${payload}"  # Concatenate header and payload.
}

# Signs the JWT using the private key.
function jwt_signature_private_key() {
    if [[ -z "$GH_APP_PRIVATE_KEY_BASE64" ]]; then
        echo "Private key not provided as input; attempting to download from Azure Key Vault..."
        local secret=$(curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" "https://${AZURE_KEYVAULT_NAME}.vault.azure.net/secrets/${AZURE_KEYVAULT_SECRET}?api-version=7.1")
        PRIVATE_KEY=$(echo $secret | jq -r .value)
        if [[ -z "$PRIVATE_KEY" ]]; then
            echo "Failed to download private key from Azure Key Vault."
            exit 1
        fi
    else
      # Decode GH_APP_PRIVATE_KEY_BASE64
      PRIVATE_KEY=$(echo $GH_APP_PRIVATE_KEY_BASE64 | base64 -d)
    fi
    echo -n "$PRIVATE_KEY" > private.pem
    if [ ! -f private.pem ]; then
        echo "Failed to create PEM file from private key."
        exit 1
    fi
    SIGNATURE=$(echo -n "${header_payload}" | openssl dgst -sha256 -sign private.pem | b64enc)
    rm private.pem  # Ensure the private key file is removed after use
}


# Main function to get the GitHub runner registration token.
function runner_token() {
  if [[ -n "${RUNNER_TOKEN}" ]]; then
    echo "Connect to GitHub using RUNNER_TOKEN environment variable."
  elif [[ -n "${GH_APP_ID}" ]] && [[ -n "${GH_OWNER}" ]]; then
    # Generate the JWT header and payload.
    jwt_header_payload  
  
    # Sign the JWT header and payload with private key
    jwt_signature_private_key

    # Handle failure in JWT signing.
    if [[ -z "$SIGNATURE" ]] || [[ "$SIGNATURE" == "null" ]]; then
        echo "Failed to sign the header and payload."
        exit 1
    else
      echo "Header and payload signed successfully"
      # Construct the JWT by concatenating the encoded header, payload, and signature.
      JWT="${header_payload}.${SIGNATURE}"
    fi

    # Fetch the GitHub App installation ID and subsequently the installation token.
    # This token is used to request a runner registration token for the specified organization or repository.
    # Additional checks ensure the validity of the obtained tokens.

    # Start to get the installation token and agent registration token
    if [[ -n "${JWT}" ]]; then
      echo "JWT generated successfully"
      # Get the installation ID for the organization
      if [[ -z "${GH_APP_INSTALLATION_ID}" ]]; then
        if [[ -z "${GH_REPOSITORY}" ]]; then
          echo "Get installation ID for the organization"
          GH_APP_INSTALLATION_ID=$(curl -s -H "Authorization: Bearer $JWT" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/app/installations" | jq '.[] | select(.account.login=="'$ORG'") | .id')
        # Get the installation ID for the repository
        else
          echo "Get installation ID for the repository"
          GH_APP_INSTALLATION_ID=$(curl -s -H "Authorization: Bearer $JWT" -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/${GH_OWNER}/${GH_REPOSITORY}/installation" | jq -r .id)
        fi
        echo "GH_APP_INSTALLATION_ID: ${GH_APP_INSTALLATION_ID}"
      else
        echo "Using provided installation ID: ${GH_APP_INSTALLATION_ID}"
      fi
      
      # Check for valid installation ID
      if [[ -z "$GH_APP_INSTALLATION_ID" ]] || [[ "$GH_APP_INSTALLATION_ID" == "null" ]]; then
          echo "Failed to get installation ID."
          exit 1
      else
        # Get installation access token
        echo "Get installation access token"
        INSTALLATION_TOKEN=$(curl -sX POST -H "Authorization: Bearer $JWT" -H "Accept: application/vnd.github.v3+json" \
          "https://api.github.com/app/installations/${GH_APP_INSTALLATION_ID}/access_tokens" | jq -r .token)

        # Check for valid installation token
        if [[ -z "$INSTALLATION_TOKEN" ]] || [[ "$INSTALLATION_TOKEN" == "null" ]]; then
            echo "Failed to get installation token."
            exit 1
        else
          echo "Got installation token"
          # Get agent registration token for the org / repository
          if [[ -z "${GH_REPOSITORY}" ]]; then
            # Org level runner
            echo "Get agent registration token for the organization"
            RUNNER_TOKEN=$(curl -s POST -H "Authorization: token ${INSTALLATION_TOKEN}" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/orgs/${ORG}/actions/runners/registration-token" | jq -r .token)
          else
            # Repo level runner
            echo "Get agent registration token for the repository"
            RUNNER_TOKEN=$(curl -sX POST -H "Authorization: token ${INSTALLATION_TOKEN}" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${GH_OWNER}/${GH_REPOSITORY}/actions/runners/registration-token" | jq -r .token)
          fi
          # Check for valid agent token
          if [[ -z "$RUNNER_TOKEN" ]] || [[ "$RUNNER_TOKEN" == "null" ]]; then
              echo "Failed to get agent registration token."
              exit 1
          else
            echo "Got agent registration token"
            export RUNNER_TOKEN=$RUNNER_TOKEN
          fi          
        fi
      fi
    fi
  else
    echo "Required environment variables are missing. Please provide one of the following sets:"
    echo " - GH_OWNER, GH_APP_ID, AZURE_KEYVAULT_NAME, and AZURE_KEYVAULT_SECRET (Recommended)"
    echo " - GH_OWNER, GH_APP_ID, and GH_APP_PRIVATE_KEY_BASE64 (Not recommended)"
    echo " - MSI_ID or MSI_CLIENT_ID if you use user assigned managed identity"
    exit 1
  fi
}