#!/bin/zsh --no-rcs

# Created by Luis Mesquita based on:
# Script created by Bart Reardon, June 11, 2025
# Augmented by Anthony Darlow (CantScript), June 13, 2025
# Script provided AS IS and without warranty of any kind


#################################################################################
# Get the directory where the script is located
scriptDir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Defines the path for the log file. It will be stored in the same folder as the script, so it does not prompt for admin Credentials
scriptLog="/Library/Logs/com.w4all.triplea.log" 
# Defines the path to the Client Assertion file relative to the script's directory
assertLocation="$scriptDir/../Resources/Tokens/client_assertion_format.txt"
# Defines the path to the Access Token file relative to the script's directory
aTokenLocation="$scriptDir/../Resources/Tokens/access_token_format.txt"
# Capturing the Logged in User
loggedInUser=$( stat -f%Su /dev/console)
# Finding the Full Name of the logged in User
fullName=$(dscl . -read /Users/"$loggedInUser" RealName | awk 'FNR==2')
# Finding the HomeFolder of the logged in User
homeFolder=$(dscl . -read /Users/"$loggedInUser" NFSHomeDirectory | awk '{print $2}')
# Defines the path to the Config file
configLocation="$homeFolder/Library/Preferences/com.w4all.triplea.plist"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# APPLE API FUNCTIONS
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

# Creating the JWT Assertion for Apple School and Business Manager API
# This script generates a JWT assertion that can be used to authenticate with the Apple School and Business Manager API.

# zsh version of Implementing OAuth for the Apple School and Business Manager API
#   https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api
#
# Created by Luis Mesquita based on:
# Script created by Bart Reardon, June 11, 2025
# Augmented by Anthony Darlow (CantScript), June 13, 2025
# Script provided AS IS and without warranty of any kind

# Requirements:
#   Private key downloaded from Apple Business Manager or Apple School Manager and placed in the AxmCert folder
#   Client ID - Found in the "Manage" info pane for the API key in ABM/ASM. Also needed in the create_access_token.sh script
#   Key ID    - Found in the "Manage" info pane for the API key in ABM/ASM

# The JWT generated is valid for 180 days and does not need to be re-generated every time you want to use it
# Create the JWT once, then use that when requesting a bearer token from the ABM/ASM API.
# re-create once it has expired.

#################################################################################
# FUNCTION TO CREATE THE API ASSERTION
#################################################################################
function create_client_assertion() {

  team_id="$client_id" # Team ID is the same as Client ID for ABM/ASM
  audience="https://account.apple.com/auth/oauth2/v2/token"
  alg="ES256"

  iat=$(date -u +%s)
  exp=$((iat + 86400 * 180))
  jti=$(uuidgen)


  ###Discover Locations

  # Define the path to the file relative to the script's directory
  pKeyLocation="${private_key_path}"

  # Check to see if we have all our stuff
  if [[ ! -e "$pKeyLocation" ]]; then
    echo "- Private key $private_key_file can't be found\n"
    exit 1
  fi
  if [[ -z $client_id ]] || [[ -z $key_id ]]; then
    echo "- Client ID or Key ID are missing\n"
    echo "- Client ID: ${client_id}\n"
    echo "- Key ID: ${key_id}\n"
    exit 1
  fi


  # base64url encode
  b64url() {
  # Encode base64 to url safe format
    echo -n "$1" | openssl base64 -e -A | tr '+/' '-_' | tr -d '='
  }

  pad64() {
  # Pad ECDSA signature on the left with 0s until it is exactly 64 characters long (i.e., 32 bytes = 64 hex digits)
    local hex=$1
    printf "%064s" "$hex" | tr ' ' 0
  }

  # JWT sections
  header=$(jq -nc --arg alg "$alg" --arg kid "$key_id" '{alg: $alg, kid: $kid, typ: "JWT"}')
  payload=$(jq -nc \
    --arg sub "$client_id" \
    --arg aud "$audience" \
    --argjson iat "$iat" \
    --argjson exp "$exp" \
    --arg jti "$jti" \
    --arg iss "$team_id" \
    '{sub: $sub, aud: $aud, iat: $iat, exp: $exp, jti: $jti, iss: $iss}')

  header_b64=$(b64url "$header")
  payload_b64=$(b64url "$payload")
  signing_input="${header_b64}.${payload_b64}"

  # Create temporary file
  sigfile=$(mktemp /tmp/sig.der.XXXXXX)

  # Sign using EC private key, output raw DER binary to file
  echo -n "$signing_input" | openssl dgst -sha256 -sign ${pKeyLocation} > "$sigfile"

  # Extract R and S integers using ASN1 parse
  r_hex=""
  s_hex=""
  i=0

  while read -r line; do
    hex=$(echo "$line" | awk -F: '/INTEGER/ {print $NF}')
    if [[ -n "$hex" ]]; then
      if [[ $i -eq 0 ]]; then
        r_hex="$hex"
      elif [[ $i -eq 1 ]]; then
        s_hex="$hex"
      fi
      ((i++))
    fi
  done < <(openssl asn1parse -in "$sigfile" -inform DER 2>/dev/null)

  # Clean up the sig file as we no longer need it
  rm $sigfile

  # create R and S values
  r=$(pad64 "$r_hex")
  s=$(pad64 "$s_hex")

  # Convert signature to base64  
  rs_b64url=$(echo "$r$s" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')

  # form the completed JWT
  jwt="${signing_input}.${rs_b64url}"

  # Write to file using tee and heredoc
  tee $scriptDir/../Resources/Tokens/client_assertion_format.txt > /dev/null <<EOF
Token: $jwt
Expire: $(date -r $exp)
EOF
}

#################################################################################
# FUNCTION TO CHECK THE ASSERTION VALIDITY
#################################################################################
# Creating the Access Token for Apple School and Business Manager API
# This script generates a Token that can be used to authenticate with the Apple School and Business Manager API.
# Created by Luis Mesquita, based on Anthony Darlow's (CantScript)
# Script provided AS IS and without warranty of any kind
# This function checks the validity of the client assertion token
# If the token is valid, it returns 0
# If the token is invalid, it generates a new token and returns 1
# It also checks the expiry date of the token and generates a new token if it has expired
# It uses the create_client_assertion.sh script to generate a new assertion
function checkAssertionValidity() {
	local file="${assertLocation}"
	
	if [[ -f "$file" ]]; then
		client_assert=$(awk -F': ' '/^Token:/ {print $2}' "$file")
	else
		echo "- Error: $file not found!\n"
    echo "- Generating new Assertion Token....\n"
    create_client_assertion
		return 1
	fi
	
	# Extract the human-readable expire date string
	expire_str=$(awk -F': ' '/^Expire:/ {print $2}' "$file")
	
	# Convert expire_str to a Unix timestamp (macOS format)
	expire_ts=$(date -jf "%a %b %d %T %Z %Y" "$expire_str" +%s)
	
	# Get the current time as a Unix timestamp
	now_ts=$(date +%s)
	
	# Compare
	if [[ "$now_ts" -lt "$expire_ts" ]]; then
		echo "- Assertion Token is still valid.\n"
		return 0
	else
		echo "- Assertion Token has expired.\n"
		echo "- Generating new Assertion Token....\n"
		create_client_assertion
		return $?
	fi
}

#################################################################################
# FUNCTION TO CREATE THE ACCESS TOKEN
#################################################################################
# This function creates the Access Token using the client assertion
# It sends a POST request to the Apple Account service with the client assertion and scope
# It saves the Access Token and its expiry date to the access_token_format.txt file
# It also checks if the access_token_format.txt file exists and creates it if it doesn't
# If the access token is successfully created, it returns 0
# If there is an error, it returns 1
# It uses the jq command to parse the JSON response from the Apple Account service
# It also uses the curl command to send the POST request
# The access token is valid for 1 hour and is saved in the access_token_format.txt file
function createAccessToken() {
	request_json=$(curl -s -X POST -H 'Host: account.apple.com' -H 'Content-Type: application/x-www-form-urlencoded' "https://account.apple.com/auth/oauth2/token?grant_type=client_credentials&client_id=${client_id}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=${client_assert}&scope=${scope}")
	accessToken=$(echo $request_json | jq -r '.access_token')
	
	iat=$(date -u +%s)
	exp=$((iat + 3600)) ## Access token is valid for 1 hour
	
	tee "${aTokenLocation}" > /dev/null <<EOF
AccessToken: $accessToken
Expire: $(date -r $exp)
EOF
	
	echo "- Access Token Created\n"
	
}

#################################################################################
# FUNCTION TO CHECK THE VALIDITY OF THE ACCESS TOKEN
#################################################################################
# This function checks the validity of the Access Token
# It checks if the access_token_format.txt file exists and reads the Access Token from it
# If the file does not exist, it calls the checkAssertionValidity function to create a new client assertion
# It then calls the createAccessToken function to create a new Access Token
# It checks the expiry date of the Access Token and compares it with the current time
# If the Access Token is still valid, it returns 0
# If the Access Token has expired, it calls the checkAssertionValidity function to create a new client assertion
# It then calls the createAccessToken function to create a new Access Token
# It checks the expiry date of the new Access Token and compares it with the current time
# If the new Access Token is valid, it returns 0
# If there is an error, it returns 1
# It uses the awk command to parse the Access Token and expiry date from the access_token_format.txt file
# It also uses the date command to convert the expiry date to a Unix timestamp
# It uses the echo command to print messages to the console
# It also uses the sleep command to wait for a few seconds before checking the Access Token again
function checkTokenValidity() {
  if [[ -f "${aTokenLocation}" ]]; then
	  accessToken=$(awk -F': ' '/^AccessToken:/ {print $2}' "${aTokenLocation}")
    while [[ $accessToken == "null" ]]; do
      echo "- The Access Token has a value of null. Recreating the file\n"
      rm -f "${aTokenLocation}"
      checkAssertionValidity
      sleep 2
	    createAccessToken 
	    sleep 2
	    if [[ -f "${aTokenLocation}" ]]; then
		    accessToken=$(awk -F': ' '/^AccessToken:/ {print $2}' "${aTokenLocation}")
	    else
		  echo "- Something went wrong when creating the Access Token\n"
		  exit 1
	    fi
    done
  else
	  echo "- Error: access_token_format.txt not found!\n"
	  echo "- Creating Access Token\n"
	  checkAssertionValidity
    sleep 2
	  createAccessToken 
	  sleep 2
	  if [[ -f "${aTokenLocation}" ]]; then
		  accessToken=$(awk -F': ' '/^AccessToken:/ {print $2}' "${aTokenLocation}")
	  else
		  echo "- Something went wrong when creating the Access Token\n"
		  exit 1
	  fi
  fi

  #Get expiry from current Access Token
  # Extract the human-readable expire date string
  expire_str=$(awk -F': ' '/^Expire:/ {print $2}' "${aTokenLocation}")

  # Convert expire_str to a Unix timestamp
  expire_ts=$(date -jf "%a %b %d %T %Z %Y" "$expire_str" +%s)

  # Get the current time as a Unix timestamp
  now_ts=$(date +%s)


  # Compare
  if [[ "$now_ts" -lt "$expire_ts" && $accessToken != "null" ]]; then
	  echo "- Access Token is valid.\n"
  else
	  echo "- Access Token has expired.\n"
	  echo "- Generating new Access Token...\n"
	  checkAssertionValidity
	  createAccessToken 
	  sleep 5
	  expire_str=$(awk -F': ' '/^Expire:/ {print $2}' "${aTokenLocation}")
	  expire_ts=$(date -jf "%a %b %d %T %Z %Y" "$expire_str" +%s)
	  echo "- New Access Token Expires: ${expire_str}\n"
	  if [[ "$now_ts" -lt "$expire_ts" ]]; then
		  echo "- Access Token is now valid.\n"
		  echo "- Continuing with API Call(s)\n"
	  else
		  echo "- Something went wrong with date validation for the Access Token\n "
		  exit 1
	  fi
  fi

}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# SWIFT DIALOG FUNCTIONS
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# swiftDialog Variables
swiftDialogMinimumRequiredVersion="2.3.2.4726"					
dialogBinary="/usr/local/bin/dialog"

# Validate/install swiftDialog (Thanks big bunches, @acodega!)
#################################################################################
# FUNCTION TO INSTALL SWIFT DIALOG
#################################################################################
function dialogInstall() {

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    # Create a temporary working directory
    workDirectory=$( basename "$0" )
    tempDirectory=$( mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package
    curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

    # Verify the download
    teamID=$(spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then
        /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
    
    else
        # Display a so-called "simple" dialog if Team ID fails to validate
        osascript -e 'display dialog "Swift Dialog cannot be installed as the Dialog Team ID verification has failed\r\r" with title "'"${scriptFunctionalName}"': Error" buttons {"Close"} with icon caution'
        exitCode="1"
        quitScript
    fi

    # Remove the temporary working directory when done
    rm -Rf "$tempDirectory"

}

#################################################################################
# FUNCTION TO CHECK FOR SWIFT DIALOG
#################################################################################
function dialogCheck() {

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then
        echo "- swiftDialog not found. Installing...\n"
        dialogInstall
    else
        dialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${dialogVersion}" < "${swiftDialogMinimumRequiredVersion}" ]]; then
            echo "- swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating...\n"
            dialogInstall
        else
            echo "- swiftDialog version ${dialogVersion} found; proceeding...\n"
        fi
    fi

}

#################################################################################
# FUNCTION TO PRESENT THE FIRST TIME USE DIALOG
#################################################################################
# This dialog will be presented the first time the script is run
# It will ask the user to create an Apple Business Manager or Apple School Manager API Key and download the private key file
# It will also ask the user to place the private key file in the AxmCert folder in the same directory as this script
# It will also ask the user to set the Client ID and Key ID in the script
# The Client ID and Key ID can be found in the "Manage" info pane for the API key in ABM/ASM

function firstTimeUse() {
  
  greeting=$((){print Good ${argv[2+($1>11)+($1>18)]}} ${(%):-%D{%H}} morning afternoon evening)

    # Create the deferrals available dialog options and content
    dialogContent=(
		--message "$greeting$fullName! 
    Before this utility can be used, there are some requirements to fulfil.
 - You need to create an Apple Business Manager or Apple School Manager API Key and download the private key file.
 - The private key file needs to be placed in the AxmCert folder in the same directory as this script.
 - The Client ID and Key ID need to be set in the script.
 - The Client ID and Key ID can be found in the "Manage" info pane for the API key in ABM/ASM.


  To know more about the details of the process, click the ***'More Info'*** button below.
    "
		--messagealign center
		--titlealign left
		--title "First Time Use"
    --icon sf=rainbow,colour=auto,animation=variable,weight=medium
    --iconsize 180
    --button1text "OK"
		--button2text "Cancel"
    --checkbox "Do not show this dialog again"
    --infobuttontext "More Info"
    --infobuttonaction "https://bartreardon.github.io/2025/06/11/using-the-new-api-for-apple-business-school-manager.html?utm_campaign=MacAdmins.news&utm_medium=email&utm_source=MacAdmins.news_365"
	
    )

    dialogOptions=(
        --position center
        --moveable
        --ontop
        --medium
        --ignorednd
        --quitoninfo
        --quitkey k
        --titlefont size=28
        --messagefont size=14
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"

    case $? in
     0)
      return 0
 
     ;;
     2)
      return 1
     ;;
	  esac
   
}

#################################################################################
# FUNCTION TO ADD THE DETAILS FOR THE API CALL
#################################################################################
# This is the function that will present the dialog to add the details
# It will be called if the storeDetailsValue is not set or is not equal to true
# It will also be called if the firstTimeUse dialog is presented
# It will present the dialog to add the details and return the values entered by the user
# The dialog will have the following fields:
# - Service: Select the service to use (Apple Business Manager or Apple School Manager)
# - Private Key File: Select the private key file to use
# - Client ID: Enter the Client ID
# - Key ID: Enter the Key ID

function addDetails() {

   
    # Create the deferrals available dialog options and content
    dialogContent=(
		--message "Now that you have all the details, you can pass them in the form below.\n
 By default, this dialog will be presented every time you run the script. If you don't want that, check the box ***'Save the details'***.\n
 By doing that, this dialog will not be presented again, until you manually change the value in the config file.\n
    "
		--messagealign center
		--titlealign left
		--title "Authentication Details"
    --icon sf=gear.badge.questionmark,colour=auto,animation=variable,weight=medium
    --iconsize 180
    --button1text "OK"
		--button2text "Cancel"
    --selecttitle "Service",required
    --selectvalues "Apple Business Manager,Apple School Manager"
    --selectdefault "Apple Business Manager"
    --textfield "Select the Private Key File,fileselect", required
    --textfield "Client ID",required,secure
    --textfield "Key ID",required,secure
    --checkbox "Save the details"
    --infobuttontext "More Info"
    --infobuttonaction "https://bartreardon.github.io/2025/06/11/using-the-new-api-for-apple-business-school-manager.html?utm_campaign=MacAdmins.news&utm_medium=email&utm_source=MacAdmins.news_365"
	
    )

    dialogOptions=(
        --position bottom
        --quitoninfo
        --moveable
        --big
        --ontop
        --ignorednd
        --quitkey k
        --titlefont size=28
        --messagefont size=14
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"

    case $? in
      0)
       return 0
      ;;
      2)
       return 1
      ;;
	  esac
   
}

#################################################################################
# FUNCTION TO PROMPT THE USER TO SELECT AN API ENDPOINT
#################################################################################
# Parameters:
#   - $1: The current hour (0-23)
#   - $2: The logged-in user
# Returns:
#   - 0 if the user clicked OK
#   - 1 if the user clicked Cancel or closed the dialog
# Displays a dialog with options to perform various actions related to the API
# Uses swiftDialog to create the dialog and handle user input
# The dialog will display a greeting based on the current time and the logged-in user
# The dialog will have options to list organization devices, list MDM servers, list devices for MDM server, read device information, create unassigned devices CSV, create assigned devices CSV, assign
function promptUser() {
  
  greeting=$((){print Good ${argv[2+($1>11)+($1>18)]}} ${(%):-%D{%H}} morning afternoon evening)

    # Create the deferrals available dialog options and content
    dialogContent=(
		--message "$greeting$fullName!\n
 Choose one option from the list below to perform the desired action.\n
 You can also reset the credentials if you want. In that case the selected action will be ignored.\n
 If you reset the Credentials, the Dialog will ask you to enter the details again.\n"
		--messagefont size=14
		--titlefont size=28
		--messagealign center
		--titlealign left
		--title "$mainTitle"
        --selecttitle "Actions to perform",radio 
		--selectvalues "List Organization Devices, List MDM Servers, List Devices for MDM Server, Read Device Information, Create Unassigned Devices CSV, Create Assigned Devices CSV, Assign Devices, Unassign Devices"
        --icon sf=rainbow,colour=auto,animation=variable,weight=medium
        --iconsize 180
        --button1text "OK"
		--button2text "Cancel"
    --infobuttontext "Reset Credentials"
	
    )

    dialogOptions=(
        --position center
        --moveable
        --big
        --ontop
        --ignorednd
        --quitkey k
        --titlefont size=28
        --messagefont size=14

    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
    
  case $? in
      0)
       return 0
      ;;
      2)
       return 1
      ;;
      3)
       return 2
      ;;
	esac
}

#################################################################################
# FUNCTION TO PRESENT THE RESULTS OF THE API CALL
#################################################################################
# Parameters:
#   - title: The title of the dialog
#   - message: The message to display in the dialog
#   - fileName: The name of the file containing the results
function apiResults() {
	local title="$1"
	local message="$2"
	local fileName="$3"
	
    # Create the deferrals available dialog options and content
    dialogContent=(
		--message "$message"
		--messagealign left
		--titlealign center
		--title "$title"
        --icon sf=checkmark.circle,colour=green,animation=pulse.bylayer,weight=medium
        --iconsize 300
		--infotext "$fileName"
        --button1text "OK"

    )

    dialogOptions=(
        --position center
        --moveable
        --medium
        --ignorednd
        --quitkey k
        --titlefont size=28
        --messagefont size=14
    
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
  
}

#################################################################################
# FUNCTION TO ASK THE USER IF THEY WANT TO PERFORM ANOTHER ACTION
#################################################################################
# Returns:
#   - 0 if the user wants to perform another action
#   - 1 if the user does not want to perform another action
# Displays a dialog with options to perform another operation or exit
function newAction() {
    local message="$1"
    local button1="$2"
    local button2="$3"
    # Create the deferrals available dialog options and content
    dialogContent=(
		--message "$message"
		--messagefont size=12
		--messagealign center
		--title "none"
		--width 350
		--height 300
		--alignment "center"
    --centericon true
    --icon sf=questionmark.circle.fill,colour=blue,animation=pulse.bylayer,weight=medium
    --iconsize 100
		--buttonstyle stack
    --button1text "$button1"
		--button2text "$button2"
    )

    dialogOptions=(
        --position center
        --moveable
        --ontop
        --small
        --ignorednd
        --quitkey k
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
  
}

#################################################################################
# FUNCTION TO PRESENT THE MDM SERVER SELECTION DIALOG
#################################################################################
# This function will present a dialog with the MDM servers available
# It will be called when the user selects the "List Devices for MDM Server" or when the action is to "Assign Devices to a Server" option in the main dialog
# It will present a dialog with the MDM servers available and allow the user to select one
function mdmSelection() {
  selectitems=$(IFS=','; echo "${mdmNames[*]}" | tr -d '"')

    # Create the deferrals available dialog options and content
    dialogContent=(
    --message ""
		--messagealign center
		--titlealign left
		--title "MDM Server Selection"
    --icon sf=filemenu.and.selection,colour=orange,animation=pulse.bylayer,weight=medium
    --iconsize 180
    --button1text "OK"
		--button2text "Cancel"
    --selecttitle "MDM Servers",radio, required
    --selectvalues "$selectitems"
    
    )

    dialogOptions=(
        --position center
        --moveable
        --medium
        --ignorednd
        --quitkey k
        --titlefont size=28
        --messagefont size=14
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
   
}

#################################################################################
# FUNCTION TO GET THE SERIAL NUMBER OF A DEVICE
#################################################################################
# It will be called when the user selects the "Read Device Information" option in the main dialog
# It will present a dialog with a text field to enter the serial number of the device
# It will validate the serial number to be a 10 or 12 character alphanumeric value
# If the serial number is valid, it will return 0
# If the serial number is not valid, it will return 1
function getSerialNumber() {
    action="$1"
    dialogContent=(
		--message "Type the Serial Number of the device you want to $action."
		--messagealign center
		--titlealign left
		--title "Device Serial Number"
    --icon sf=barcode,colour=orange,animation=variable,weight=medium
    --iconsize 120
    --button1text "OK"
		--button2text "Cancel"
    --textfield "Serial Number",prompt="Enter the 10 or 12 character product code",regex="^[A-Z0-9]{10}$|^[A-Z0-9]{12}$",regexerror="Code must be a 10 or 12 character value",required
  
    )

    dialogOptions=(
        --position center
        --moveable
        --small
        --ontop
        --ignorednd
        --quitkey k
        --titlefont size=28
        --messagefont size=14
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
   
}

#################################################################################
# FUNCTION TO ASK THE USER IF IT REALLY WANTS TO PROCEED
#################################################################################
# This function will present a dialog with a message asking the user if they really want to proceed with the action
# It will present a dialog with a message and two buttons: 
# - "Yes, proceed" to confirm the action
# - "No, cancel" to cancel the action
# It will return 0 if the user clicks "Yes, proceed" and 1 if the user clicks "No, cancel"
# The message will be passed as a parameter to the function
# The buttons will be passed as parameters to the function
# The function will also set the icon to an exclamation mark triangle fill icon with a red color and a pulse animation
# The icon will be set to a size of 100 pixels
function warningUsers() {
    local message="$1"
    local button1="$2"
    local button2="$3"
    # Create the deferrals available dialog options and content
    dialogContent=(
		--message "$message"
		--messagefont size=12
		--messagealign center
		--title "none"
		--width 350
		--height 300
		--alignment "center"
    --centericon true
    --icon sf=exclamationmark.triangle.fill,colour=red,animation=pulse.bylayer,weight=bold
    --iconsize 100
		--buttonstyle stack
    --button1text "$button1"
		--button2text "$button2"
    )

    dialogOptions=(
        --position center
        --moveable
        --ontop
        --small
        --ignorednd
        --quitkey k
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
    case $? in
      0)
       return 0
      ;;
      2)
       return 1
      ;;
	esac
}

#################################################################################
# FUNCTION TO SELECT THE CSV FILE PATH TO UPLOAD
#################################################################################
function getSerialNumbersToAction() {
  
    dialogContent=(
		--message "Upload the Serial Numbers of the devices you want to $action."
		--messagealign center
		--titlealign left
		--title "Device Serial Numbers"
    --icon sf=barcode,colour=orange,animation=variable,weight=medium
    --iconsize 120
    --button1text "OK"
		--button2text "Cancel"
    --textfield "Select a csv file,fileselect",required
    )

    dialogOptions=(
        --position center
        --moveable
        --small
        --ignorednd
        --quitkey k
        --titlefont size=28
        --messagefont size=14
    )
    
    "$dialogBinary" "${dialogContent[@]}" "${dialogOptions[@]}"
   
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# ENDPOINT FUNCTIONS
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

#################################################################################
# FUNCTION TO LIST ALL DEVICES IN THE ORGANIZATION
#################################################################################
# It retrieves the device information from the API and displays it in a dialog
# It counts the number of assigned and unassigned devices and creates a CSV file with the following format:
# SerialNumber,Status,Model
# It shows a message with the number of assigned and unassigned devices
function listOrganizationDevices() {
	response=$(curl -s "${url}/orgDevices" -H "Authorization: Bearer ${accessToken}")
	assignedCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "ASSIGNED")] | length ')
	unassignedCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "UNASSIGNED")] | length ')
	
	title="The instance has $assignedCount assigned devices and $unassignedCount unassigned devices."

  if [[ $assignedCount -eq 0 && $unassignedCount -eq 0 ]]; then
    message="There are no devices in the organization."
  else
  message="ASSIGNED DEVICES:\n
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "ASSIGNED")] | .[] | " - SerialNumber: \(.id)\n- Model: \(.attributes.deviceModel)\n---"')
 UNASSIGNED DEVICES:\n
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "UNASSIGNED")] | .[] | " - SerialNumber: \(.id)\n- Model: \(.attributes.deviceModel)\n---"')"
  fi  
	fileName="A file called listOrgDevices.csv has been created on your Desktop"

	echo "$response" | jq -r '.data[] | [.id, .attributes.status, .attributes.deviceModel] | @csv' > "$homeFolder/Desktop/listOrgDevices.csv"

  if [[ $? == 0 ]]; then
    echo "- A file called listOrgDevices.csv has been created on the Desktop/\n"
  else
    echo "- An error occured when creating the file listOrgDevices.csv on the Desktop\n"
  fi
	
}

#################################################################################
# FUNCTION TO CREATE A CSV FILE WITH ALL ASSIGNED/UNASSIGNED DEVICES IN THE ORGANIZATION
#################################################################################
# It counts the number of assigned/unassigned devices and creates a CSV file with the following format:
# SerialNumber
# It shows a message with the number of assigned/unassigned devices
# and the total number of devices in the organization
# It also shows a message with the list of assigned/unassigned devices
# The file is created in the Reports folder in the script directory
# Parameters:
#   - deviceStatus: "ASSIGNED" or "UNASSIGNED"
function createStatusDevicesCSV() {

	deviceStatus="$1"
	response=$(curl -s "${url}/orgDevices" -H "Authorization: Bearer ${accessToken}")
	assignedCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "ASSIGNED")] | length ')
	unassignedCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "UNASSIGNED")] | length ')	
	totalCount=$(echo "$response" | jq '.data | length')
  macCount=0
  iosCount=0
  ipadCount=0
  message=""

	if [[ $deviceStatus == "UNASSIGNED" ]]; then
		title="The instance has $unassignedCount unassigned devices out of $totalCount."

    macCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "UNASSIGNED") | select(.attributes.productFamily | contains("Mac"))] | length')
    iosCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "UNASSIGNED") | select(.attributes.productFamily | contains("iPhone"))] | length')
    ipadCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "UNASSIGNED") | select(.attributes.productFamily | contains("iPad"))] | length')

    if [[ $macCount -eq 0 && $iosCount -eq 0 && $ipadCount -eq 0 ]]; then
      message="There are no unassigned devices in the organization."
    else
      if [[ $macCount -gt 0 ]]; then
        message="Mac Devices:\n"
        message+="
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "UNASSIGNED") | select(.attributes.productFamily | contains("Mac"))] | .[] | " - SerialNumber: \(.id)\n---"')"
      fi
      if [[ $iosCount -gt 0 ]]; then
        message+="
 iOS Devices:\n"
        message+="
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "UNASSIGNED") | select(.attributes.productFamily | contains("iPhone"))] | .[] | "- SerialNumber: \(.id)\n---"')"
      fi
      if [[ $ipadCount -gt 0 ]]; then
        message+="
 iPadOS Devices:\n"
        message+="
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "UNASSIGNED") | select(.attributes.productFamily | contains("iPad"))] | .[] | "- SerialNumber: \(.id)\n---"')"
      fi

      fileName="A file called listUnassignedOrgDevices.csv has been created on the Desktop"

		  echo "$response" | jq -r '.data[] | select(.attributes.status == "UNASSIGNED") | [.id, .attributes.deviceModel] | @csv' > "$homeFolder/Desktop/listUnassignedOrgDevices.csv"
      
      if [[ $? == 0 ]]; then
        echo "- A file called listUnassignedOrgDevices.csv has been created on the Desktop\n"
      else
        echo "- An error occured when creating the listUnassignedOrgDevices.csv on the Desktop\n"
      fi

    fi

	else

		title="The instance has $assignedCount assigned devices out of $totalCount."
		macCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "ASSIGNED") | select(.attributes.productFamily | contains("Mac"))] | length')
    iosCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "ASSIGNED") | select(.attributes.productFamily | contains("iPhone"))] | length')
    ipadCount=$(echo "$response" | jq '[.data[] | select(.attributes.status == "ASSIGNED") | select(.attributes.productFamily | contains("iPad"))] | length')

    if [[ $macCount -eq 0 && $iosCount -eq 0 && $ipadCount -eq 0 ]]; then
      message="There are no assigned devices in the organization."
    else
      if [[ $macCount -gt 0 ]]; then
        message="Mac Devices:"
        message+="
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "ASSIGNED") | select(.attributes.productFamily | contains("Mac"))] | .[] | " - SerialNumber: \(.id)\n---"')"
      fi
      if [[ $iosCount -gt 0 ]]; then
        message+="
 iOS Devices:"
        message+="
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "ASSIGNED") | select(.attributes.productFamily | contains("iPhone"))] | .[] | "- SerialNumber: \(.id)\n---"')"
      fi
      if [[ $ipadCount -gt 0 ]]; then
        message+="
 iPadOS Devices:"
        message+="
 $(echo "$response" | jq -r '[.data[] | select(.attributes.status == "ASSIGNED") | select(.attributes.productFamily | contains("iPad"))] | .[] | "- SerialNumber: \(.id)\n---"')"
      fi

		  fileName="A file called listAssignedOrgDevices.csv has been created in $scriptDir/Reports/"
  
		  echo "$response" | jq -r '.data[] | select(.attributes.status == "ASSIGNED") | [.id, .attributes.deviceModel] | @csv' > "$scriptDir/../Resources/Reports/listAssignedOrgDevices.csv"
    
      if [[ $? == 0 ]]; then
        echo "- A file called listAssignedOrgDevices.csv has been created in $scriptDir/Reports/\n"
      else
        echo "- An error occured when creating the listAssignedOrgDevices.csv in $scriptDir/Reports/\n"
      fi
    fi
	fi

}

#################################################################################
# FUNCTION TO LIST ALL MDM SERVERS IN THE ORGANIZATION
#################################################################################
# It counts the number of MDM servers and shows their names
# It creates a CSV file with the following format:
# ServerName,ServerId
# The CSV file is created in the Reports folder in the script directory
function listMDMServers() {
	response=$(curl -s "${url}/mdmServers" -H "Authorization: Bearer ${accessToken}")
	
  serverCount=$(echo "$response" | jq '[.data[] | select(.attributes.serverType == "MDM")] | length ')
	
	title="The instance has $serverCount MDM Servers"
	message=$(echo "$response" | jq -r '.data[] | select(.attributes.serverType == "MDM") | "
  - \(.attributes.serverName)" ')
	fileName="A file called listMDMServers.csv has been created on the Desktop"
	

  echo "$response" | jq -r '.data[] | select(.attributes.serverType == "MDM") | [.id, .attributes.serverName ] | @csv' > "$homeFolder/Desktop/listMDMServers.csv"

  if [[ $? == 0 ]]; then
    echo "- A file called listMDMServers.csv has been created on the Desktop\n"
  else
    echo "- An error occured when creating the file listMDMServers.csv on the Desktop\n"
  fi
}

#################################################################################
# FUNCTION TO GET THE MDM Server ID AND NAME
#################################################################################
# This function gets the MDM Server ID and name from the list of MDM servers
# It prompts the user to choose an MDM server from a list
# It creates two arrays, one for the names and one for the IDs
# It shows an AppleScript dialog with the names and returns the chosen name and ID
# The chosen name and ID are stored in the variables chosenName and chosenId
function getMDMServerId() {
	response=$(curl -s "${url}/mdmServers" -H "Authorization: Bearer ${accessToken}")
	echo "$response" | jq -r '.data[] | select(.attributes.serverType == "MDM") | [.id, .attributes.serverName] | @csv' > "$homeFolder/Desktop/listMDMServers.csv"
	
  if [[ $? == 0 ]]; then
    echo "- A file called listMDMServers.csv has been created on the Desktop"
  else
    echo "- An error occured when creating the file listMDMServers.csv on the Desktop"
  fi

  mdmNames=()
  mdmIds=()

  # Get the name and ID for the servers
  # The sets will be places in an array
	while IFS=',' read -r id name; do
		mdmNames+=($name)
		mdmIds+=($id)
	done < "$homeFolder/Desktop/listMDMServers.csv"
	

  # Show MDM Selection dialog with names
  # Use the mdmSelection function to present the dialog
  # The dialog will have a list of MDM servers to choose from
  # The user will select one MDM server from the list
    # The selected option will be parsed to get the name of the MDM server
	chosenName=$(mdmSelection | awk -F ':' '/SelectedOption/ {print $2}' | tr -d '"' | xargs)


			
  # If the user cancelled, exit
		if [ -z "$chosenName" ]; then
			echo "- User cancelled selection when choosing an MDM Server\n"
			exit 1
		fi
		
  # Find the corresponding ID
	chosenId=""
 
	for ((i=1; i<=${#mdmNames[@]}; i++)); do
		if [ "$(echo "${mdmNames[$i]}" | tr -d '"' | xargs)" = "$chosenName" ]; then
			chosenId=$(echo "${mdmIds[$i]}" | tr -d '"' | xargs)
			break
		fi
	done

	# If no ID was found, exit
        if [ -z "$chosenId" ]; then
            echo "- No ID found for the chosen name: ${chosenName}\n"
            exit 1
        fi

}

#################################################################################
# FUNCTION TO LIST DEVICES FOR A SPECIFIC MDM SERVER
#################################################################################
# It calls the getMDMServerId function to get the MDM Server ID and name
# It then makes an API call to get the list of devices assigned to that MDM Server
# It shows the Serial Numbers of the devices and creates a CSV file with the following format:
# SerialNumber
# The CSV file is saved in /Users/Shared/listDevicesfor_<MDM_Server_Name>.csv
function listDevicesforMDMService() {
	
  getMDMServerId
  fileName=""
  # Get the list of devices for the chosen MDM Server
  deviceList=$(curl -s "${url}/mdmServers/${chosenId}/relationships/devices" -H "Authorization: Bearer ${accessToken}")

  devices=$(echo "$deviceList" | jq -r '.data[] | .id' 2> /dev/null)
  title="Devices for MDM Server: ${chosenName}"
  if [[ -z "$devices" ]]; then
		message="No devices found for the selected MDM Server."
    echo "- No devices found for the selected MDM Server"

	else
    message=$(echo "$deviceList" | jq -r '.data[] | (.id) as $serialNumber | "
 - \($serialNumber)\n---"')
    fileName="A file called listDevicesfor_${chosenName}.csv has been created on the Desktop"
	
    echo "$deviceList" | jq -r '.data[] | [.id] | @csv' > "$homeFolder/Desktop/listDevicesfor_${chosenName}.csv"

    if [[ $? == 0 ]]; then
      echo "- A file called listDevicesfor_${chosenName}.csv has been created on the Desktop"
    else
      echo "- An error occured when creating the file listDevicesfor_${chosenName}.csv on the Desktop\n"
    fi


  fi

}

#################################################################################
# FUNCTION TO READ DEVICE INFORMATION FOR A SPECIFIC SERIAL NUMBER
#################################################################################
# It calls the getSerialNumber function to get the serial number from the user
# It then makes an API call to get the device information for that serial number
# It shows the device information in a dialog with the following format:
# Device Model: <model>
# Product Type: <type>
# Device Capacity: <capacity>
# Device Color: <color>
# SourceType: <source>
# Date Added: <dateAdded>
# Last Assigned Date: <dateUpdated>
# If the device is assigned, it also shows the MDM Server name to which it is assigned
# If the device is not assigned, it shows the status as "UNASSIGNED"
function readDeviceInfo() {

  serialNumber=$(getSerialNumber "know more about" | awk -F ':' '/Serial Number/ {print $2}' | tr -d '"' | xargs)
	deviceInfo=$(curl -s "${url}/orgDevices/${serialNumber}" -H "Authorization: Bearer ${accessToken}")
  
  serialStatus=$(echo $deviceInfo | jq -r '.errors[] | .code' 2> /dev/null)

  if [[ $serialStatus == "NOT_FOUND"  ]]; then
    echo "- Serial Number not found: ${serialNumber}\n"
    title="Device Information for Serial Number: $serialNumber"
    message=$(echo "
 - The Serial Number (${serialNumber}) does not exist in the organization.\nPlease check the Serial Number and try again.")
  else
	title="Device Information for Serial Number: $serialNumber"
  messagePart1=$(echo "$deviceInfo" | jq -r '
 .data.attributes.deviceModel as $model | 
 .data.attributes.productType as $type | 
 .data.attributes.deviceCapacity as $capacity | 
 .data.attributes.color as $color | 
 .data.attributes.purchaseSourceType as $source | 
 (.data.attributes.addedToOrgDateTime | sub("\\.[0-9]*Z$"; "") | sub("T"; " ")) as $dateAdded | 
 (.data.attributes.updatedDateTime | sub("\\.[0-9]*Z$"; "") | sub("T"; " ")) as $dateUpdated | 
 "\nDevice Model: \($model)\n
 Product Type: \($type)\n
 Device Capacity: \($capacity)\n
 Device Color: \($color)\n
 Source Type: \($source)\n
 Date Added: \($dateAdded)\n
 Last Assigned Date: \($dateUpdated)\n

 "'
  )
	deviceStatus=$(echo "$deviceInfo" | jq -r '.data.attributes.status')
	
	  if [[ $deviceStatus == "ASSIGNED" ]]; then
		  assignedServer=$(curl -s ${url}/orgDevices/${serialNumber}/assignedServer -H "Authorization: Bearer ${accessToken}" | jq -r '.data.attributes.serverName')
		  messagePart2=$(echo "
 Status: $deviceStatus\n
 Assigned MDM Server: $assignedServer")
	  else
		  messagePart2=$(echo "Status: $deviceStatus")
	  fi
  
    message=$(echo -e "$messagePart1\n$messagePart2")
  fi
}

#################################################################################
# FUNCTION TO CREATE A CSV TEMPLATE FILE FOR ASSIGNED DEVICES
#################################################################################
# File created to be used as a template for Assigning devices
# It will be used to create the payload for the API calls
# The placeholders will be replaced with the actual values when the script is run
# The placeholders are CHOSEN_ID_PLACEHOLDER and SERIAL_NUMBER_PLACEHOLDER
# The template file will be created in the same directory as the script
function createAssignTemplateFile() {
	# Create a template file
	cat > payload_template.json << 'EOF'
  {
	"data": {
		"type": "orgDeviceActivities",
		"attributes": {
			"activityType": "ASSIGN_DEVICES"
		},
		"relationships": {
			"mdmServer": {
				"data": {
					"type": "mdmServers",
					"id": "CHOSEN_ID_PLACEHOLDER"
				}
			},
			"devices": {
				"data": [
					{
						"type": "orgDevices",
						"id": "SERIAL_NUMBER_PLACEHOLDER"
					}
				]
			}
		}
	}
  }
EOF
}

#################################################################################
# FUNCTION TO CREATE A CSV TEMPLATE FILE FOR UNASSIGNED DEVICES
#################################################################################
# File created to be used as a template for Unassigning devices
# It will be used to create the payload for the API calls
# The placeholders will be replaced with the actual values when the script is run
# The placeholders are CHOSEN_ID_PLACEHOLDER and SERIAL_NUMBER_PLACEHOLDER
# The template file will be created in the same directory as the script	
function createUnassignTemplateFile() {
	# Create a template file
	cat > payload_template.json << 'EOF'
  {
	"data": {
		"type": "orgDeviceActivities",
		"attributes": {
			"activityType": "UNASSIGN_DEVICES"
		},
		"relationships": {
			"mdmServer": {
				"data": {
					"type": "mdmServers",
					"id": "CHOSEN_ID_PLACEHOLDER"
				}
			},
			"devices": {
				"data": [
					{
						"type": "orgDevices",
						"id": "SERIAL_NUMBER_PLACEHOLDER"
					}
				]
			}
		}
	}
  }
EOF
}

#################################################################################
# FUNCTION TO REPLACE THE PLACEHOLDERS IN THE TEMPLATE FILE WITH THE ACTUAL VALUES
#################################################################################
# Creates the temporary payload file with substituted values
# It will be called when the user selects the "Assign Devices" or "Unassign Devices" option in the main dialog
# It is using the template file created in the createAssignTemplateFile or createUnassignTemplateFile function
function assignAction() {

		sed -e "s/CHOSEN_ID_PLACEHOLDER/${chosenId}/g" \
		-e "s/SERIAL_NUMBER_PLACEHOLDER/${serialNumber}/g" \
		payload_template.json > "$scriptDir/../Resources/temp_payload.json"
	
  echo "- Template file replaced with correct value: ${serialNumber}\n"
	
	curl -s -X POST "${url}/orgDeviceActivities" \
	-H "Authorization: Bearer ${accessToken}" \
	-H "Content-Type: application/json" \
	-d @"$scriptDir/../Resources/temp_payload.json"
			
}

#################################################################################
# FUNCTION TO ASSIGN OR UNASSIGN DEVICES
#################################################################################
function actionOnDevices() {

	local action=$1
  # Get the MDM Server ID and name
	getMDMServerId

	if [[ $action == "assign" ]]; then
		createAssignTemplateFile
	elif [[ $action == "unassign" ]]; then
		createUnassignTemplateFile
	else
		echo "- Invalid action specified. Use 'assign' or 'unassign'."
		exit 1
	fi
	
  # Ask the user if it wants to upload or type a Serial Number
  newAction "Do you want to *Upload* a file with **Serial Numbers** or do you prefer to enter the **Serial Numbers** *Manually*?" "Upload" "Manually"
	
  # Evaluate which button the user clicked
  case $? in
    0)
    echo "- The user selected to Upload Serial Numbers\n"
    details=$(getSerialNumbersToAction)
    serialNumbersPath=$(echo "$details" | awk -F ':' '{print $2}' | xargs)
  
    # Logic for the uploaded file
    while IFS=',' read -r serialNumberRaw type; do
			echo "$serialNumberRaw"
      serialNumber=$(echo "$serialNumberRaw" | tr -d '"' | xargs)
      echo $serialNumber
      echo $chosenId
			assignAction
		
			if [[ $? != 0 ]]; then
				echo "Failed to ${action} device with Serial Number: ${serialNumber}\n"
				continue
			fi
		# Clean up
			rm -f "$scriptDir/../Resources/temp_payload.json"
			
		done < "$serialNumbersPath"

    ;;
    2)
    echo "- The user selected to Manually add Serial Numbers\n"
    serialNumber=""
    while [[ $serialNumber == ""  ]]; do
      serialNumber=$(getSerialNumber "know more about" | awk -F ':' '/Serial Number/ {print $2}' | tr -d '"' | xargs)

      # Logic for the action on the device
      # It just needs to call the function. the function itself does the job
      assignAction

      if [[ $? != 0 ]]; then
			  echo "- Failed to "${action}" device with Serial Number: ${serialNumber}\n"
		  fi

      # If the user wants to type prompt for another SN at the end of the action
      newAction "Do you want to add more Serial Numbers?" "Yes" "No"
      case $? in
        0)
        serialNumber=""
        ;;
        2)
        echo "- The user choose not to add more Serial Numbers\n"
      esac
    # Clean up
		rm -f "$scriptDir/../Resources/temp_payload.json"
    done
    ;;
    *)
    echo "- Something else happened\n"
    ;;
	esac
    

  







}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# MAIN SCRIPT FUNCTIONS
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

#################################################################################
# FUNCTION TO GET CREDENTIALS FROM THE USER
#################################################################################
# Check if the storeDetailsValue is set in the config file
# If the storeDetailsValue exists and is set to true (1), the dialog will not be presented
# If the storeDetailsValue is set to true (1), then we will read the clientId
# and keyId, private_key_file and service from the config file and use them in the script
# If the user checks "Save details" the details will be saved in the config file and the dialog will not be presented again
# To present the dialog again the Config file needs to be deleted or the storeDetailsValue needs to be set to false (0)
# If the storeDetailsValue does not exist, then
function getCredentials() {

  storeDetailsValue=$(defaults read "$configLocation" storeDetailsValue 2>/dev/null)
  if [[ $storeDetailsValue != "1" ]]; then
    details=$(addDetails)
    if [[ $? != 0 ]]; then
      echo "- The user cancelled the Add Details prompt. Exiting...\n"
      exit
    else
      echo "- Presenting the Add Details dialog...\n"   
      storeDetailsCheck=$(echo "${details}" | awk '/Save the details/' | awk -F '"' '{print $4}')
      service=$(echo "$details" | awk '/SelectedOption/' | awk -F ':' '{print $2}' | tr -d '"' | xargs)
      private_key_path=$(echo "$details" | awk 'FNR==1' | awk -F ':' '{print $2}' | xargs)
      private_key_file=$(basename "$private_key_path")
      client_id=$(echo "$details" | awk 'FNR==2 {print $NF}')
      key_id=$(echo "$details" | awk 'FNR==3 {print $NF}')

      if [[ $storeDetailsCheck == "true" ]]; then
        echo "- The user has chosen to save the details in the config file.\n"
        defaults write "$configLocation" storeDetailsValue -bool true
        defaults write "$configLocation" clientID -string "$client_id"
        defaults write "$configLocation" keyID -string "$key_id"
        defaults write "$configLocation" privateKeyFile -string "$private_key_path"
        defaults write "$configLocation" service -string "$service"
      fi
    fi  
  else
    client_id=$(defaults read "$configLocation" clientID 2>/dev/null)
    key_id=$(defaults read "$configLocation" keyID 2>/dev/null)
    private_key_path=$(defaults read "$configLocation" privateKeyFile 2>/dev/null)
    service=$(defaults read "$configLocation" service 2>/dev/null)

  fi

 # Checking the value of the service variable
 # The variables below will be used to set the URL, mainTitle and scope variables
  if [[ $service == "Apple School Manager" ]]; then
	  url="https://api-school.apple.com/v1"
	  mainTitle="Apple School Manager Information"
    scope="school.api"
  else
	  url="https://api-business.apple.com/v1"
	  mainTitle="Apple Business Manager Information"
    scope="business.api"
  fi
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# MAIN SCRIPT
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
exec 1>> $scriptLog 2>&1

echo -e "
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    Script started: $( date +%Y-%m-%d\ %H:%M:%S ) -$fullName
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    "
###############################################################################################################
# STEP 0: CHECKING FOR SWIFTDIALOG
###############################################################################################################
if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]; then
    echo "- swiftDialog is not found and is configured to be used...
    "
    dialogCheck
  else
  echo "- swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding...
  "
fi

###############################################################################################################
# STEP 1: PRESENTING THE FIRST TIME USE DIALOG (IT WILL BE SKIPPED IF THE FIRST TIME USE VALUE IS SET TO 1 "TRUE")
###############################################################################################################
# Check if the firstUseValue is set in the config file
# If the firstUseValue exists and is set to true (1), the dialog will not be presented
# If the firstUseValue exists and is set to false (0) or does not exist, then the first time use dialog is presented
# If the user checks "Do not present this Dialog again", firstUseValue will be set to true(1), and the dialog box is not presented again
# To present the dialog again the Config file needs to be deleted or the firstUseValue needs to be set to 0 (false)
firstTimeValue=$(defaults read "$configLocation" firstUseValue 2>/dev/null)
if [[ $firstTimeValue != "1" ]]; then
  echo "- Presenting the First Time Use Prompt...\n"
  firstTimeVariable=$(firstTimeUse)
  if [[ $? != 0 ]]; then
    echo "- The user cancelled the First Time Use prompt. Exiting...\n"
    exit
  else    
    firstTimeCheck=$(echo "$firstTimeVariable" | awk -F '"' '{print $4}')
    defaults write "$configLocation" firstUseValue -bool "$firstTimeCheck"
  fi
else
  echo "- The first time use dialog has been skipped as the firstUseValue is set to 1 (true) in the config file.\n"
fi

###############################################################################################################
# STEP 2: GETTING DETAILS FROM THE USER OR READING FROM THE CONFIG FILE
###############################################################################################################
getCredentials

###############################################################################################################
# STEP 4: CHECKING FOR FOR THE ASSERTION AND ACCESS TOKENS
###############################################################################################################
checkTokenValidity

###############################################################################################################
# STEP 5: SHOWING THE USER A DIALOG TO SELECT AN ACTION
###############################################################################################################
newSearchCode=0
while [[ $newSearchCode -eq 0 ]]; do
	
  echo "- Presenting the Actions dialog...\n"
  userSelection=$(promptUser)
  if [[ $? == 2 ]]; then
    echo "- The user wants to reset Credentials...\n"
    warningUsers "This action will reset the saved Credentials? Are you sure you want to proceed?" "Yes" "No"
    if [[ $? == 0 ]]; then
      echo "- The user confirmed resetting the Credentials\n"
      defaults delete "$configLocation" clientID
      defaults delete "$configLocation" keyID
      defaults delete "$configLocation" privateKeyFile
      defaults delete "$configLocation" service
      defaults write "$configLocation" storeDetailsValue -bool false
      echo "- The Credentials have been reset.\n"
      getCredentials
    else
      echo "- The user has chosen not to reset the Credentials\n"
      exit
    fi
    
  else
  selectedOption=$(echo "$userSelection" | awk '-F :' '/SelectedOption/ {print $NF}' | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//')
		case "$selectedOption" in
			"List Organization Devices")
				listOrganizationDevices
        echo "- Listing Organization Devices...\n"
				apiResults "$title" "$message" "$fileName"
				;;
			"List MDM Servers")
        listMDMServers
				echo "- Listing MDM Servers...\n"
        apiResults "$title" "$message" "$fileName"
				;;
			"List Devices for MDM Server")
        listDevicesforMDMService
				echo "- Listing Devices for MDM Server...\n"
        echo $title
        echo $message
        echo $fileName
        apiResults "$title" "$message" "$fileName"
				;;
			"Read Device Information")
        readDeviceInfo
        echo "- Reading Device Information...\n"
        apiResults "$title" "$message"
				;;
			"Create Unassigned Devices CSV")
				createStatusDevicesCSV "UNASSIGNED"
        echo "- Creating Unassigned Devices CSV...\n"
				apiResults "$title" "$message" "$fileName"
				;;
			"Create Assigned Devices CSV")
				createStatusDevicesCSV "ASSIGNED"
        echo "- Creating Assigned Devices CSV...\n"
				apiResults "$title" "$message" "$fileName"
				;;
			"Assign Devices")
        actionOnDevices assign
        echo "- Assigning Devices...\n"
				;;
			"Unassign Devices")
        actionOnDevices unassign
        echo "- Unassigning Devices...\n"
				;;
			*)
			echo "- The User has chosen to cancel the Actions prompt\n"
				exit
				;;
		esac
  fi
	newAction "Do you want to perform another operation?" "Yes" "No"
	
	newSearchCode=$(echo $?)

	if [[ $newSearchCode -ne 0 ]]; then
		echo "- The User has chosen to exit the script\n"
		exit 0
	fi


done
