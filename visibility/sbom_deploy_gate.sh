#!/bin/bash 

set -e #exit immediately if a command exits with a non-zero status. This is a common practice in shell scripts to ensure that any errors are caught and handled appropriately, rather than allowing the script to continue running and potentially causing further issues.

#check 1: File exxistence check
[ -f sbom-image.json ] || { #check if the file exists
    echo "No SBOM file found. Please run 'make sbom' first."
    exit 1 # Exit with an error code
}

#check 2: File non-empty check
[ -s sbom-image.json ] || { #check if the file is empty
    echo "SBOM file is empty. Please run 'make sbom' first."
    exit 1 # Exit with an error code
}   

#check 3: Valid schema check
# This check is not implemented in this script, but it can be added using a JSON schema
schema_validation=$(jq '.bomFormat' sbom-image.json) #jq is a search query tool for JSON files, it is used to check if the schema version is valid
#check for cyclonedx and spdx, if the schema version is not valid, then it is not valid
if [[ "$schema_validation" != "\"CycloneDX\"" && "$schema_validation" != "\"SPDX\"" ]]; then
    echo "Invalid SBOM schema. Expected 'CycloneDX' or 'SPDX'."
    exit 1 # Exit with an error code
fi