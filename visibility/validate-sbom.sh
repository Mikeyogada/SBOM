#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

[ -f sbom-image.json ] || { #check if the file exists
    echo "No SBOM file found. Please run 'make sbom' first."
    exit 1 # Exit with an error code
}

[ -s sbom-image.json ] || { #check if the file is empty
    echo "SBOM file is empty. Please run 'make sbom' first."
    exit 1 # Exit with an error code
}
#
COUNT=$(jq '.components | length' sbom-image.json) #jq is a search query tool for JSON files, it is used to count the number of components in the SBOM file

echo "SBOM file contains $COUNT artifacts."

[ "$COUNT" -gt 0 ] || { #count should be greater than 0, if greater than 0, then it is valid, otherwise it is not valid
    echo "SBOM file does not contain any artifacts. Please run 'make sbom' first."
    exit 1 # Exit with an error code
}

echo "SBOM file is valid and contains artifacts."