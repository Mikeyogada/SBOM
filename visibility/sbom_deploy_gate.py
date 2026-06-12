#!/usr/bin/env python3
import os
import json
from time import time 


def validate_sbom(sbom_image):
    #check 1: Check if the file exists
    if os.path.isfile(sbom_image):
        print ("SBOM file found.")
    else:
        print ("No SBOM file found. Please run 'make sbom' first.")
        exit(1) # Exit with an error code
    
    #check 2: Check if the file is empty
    if os.stat(sbom_image).st_size > 0:
        print ("SBOM file has several components")
    else:
        print ("SBOM file is empty. Please run 'make sbom' first.")
        exit(1) # Exit with an error code

    #check 3: Valid schema check
    with open(sbom_image) as f:
        sbom_data = json.load(f) #load python file as f and link it to sbom_data variable
        schema_validation = sbom_data.get("bomFormat", "")
        if schema_validation in ["CycloneDX", "SPDX"]:
            print(f"SBOM schema is valid: {schema_validation}")
        else:
            print ("Invalid SBOM schema. Expected 'CycloneDX' or 'SPDX'.")
            exit(1) # Exit with an error code

    #check 4: Check if the SBOM file contains components (non-zero components)
    components = sbom_data.get("components", []) #get components from the SBOm data, this is a list of components in the SBOm file

    if len(components) > 0:
        print(f"SBOM file contains {len(components)} components.")
    else:
        print ("SBOM file does not contain any components. Please run 'make sbom' first.")
        exit(1) # Exit with an error code

    #check 5: Check if the artifact mathches the expected artifact (this is a placeholder check, as the expected artifact is not defined in this script)
    artifact = sbom_data.get("metadata", {}).get("component", {}).get("name", "") #get the artifact name from the SBOM data, this is a placeholder check, as the expected artifact is not defined in this script

    if artifact == "sbom-lab": #replace with the expected artifact name
        print("SBOM artifact matches the expected artifact.")
    else:
        print ("SBOM artifact does not match the expected artifact. Please check the SBOM file.")
        exit(1) # Exit with an error code

    #check 6: Check if the SBOM file is stale (this is a placeholder check, as the expected artifact is not defined in this script)
    # This check can be implemented by comparing the timestamp of the SBOM file with the timestamp of the source code or the build process. If the SBOM file is older than the source code or the build process, then it is considered stale and should be regenerated. This check is not implemented in this script, but it can be added using the os.path.getmtime() function to get the timestamp of the SBOM file and the source code or the build process.
    timestamp_sbom = os.path.getmtime(sbom_image) #get the timestamp of the SBOM file
    timestamp_source = os.path.getmtime("Dockerfile") #get the timestamp of the source code, replace with the actual source code directory or file
    #check two pointers:
    #1. Age of the SBOM file (timestamp_sbom) against the age of the source code or the build process (timestamp_source)
    #2. if SBOM is older than 3 hours of the current time, then it is considered stale and should be regenerated. This can be implemented using the time module to get the current time and compare it with the timestamp of the SBOM file.
    
    current_time = time()
    if timestamp_sbom >= timestamp_source and (current_time - timestamp_sbom) <= 3 * 3600:
        print("SBOM file is up to date.")
    else:
        print ("SBOM file is stale. Please run 'make sbom' to regenerate the SBOM file.")
         # Exit with an error code

    #check 7: SBOM license check
    Blocked_licenses = ["GPL-2.0", "GPL-3.0"] #replace with the actual list of blocked licenses

    for component in components:
        license = component.get("licenses", [{}])[0].get("license", {}).get("id", "") #get the license of the component, this is a placeholder check, as the actual license information may be structured differently in the SBOM file
        if license in Blocked_licenses:
            print(f"Component {component.get('name', '')} has a blocked license: {license}. Please check the SBOM file.")
            exit(1) # Exit with an error code

    print(f"All components have valid licenses..")

    #check 8: Dependency allowlist check
    Blacklisted_dependencies = ["express"] #replace with the actual list of allowed dependencies
    sbom_data = json.load(open(sbom_image)) #load the SBOM file as a JSON object

    for component in sbom_data.get("components", []):
        name = component.get("name", "")
        
        if name in Blacklisted_dependencies:
            print(f"Component {name} is blacklisted. Please check the SBOM file.")
            exit(1) # Exit with an error code

    print(f"All dependencies are allowed.")
            

    return True

validate_sbom("sbom-image.json")
