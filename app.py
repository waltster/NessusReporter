# Copyright 2023 University of South Carolina. All rights reserved.
# Released under the license found in LICENSE.md
# 
# @author Walter Pach <walterdpach@outlook.com 
# @date 03/22/2023
# 
# A script for parsing and generating data from Nessus audit reports
import csv
import json
import sys
import os.path
from NessusAudit import NessusAudit

# Main function for running the parser
def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <input file> [output file]")
        exit(1)

    file_name = sys.argv[1]
    output_file = "report.csv"

    if len(sys.argv) == 3:
        output_file = sys.argv[2]
 
    if not os.path.isfile(file_name):
        print(f"Audit file \"{file_name}\" must exist in order to parse.")
        exit(1)

    audit_file = NessusAudit(file_name)
    data = audit_file.array()

    if len(data) <= 0:
        print(f"Either audit file contains no data or this is not a valid "
               "audit file. Please verify or try again with a different "
               "file.") 

    items_to_export = []
    items_to_export.append(["Reference", "Description", "Controls"]) 

    for custom_item in data:
        description = custom_item["description"]
        identifier = "No reference"
        reference = custom_item["reference"]
        references = []
 
        if custom_item["ref"] != "n/a":
            identifier = custom_item["ref"]

        for ref in reference.split(","):
            if "CSF" in ref:
                references.append(ref)

        if len(references) <= 0:
            continue

        items_to_export.append([identifier, description, ", ".join(references)])

    with open(output_file, "w") as outfile:
        csv_writer = csv.writer(outfile)
        
        for item in items_to_export:
            csv_writer.writerow(item)
    
    print(f"Wrote report to file: \"{output_file}\"") 

if __name__ == "__main__":
    main()
