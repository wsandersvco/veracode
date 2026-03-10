#! /bin/sh

# set these up in the environment before running this script
# export VERACODE_API_KEY_ID=${{ secrets.VERACODE_API_ID }}
# export VERACODE_API_KEY_SECRET=${{ secrets.VERACODE_API_KEY }}

# Dependencies
# httpie
# jq
# wc, tr, cat, rm, cp
# best suited for veracode/api-signing container

# Inputs
# APP_NAME
# PIPELINE_RESULTS_FILE
# OUTPUT_FILTERED_PIPELINE_RESULTS_FILE

# Usage: ./filter_policy_flaws.sh <APP_NAME> <PIPELINE_RESULTS_FILE> <OUTPUT_FILTERED_PIPELINE_RESULTS_FILE>
# Example: ./filter_policy_flaws.sh "wsandersvco/verademo-dotnet" "1-results.json" "filtered_results.json"

# Validate arguments
if [ $# -lt 3 ]; then
    echo "Error: Missing required arguments"
    echo "Usage: $0 <APP_NAME> <PIPELINE_RESULTS_FILE> <OUTPUT_FILTERED_PIPELINE_RESULTS_FILE>"
    echo "Example: $0 'wsandersvco/verademo-dotnet' '1-results.json' 'filtered-results.json'"
    exit 1
fi

echo "PWD: $(pwd)"

APP_NAME="$1"
PIPELINE_RESULTS_FILE="$2"
OUTPUT_FILTERED_PIPELINE_RESULTS_FILE="$3"

# Validate pipeline results file exists
if [ ! -f "$PIPELINE_RESULTS_FILE" ]; then
    echo "Error: Pipeline results file '$PIPELINE_RESULTS_FILE' not found"
    exit 1
fi

output_file=flaws_all.json

# fetch application and static policy findings
guid=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v1/applications?name=$APP_NAME" | jq -r '._embedded.applications[0].guid') 
echo GUID: ${guid}

# Check if guid is null or empty
if [ -z "$guid" ] || [ "$guid" = "null" ]; then
    echo "Error: Could not find application with name '$APP_NAME'"
    echo "Skipping policy flaws fetch. Copying pipeline results without filtering."
    cp "$PIPELINE_RESULTS_FILE" "$OUTPUT_FILTERED_PIPELINE_RESULTS_FILE"
    exit 0
fi

total_pages=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC" | tee flaws_p0.json | jq -r '.page.total_pages')
echo Pages: ${total_pages}

if [ ${total_pages} = 1 ]; then
	mv flaws_p0.json ${output_file}
else
	echo "Already have flaws, page 0"

	# get remaining pages and merge flaws
	for i in `seq 1 ${total_pages}`
	do
		echo "Getting flaws, page $i"
		http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&page=$i" > flaws_tmp.json

		echo "Merging flaws, page `expr $i - 1` into page $i"
		jq -s '.[0] as $f1 | .[1] as $f2 | ($f1 + $f2) | ._embedded.findings = ($f1._embedded.findings + $f2._embedded.findings)' flaws_p`expr $i - 1`.json flaws_tmp.json > flaws_p$i.json
	done
	
	# rename final output file
	mv flaws_p`expr $i - 1`.json ${output_file}
fi

# apply filtering for closed flaws that are approved as mitigated or potential false positives
# jq '._embedded.findings |= map(select(
# 	.finding_status.status != "CLOSED" 
# 	or (.finding_status.resolution != "POTENTIAL_FALSE_POSITIVE" and .finding_status.resolution != "MITIGATED") 
# 	or .finding_status.resolution_status != "APPROVED"
# 	))' ${output_file} > flaws_filtered.json
# cp flaws_filtered.json ${output_file}

# Extract file_path, cwe_id, and line_number from policy scan findings that should be excluded
# Replicate functionality in veracode/github-actions-integration-helper, line 124 to 132 and line 151 to 162
echo "Start: exclusion criteria"
jq -r '._embedded.findings[] | select(
  .finding_status.status == "CLOSED" and
  .finding_status.resolution_status == "APPROVED" and
  (.finding_status.resolution == "MITIGATED" or .finding_status.resolution == "POTENTIAL_FALSE_POSITIVE") and
  .finding_details.file_path != null
) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' ${output_file} > exclusion_criteria.txt

exclusion_count=$(wc -l < exclusion_criteria.txt | tr -d ' ')
echo "Exclusion criteria: ${exclusion_count}"

if [ "$exclusion_count" -eq 0 ]; then
    echo "No exclusions found."
    cp $PIPELINE_RESULTS_FILE $OUTPUT_FILTERED_PIPELINE_RESULTS_FILE
    exit 0
fi

exclusion_list=$(cat exclusion_criteria.txt | jq -R -s 'split("\n") | map(select(length > 0))')
echo "Finish: exclusion criteria"

echo "Start: filter pipeline results"
jq --argjson exclusions "$exclusion_list" '
  .findings |= map(
    . as $finding |
    ("\($finding.files.source_file.file)|\($finding.cwe_id)|\($finding.files.source_file.line)") as $key |
    select($exclusions | index($key) | not)
  )
' $PIPELINE_RESULTS_FILE > $OUTPUT_FILTERED_PIPELINE_RESULTS_FILE
echo "Finish: filter pipeline results"

filtered_count=$(jq '.findings | length' $OUTPUT_FILTERED_PIPELINE_RESULTS_FILE)
original_count=$(jq '.findings | length' $PIPELINE_RESULTS_FILE)
removed_count=$((original_count - filtered_count))

# Cleanup
rm flaws_p*.json flaws_tmp.json flaws_all.json exclusion_criteria.txt

echo "Original findings: ${original_count}"
echo "Filtered findings: ${filtered_count}"
echo "Removed findings: ${removed_count}"
