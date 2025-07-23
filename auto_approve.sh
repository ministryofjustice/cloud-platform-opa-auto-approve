#!/usr/bin/env bash

set -eu

PLAN_DIR=$1
PLAN_NAME=$2
PR=$3
NAMESPACE_CONTAINS_SKIP_FILE=$4

JSON_FILE="${PLAN_NAME%.out}.json"

terraform -chdir="$PLAN_DIR" show -json "$PLAN_NAME" > "$JSON_FILE"

cat $JSON_FILE | jq --arg ns_contains_skip_file $NAMESPACE_CONTAINS_SKIP_FILE '. + {namespace_contains_skip_file: $namesspace_contains_skip_file}' > $JSON_FILE

results=()

CHANGED_FILES=$(curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/ministryofjustice/cloud-platform-environments/pulls/$PR/files" |  jq -r '.[].filename')


NUM_CHANGED_FILES=$(echo "$CHANGED_FILES" | wc -l)

if [[ "$CHANGED_FILES" == namespaces/live.cloud-platform.service.justice.gov.uk/*/APPLY_PIPELINE_SKIP_THIS_NAMESPACE ]] && [[ "$NUM_CHANGED_FILES" -eq 1 ]] ; then
    exit 0
fi

for f in $CHANGED_FILES; do
    if [[ "$f" == namespaces/live.cloud-platform.service.justice.gov.uk/*/*.yaml ]]; then
        REASON=":male_detective: **Detected changes to K8s YAML files. Manual review needed.**"

        curl -L \
            -X POST \
            -H "Accept: application/vnd.github+json" \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "https://api.github.com/repos/ministryofjustice/cloud-platform-environments/issues/$PR/comments" \
            -d '{
              "body": "This PR **CANNOT** be auto approved and requires manual approval from the Cloud Platform team.\n Reason:\n '"$REASON"'\n Please raise it in #ask-cloud-platform Slack channel."
        }'
        exit 0
    fi
done

BRANCH_NAME=$(curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/ministryofjustice/cloud-platform-environments/pulls/$PR" | jq -r ".head.ref")

BRANCH_STATUS_CHECKS=$(curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/ministryofjustice/cloud-platform-environments/commits/$BRANCH_NAME/check-runs")


SUCCESSFUL_CHECKS=$(echo $BRANCH_STATUS_CHECKS | jq '.check_runs[] | select(.conclusion == "success")' | jq -s '. | length')

TOTAL_CHECKS=$(echo $BRANCH_STATUS_CHECKS | jq '.total_count')

for i in 1 2 3 4 5; do
    if [[ $SUCCESSFUL_CHECKS -ne $TOTAL_CHECKS ]]
    then
        if [[ i -eq 5 ]]
        then
            echo "Checks have not completed successfully, skipping auto approve"
            exit 0
        fi
        echo "Checks have not completed retrying ${i}/5"
        sleep 60
    fi
    echo "${SUCCESSFUL_CHECKS} Successful / ${TOTAL_CHECKS} Total Checks. All Checks have passed"
    break
done

for dir in cloud-platform-opa-auto-approve/*/;
do
    OUTPUT=$(opa exec --decision terraform/analysis/allow --bundle $dir "$JSON_FILE")
    OPA_RESULT=$(echo "$OUTPUT" | jq -r '.result[0].result.valid')
    OPA_MESSAGE=$(echo "$OUTPUT" | jq -r '.result[0].result.msg')
    testname=$(echo "$dir" | sed 's/cloud\-platform\-opa\-auto\-approve\///g' | sed 's/\///g')
    if [[ $OPA_RESULT == "true" ]]
    then
        testresult=":white_check_mark:"
    else
        testresult=":x:"
    fi
    results+=($testname";"$testresult";""$OPA_MESSAGE")

done

if [[ ${results[@]} =~ ":x:" ]];
then
    REASON=":male_detective: **Manual review required: [OPA auto approve policy](https://github.com/ministryofjustice/cloud-platform-environments/tree/main/opa-auto-approve-policy) checks did not pass.**"

    string="\n| Test | Passed? | Reason | \n| --- | --- | --- |\n|"
    for t in "${results[@]}"; do
        split=$(echo "$t" | tr ";" "|")
        for th in "$split"
        do
            string+=" $th |"
        done
        string+="\n"
    done

    REASON+=$string

    curl -L \
        -X POST \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/ministryofjustice/cloud-platform-environments/issues/$PR/comments" \
        -d '{
      "body": "This PR **CANNOT** be auto approved and requires manual approval from the Cloud Platform team.\n Reason:\n '"$REASON"'\n Please raise it in #ask-cloud-platform Slack channel."
    }'
else
    curl -L \
        -X POST \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/ministryofjustice/cloud-platform-environments/pulls/$PR/reviews" \
        -d '{
    "body": ":white_check_mark: **Auto-Approved!**\n\nThis PR has **passed the [OPA auto approve](https://github.com/ministryofjustice/cloud-platform-opa-auto-approve) check and security validation**.\n\nYou can merge whenever suits you! :rocket:",
    "event": "APPROVE"
    }'
fi

exit 0
