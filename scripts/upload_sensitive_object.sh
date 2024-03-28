#!/bin/bash

# Arguments:
# - Bucket_name: the name of the target bucket you're using in the course
# - Profile: the AWS CLI profile to use to access credentials

# Uploads customers.txt to S3 bucket

# Check if two arguments were provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <bucketname> <profile>"
    exit 1
fi

# Assign the provided arguments to variables
bucket_name=$1
profile=$2

echo "Uploading object customers.txt to bucket: '$bucket_name'"
sts_output=$(aws s3 cp ./data-files/customers.txt s3://"$bucket_name"/customers.txt --profile "$profile")

echo $sts_output