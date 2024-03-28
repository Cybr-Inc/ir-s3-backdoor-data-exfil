# IAM credential exposure to S3 backdoor and exfil playbook

This playbook is used in Cybr's course [Incident Response with CloudTrail and Athena](https://cybr.com/courses/incident-response-with-cloudtrail-and-athena/) and this repo contains files to download for the course. Please complete steps as outlined in each lesson.

Inspired by: https://github.com/aws-samples/aws-incident-response-playbooks-workshop/blob/main/playbooks/credential_exposure/IAM_credential_exposure.md

## **Incident Classification & Handling**

- **Tactics, techniques, and procedures (TTPs)**:
    - T1078 Valid Accounts
    - TA0010 Exfiltration

We can use [MITRE ATT&CK](https://attack.mitre.org/) to get more specific

- **Category**: IAM credential exposure and S3 Data Exfiltration
- **Resources**: IAM and S3
- **Roles Assumed**:
    - **SecurityAnalyst**: provided CloudTrail Lake querying
    - **SecurityDeploy**: deploy AWS CDK app or CloudFormation stacks
    - **SecurityBreakGlass**: containment, eradication, and recovery of IAM user, credentials, and S3 bucket policy
- **Tooling**: AWS CLI, AWS CloudTrail, CloudFormation
- **Indicators**: GuardDuty alert
- **Log Sources**: AWS CloudTrail, Amazon GuardDuty
- **Teams Involved**: Security Operations Center (SOC), Forensic Investigators, Cloud Engineering, Legal

## Response Steps

1. [**ANALYSIS**] Validate alert by checking ownership of exposed credential
2. [**ANALYSIS**] Identity exposed credential owner/custodian
3. [**CONTAINMENT**] Disable exposed credential if approved by owner/customer
4. [**ANALYSIS**] Use Lake to pull 7 days of exposed credential activity from CloudTrail logs
5. [**ANALYSIS**] Use Lake to pull 7 days of source IP addresses used by exposed credential CloudTrail logs
6. [**ANALYSIS**] Establish reputation for source IP addresses
7. [**ANALYSIS**] Discover all resources provisioned, accesses, modified, or deleted by the exposed credential based on CloudTrail logs
8. [**CONTAINMENT**] Perform containment of all rogue resources modified or used by the exposed credential
9. [**ANALYSIS**] Determine if data was exfiltrated, modified, or deleted. Figure out the classification for all data sets touched.
10. [**ANALYSIS**] (If needed) Expand log scope to 90 days or further and repeat prior steps. Use your judgment on how far back to go.
11. [**ANALYSIS**] Estimate attribution and attack type (targeted or opportunistic)
12. [**ANALYSIS**] Preserve all relevant infrastructure and service resources for forensics investigation
13. [**ERADICATION**] Perform eradication (delete rogue resources, apply security updates and harden configuration)
14. [**RECOVERY**] Perform recovery by restoring system data and rebuilding components
15. [**POST-INCIDENT ACTIVITY**] Perform post-incident activity for preparation enhancement

## Recommendations

- Eliminate all users and access keys from our accounts, and prevent creations of new ones (check out this [blog post](https://cybr.com/cloud-security/ditching-aws-access-keys/) for tips on that)
- Create alerts based on the creation of long-term access keys or users
- Create alerts for the activity we saw in this attack (including `PutBucketPolicy`)
- Save the CloudTrail Lake queries we used in a playbook so that we can quickly retrieve and use them in the future
- Review S3 bucket policies across accounts to make sure they enforce least privileges ([tips on how to do that](https://cybr.com/cloud-security/create-a-least-privilege-s3-bucket-policy/))
- Script automation for containment and eradication via the AWS CLI or SDK
- Do not use real customer data in testing or development environments!

## Primary CloudTrail Lake query used

This query will pull multiple event properties from CloudTrail logs including source IP address, resources affected, event name, and request parameters.

```
SELECT
    eventTime,
    eventName,
    userIdentity.principalId,
    userIdentity.userName,
    sourceIPAddress,
    userAgent,
    resources,
    awsRegion,
    requestParameters,
    responseElements
FROM
    ec7160cc-5b9...
WHERE
    userIdentity.accessKeyId LIKE 'AKIAexample'
    AND eventTime > '2024-03-12 00:00:00'
ORDER BY
    eventTime DESC
```

Don't forget to edit the access key ID (`AKIAexample`), the eventTime (recommend starting with last 7 days but you can expand further), and the FROM `ec7160cc-5b9...` to match the ID of your event data store.

## Remediating compromised S3 buckets

Source: https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html

1. Identify the potentially compromised S3 resource
2. Identify the source of the suspicious activity and the API call used
3. Determine whether the call source was authorized to access the identified resource
4. Determine whether the S3 bucket contains sensitive data

## CloudTrail event fields of interest

For a full list, please refer to the CloudTrail documentation: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

For this sort of investigation, some of the most interesting event fields might be:

| Event Field               | Description                               |
|---------------------------|-------------------------------------------|
| eventTime                 | Date/time a request was made (UTC)        |
| eventName                 | Requested action (API call)               |
| eventSource               | Service the request was made to           |
| userIdentity.principalId  | IAM indentity ID that made the request       |
| userIdentity.userName     | IAM indentity username that made the request       |
| userAgent                 | User agent used to make the request (ie: CLI)
| resources                 | List of resources accessed with the call  |
| awsRegion                 | Region the request was made to  |
| requestParameters         | Parameters sent with the request (ie: the uploaded bucket policy)  |
| responseElements          |  Response for actions that make changes (create, update, delete) |