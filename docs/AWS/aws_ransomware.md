# Ransomware in AWS
## Background

SIRT has received an alert about an [external KMS key being used to encrypt resources](https://github.com/DataDog/threat-detection/blob/main/rules/cloudtrail/aws_resource_encryption_ransomware.tf). For the sake of this lab, no signal was generated, but if it had been, it would have been triggered by [this GenerateDataKey event](https://app.datadoghq.com/logs?query=%40eventID%3A06d89b2c-cf2c-326f-aa8d-d80ba0dc8802&agg_m=count&agg_m_source=base&agg_t=count&clustering_pattern_field_path=message&cols=host%2Cservice%2C%40evt.name%2C%40requestParameters.bucketName%2C%40userIdentity.accessKeyId&event=AwAAAZWGathAgTavzAAAABhBWldHYkVTX0FBQVlhc0tkY0RDbGhnRFAAAAAkMDE5NTg2NmMtOTk3OC00ZDZiLWFjMzgtMmUwN2Q2YjAzNGRmAAHYoA&fromUser=true&messageDisplay=inline&refresh_mode=sliding&storage=flex_tier&stream_sort=desc&viz=stream&from_ts=1741716026101&to_ts=1741716926101&live=true).    

### Logs
The logs for this lab fall within the following time frame: `<tbd>`.
We can use the following filter to focus on the CloudTrail logs in the relevant AWS account:
`source:cloudtrail account:711387092967`

!!! note
    Since the sandbox infrastructure was used for lab development, if you do not limit your searches to account ID `711387092967`, "attacker" activity will appear in the results. Feel free to look at the events to get familiar with different event types, but in the case of a similar incident, these events will not appear as they will be logged in attacker infrastructure.


## Investigation
Start by reviewing the triggering event and understanding what is happening. 

??? question "What is the attacker doing based on this event?"
    ??? tip "Hint"
        - Search Google or generate AI to understand the `GenerateDataKey` event.  
        - Look at `@requestParameters` for more context.


    ??? info "Answer"
        This event indicates an attempt to encrypt data in AWS. The request parameters provide the following context:  
        
        - The object that was encrypted is `arn:aws:s3:::financial-reports-2025-23943/company_secrets.txt`, a file named `company_secrets.txt` in an S3 bucket called `financial-reports-2025-23943`.   
        - It was encryted with a KMS key with ARN `arn:aws:kms:us-east-1:601427279990:key/aba2894d-c354-499a-b55b-329a8e776c20`. 


??? question "What is a notable attribute of the KMS key involved in the encryption?"
    ??? tip "Hint"
        Review what each part of the ARN represents. Is there anything in the key's ARN that does not match with the context of this event?

    ??? info "Answer"
        The account ID shown in the ARN (`601427279990`) is from a different account than the one in which the encryption is occuring. In this particular case, due to testing infrastructure, it is another account within Datadog. The signal logic and what would likely be observed in an attack though is a key outside of Datadog being used. 

Now that we have reviewed the triggering event, let's look at the bigger picture and find out what other activity is associated with the attacker.

??? question "What indicators can help us track the relevant activity?"
    ??? tip "Hint"
        Take note of the following properties:   

        - @userIdentity.arn
        - @resource.ARN

    ??? info "Answer"
        - User ARN: `arn:aws:iam::711387092967:user/CloudOpsMonitor`    
        - KMS Key ARN: `arn:aws:kms:us-east-1:601427279990:key/aba2894d-c354-499a-b55b-329a8e776c20`

Before broadening our search to all activity from the IAM user, let's first see the full scope of the encryption activities.

??? question "How many files were encrypted? Gather a list of the files."

    ??? tip "Hint"
        Filter by the KMS key ARN: `index:cloudtrail account:711387092967 @resources.ARN:"arn:aws:kms:us-east-1:601427279990:key/aba2894d-c354-499a-b55b-329a8e776c20"`. Group by `@requestParameters.encryptionContext.aws:s3:arn` for a quick view of all encrypted resources.

    ??? info "Answer"
        10 files were encrypted, all in the `financial-reports-2025-23943` bucket. 

        ![file_list](./images/file_list.png)

We've mentioned in training that not all S3 buckets provide data-level logging, so any write or read operations on the bucket will not be logged. Let's go look at the bucket in the AWS console quick and see if there is anything notable.


??? question "Besides the bad practice of storing seemingly sensitive files, is there anything notable about the files in the bucket?"

    ??? tip "Hint"
        Look at the most recently modified file.

    ??? info "Answer"
        After each file is overwritten with an encrypted version of the file (Last Modified timestamps are seconds apart), a `RANSOM_NOTE.txt` is modified or created. Viewing this file reveals a ransom note that says an AWS KMS key was used to encrypt the other files and that if payment isn't made, the encryption key will be deleted after 7 days.

At this point, we've figured out that we were the target of a ransomware attack where an external KMS key was used to encrypt all the files in our bucket. To better understand the sequence of events that led to this, let's broaden our search to include all activity by the `CloudOpsMonitor` IAM user.