# Ransomware in AWS
## Background

SIRT has received an alert about an [external KMS key being used to encrypt resources](https://github.com/DataDog/threat-detection/blob/main/rules/cloudtrail/aws_resource_encryption_ransomware.tf). For the sake of this lab, no signal was generated, but if it had been, it would have been triggered by [this GenerateDataKey event](https://app.datadoghq.com/logs?query=account%3A711387092967%20%40eventID%3A38cc2426-7f1d-3218-8a48-7c68f268d485&agg_m=count&agg_m_source=base&agg_t=count&clustering_pattern_field_path=message&cols=host%2Cservice&event=AwAAAZWqoGgQl8191wAAABhBWldxb283U0FBRFlab1hWX2NmUC1nQnMAAAAkMDE5NWFhYTAtN2I5OC00MWYwLWI0ODItNDE5YzIyZDg0NjQ4AABUSQ&fromUser=true&index=cloudtrail&messageDisplay=inline&refresh_mode=paused&storage=hot&stream_sort=desc&viz=stream&from_ts=1742324100000&to_ts=1742325000000&live=false).    

### Logs
The logs for this lab can be access via this link: [Ransomware in AWS Logs](https://app.datadoghq.com/logs?query=account%3A711387092967&agg_m=count&agg_m_source=base&agg_t=count&clustering_pattern_field_path=message&cols=host%2Cservice&fromUser=true&index=cloudtrail&messageDisplay=inline&refresh_mode=paused&storage=hot&stream_sort=desc&viz=stream&from_ts=1742324100000&to_ts=1742325000000&live=false).

!!! note
    Since the sandbox infrastructure was used for lab development, if you do not limit your searches to account ID `711387092967`, "attacker" activity will appear in the results. Feel free to look at the events to get familiar with different event types, but in the case of a similar incident, these events will not appear as they will be logged in attacker infrastructure.

!!! note
    Due to the testing script used, the benign setup activity has the same IP as the attacker activity, which is unlikely to happen in most cloud attacks. Usually, the IP address would be a useful pivot point.


## Investigation
Start by reviewing the triggering event and understanding what is happening. 

??? question "What is the attacker doing based on this event?"
    ??? tip "Hint"
        - Search Google or generative AI to understand the `GenerateDataKey` event.  
        - Look at `@requestParameters` in the `GenerateDataKey` event for more context.


    ??? info "Answer"
        This event indicates an attempt to encrypt data in AWS. The request parameters provide the following context:  
        
        - The object that was encrypted is `arn:aws:s3:::financial-reports-2025-7449/accounting_data_2025.xml`, a file named `accounting_data_2025.xml` in an S3 bucket called `financial-reports-2025-7449`.   
        - It was encryted with a KMS key with ARN `arn:aws:kms:us-east-1:601427279990:key/88ab009c-12da-4b74-95b4-d051924119a5`. 


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
        - KMS Key ARN: `arn:aws:kms:us-east-1:601427279990:key/88ab009c-12da-4b74-95b4-d051924119a5`

Before broadening our search to all activity from the IAM user, let's first see the full scope of the encryption activities.

??? question "How many files were encrypted? Gather a list of the files."

    ??? tip "Hint"
        Filter by the KMS key ARN: `index:cloudtrail account:711387092967 @resources.ARN:"arn:aws:kms:us-east-1:601427279990:key/88ab009c-12da-4b74-95b4-d051924119a5"`. Group by `@requestParameters.encryptionContext.aws:s3:arn` for a quick view of all encrypted resources.

    ??? info "Answer"
        10 files were encrypted, all in the `financial-reports-2025-7449` bucket. 

        ![file_list](./images/file_list.png)

We've mentioned in training that not all S3 buckets provide data-level logging, so any write or read operations on the bucket will not be logged. Let's go look at the bucket in the AWS console quick and see if there is anything notable.

??? question "Besides the bad practice of storing seemingly sensitive files, is there anything notable about the files in the bucket?"

    ??? tip "Hint"
        Look at the most recently modified file.

    ??? info "Answer"
        After each file is overwritten with an encrypted version of the file (Last Modified timestamps are seconds apart), a `RANSOM_NOTE.txt` is modified or created. Viewing this file reveals a ransom note that says an AWS KMS key was used to encrypt the other files and that if payment isn't made, the encryption key will be deleted after 7 days.

At this point, we've figured out that we were the target of a ransomware attack where an external KMS key was used to encrypt all the files in our bucket. To better understand the sequence of events that led to this, let's broaden our search to include all activity by the `CloudOpsMonitor` IAM user.

??? question "What other actions did the `CloudOpsMonitor` IAM user take?"

    ??? tip "Hint"
        Search based on the username `CloudOpsMonitor` and group by `@evt.name`.

    ??? info "Answer"
        Along with the previously-investigated `GenerateDataKey` action, the IAM account was also used to perform the following actions:
        - `DescribeTrails`
        - `StopLogging`
        - `PutUserPolicy`
        - `GetTrailStatus` 
        - `ListBuckets`   
        - `GetBucketVersioning`
        - `DescribeKey`    
        - `DescribeSnapshots`  
        - `CopySnapshot`  
        - `GenerateDataKeyWithoutPlaintext`  
        - `DeleteSnapshot`  

Let's look through each of these events to glean some insight into what the attacker was able to do in the environment. The first events are related to CloudTrail logging.

??? question "What did the threat actor try to do with CloudTrail? What was the result?"

    ??? tip "Hint"
        Look at the sequence of events and pay attention to the `@level` associated with events.

    ??? info "Answer"
        First the attacker runs `DescribeTrails`. This would allow them to retrieve a list of CloudTrails that exist in the account. The next request is to stop the logging for one of the CloudTrail's retrieved (`security-cloudtrail`). This, along with the attempt to get the Trail status after, failed due to a lack of identity-based policies allowing for those actions. This is clearly explained via Datadog in the `Error` section.


Luckily, thanks to our IAM policies, the threat actor was unable to stop logging so we have visibility into the follow-on activities. The other event that occurs around the time of the CloudTrail is `PutUserPolicy`. 

??? question "What is the policy that is applied supposed to do?"

    ??? tip "Hint"
        Look at the `@requestParameters` of the event.

    ??? info "Answer"
        The attacker is applying a policy called `CloudOpsAdmins` to the `CloudOpsMonitor` user. The `@requestParameters.policyDocument` field shows us that the policy would allow all actions on all resources for the associated user.

Let's move onto the bucket activity we see after the attempts to stop CloudTrail and user policy changes, but before the file encryption.

??? question "How many times was the `GetBucketVersioning` action taken? How many buckets was the call made against?"

    ??? tip "Hint"
        Further filter the search to only include `@evt.name:GetBucketVersioning`. Count the results. Group by the bucket name to see unique count of buckets.

    ??? info "Answer"
        There are 16 `GetBucketVersioning` events targeting 8 different buckets.


??? question "What AWS CLI command was caused these events to be generated?"

    ??? tip "Hint"
        Look at the user agent.

    ??? info "Answer"
        The user agent ends with `command#s3api.get-bucket-versioning` indicating the command executed was `aws s3api get-bucket-versioning`. We do not know if any additional parameters were passed.


??? question "What information can the attacker find out from running this command? How is it relevant to the threat actor's attack?"

    ??? tip "Hint"
        Look up the documentation for the `GetBucketVersioning` event or `get-bucket-versioning` CLI command.

    ??? info "Answer"
        This command returns the versioning state and MFA Delete status of an S3 bucket. If versioning is enabled, this makes it much more challenging to prevent the victim from being able to recover their files, since applying encryption does not retroactively encrypt old versions of files (it just creates a new version that is encrypted). MFA Delete being enabled prevents the attacker from being able to change versioning settings or permanently delete the old versions of the files without a MFA code.

Now we will look at the activity happening after the encrytion activity that we started from. The majority of the events at this point are related to snapshots. 

??? question "How many snapshots were copied? What seems to be the threat actor's intent with these actions"

    ??? tip "Hint"
        Look at API documentation to understand this event. Look at `@requestParameters` in the events for more context.

    ??? info "Answer"
        There are 4 snapshots that are copied. The threat actor appears to be attempting to encrypt the snapshots in the account using the same KMS key that was used for encrypting the buckets.

??? question "Which snapshots were deleted?"

    ??? tip "Hint"
        Filter to the `DeleteSnaphot` events and group by `@requestParameters.snapshotId`.

    ??? info "Answer"
        The following two snapshots are deleted:
        - `snap-09336c08a16457168`
        - `snap-0a5c7f52ffd2db5da`

??? question "What events may explain why 4 snapshots were copied but only 2 were deleted?"

    ??? tip "Hint"
        Look at failed events around this timeframe.

    ??? info "Answer"
        There are two `GenerateDataKeyWithoutPlaintext` error events. While there are no details on the snapshot the key was being generated for, logic would indicate that two of the snapshots were not able to be copied and encrypted, and thus the originals were not deleted by the threat actor in their destructive actions. 

Based on what we observed at the start of our investigation, there is something missing from the logs...

??? question "What activity is missing from the logs that we know happened?"

    ??? tip "Hint"
        Revisit what we found in the bucket when we logged into the console.

    ??? info "Answer"
        The ransom note was created in the bucket but there is no evidence of that upload occurring. If you visit the bucket in the console, look at the `Server access logging` and `AWS CloudTrail data events` and you'll see there's no access or data events enabled, meaning we only will see management events. 
        
        _Note_: This information can also be found directly in Datadog via the Resource Catalog based on the `logging_enabled` key in Resource Info.


If those events are missing, maybe there are other events that could be missing too. Let's review the IAM user's permissions to see what other unlogged actions could've occurred.

??? question "What permissions does the user have that would not have been logged if they did occur?"

    ??? tip "Hint"
        Go to the AWS console and look at the user in IAM.

    ??? info "Answer"

        There are two polcies attached to this user. `CloudOpsAdmins` is the one we investigated as it was added by the attacker. The only existing policy from before the attack that is attached to this user is `CloudOpsS3Access`. Along with the observed management plane events, the user had the ability to `GetObject`, `PutObject`, or `CopyObject` in S3. This means that the attacker could have downloaded or copied the data without us having a way to find out. They could have also uploaded additional files elsewhere in the account, which would require a manual audit of each bucket for recent uploads.

At this point, we've got a good feel for the flow of the attack. The threat actor did reconnaisance searching for buckets in the account, checked which accounts had versioning/MFA delete enabled, chose a target bucket to encrypt, and left behind a ransom note. We still don't know how the attacker gained access to the IAM account though.


??? question "How did the attacker authenticate in order to perform these actions?"

    ??? tip "Hint"
        Look at the accessKeyId used for the `ListBuckets` and `GetBucketVersioning` events.

    ??? info "Answer"
        The access key ID associated with the user identity is `AKIA2LIPZS7T27U6CQ24`. As discussed when we broke down access key ID prefixes, the `AKIA` prefix indicates an access key is being used.

The challenge at this point is there isn't really any evidence of _how_ the attacker got ahold of the access key. Most often threat actors steal keys that are accidentally leaked in code repositories, but it could have also been stolen from a user's laptop or cloud storage. Unless an alert from AWS or Datadog tells us an API key is leaked, the exact source of the leak is not clear. The best we can do is uncover who created the key for this `CloudOpsMonitor` account and see where the key has been shared. 

??? question "Who created the access key that has been compromised?"

    ??? tip "Hint"
        Search for the event name associated with access key creation that also contains a field (the response elements) with the identified key.

    ??? info "Answer"
        The `CreateAccessKey` event shows that `megan.fonseca@datadoghq.com` created the access key for the account.   

        _Note_: In this case the timestamps and IP and user agent align due to how the attack simulation was executed. In a real incident you might need to look further back in the logs to find the access key creation event and it's likely to have less overlap with the attacker behavior.

