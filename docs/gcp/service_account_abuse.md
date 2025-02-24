# Default Service Account Abuse in Google Cloud

## Background

SIRT has received a [Google Cloud Instance Creation via gcloud signal](https://app.datadoghq.com/security?query=%40workflow.rule.type%3A%28%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22%29%20source%3Agcp&agg_m=count&agg_m_source=base&agg_t=count&column=time&event=AwAAAZU4_Ad1_vpBkQAAABhBWlU0X0FkMUFBQURFUTUyRDlVaFR3QUEAAAAkMDE5NTM4ZmQtZjVmMC00ODRmLWEzMjktMGZmNDU3ZDIxMmY3AAAFUg&fromUser=false&order=desc&product=siem&start=1740331935795&end=1740418335795&paused=false) that has been determined to be suspicious/malicious. Investigate the signal and determine how the threat actor accessed the environment and what they did with their access.

### Logs
The logs for this lab fall within the following time frame: `<tbd>`.
We can use the following filter to focus on the CloudTrail logs in the relevant AWS account:
`source:gcp* project_id:datadog-dfir-training-2025` 

Don't forget that there are some logs that don't make it to Datadog that might be worth exploring within Google Cloud Console.

## Investigation

Start by reviewing the signal and identifying noteworthy properties that might act as pivot points to discover related activity. 

??? question "What indicators can help us track the relevant activity?"
    ??? tip "Hint"
        Take note of the following properties:   

        - IP address  
        - User ID   
        - Entities (related resources)  

    ??? info "Answer"
        - IP address: `1.1.1.1`
        - User ID: `research-512-serivce-account@datadog-dfir-training-2025.iam.gserviceaccount.com`
        - Related resources:   
            - GCE INSTANCE 1
            - GCE INSTANCE 2
            - GCE INSTANCE 3

A good starting point is to understand the nature of the activity is to identify what the service account was used for.

??? question "What actions did the service account associated with the signal take?"
    ??? tip "Hint"
        Look at the event names associated with activity where the user ID is `research-512-serivce-account@datadog-dfir-training-2025.iam.gserviceaccount.com`. You can either do this with grouping by fields in Log Explorer or using Investigator against the service account. 

    ??? info "Answer"
        There are 6 different event types associated with this account:   

        - `v1 compute.instances.insert` 
        - `iam.serviceAccounts.actAs`
        - `v1.compute.instances.get`
        - `v1.compute.projects.get`
        - `v1.compute.zoneOperations.wait`  
        - `v1.compute.zones.get` 

Most of the associated events are read-only activity, so let's focus on the first event type: `v1 compute.instances.insert`. This indicates attempts to deploy virtual machines on Google Cloud Compute.

??? question "How many virtual machines were deployed and hat are their instance names/IDs?"
    ??? tip "Hint"
        Further filter the search for the project and service account using `@evt.name:v1 compute.instances.insert`. Look at `@data.protoPayload.resourceName` and `@data.resource.labels.instance_id` for the resource names and instance IDs.

    ??? info "Answer"
        - `instance-1` (ID <insert ID>)
        - `instance-2` (ID <insert ID>)
        - `instance-3` (ID <insert ID>)

The logs don't provide full context. Let's look directly in Google Cloud at the virtual machines to see if there is anything interesting about the hosts that might point to attacker intent.

??? question "What interesting instance details could point to attacker intent?"
    ??? tip "Hint"
        Look at the `Machine configuration` and `Custom metadata`.

    ??? info "Answer"
        There's two key details of interest here:  

        1. The host has GPUs attached. Attackers often create GPU-enabled VMs for the purpose of cryptomining.
        2. There is a `startup-script` key with a bash script that downloads a file from a remote host and executes it.

Now we've determined that the threat actor's intention was likely to leverage our compute infrastructure for cryptomining or another malicious activity, we should work backwards to determine how this service account was compromised in the first place. 


??? question "How did the threat actor authenticate the service account?"
    ??? tip "Hint"
        Look at `@data.protoPayload.authenticationInfo` in any of the logs associated with the account's activity.

    ??? info "Answer"
        The authenticationInfo field shows that there is an associated `serviceAccountKeyName`, indicating a key exists for the service account and was used to authenticate the user of the account.

??? question "What is the scope of access that this account has?"
    ??? tip "Hint"
        Use Policy Analyzed in Google Cloud to understand the service account's permissions. 

    ??? info "Answer"
        The service account has an Editor role grant on the project `Datadog Dfir Training 2025`.

It appears the threat actor has gotten a copy of a service account key in order to leverage the account's editor permissions to carry out their attack. Now we need to determine how the threat actor obtained access to the key. 