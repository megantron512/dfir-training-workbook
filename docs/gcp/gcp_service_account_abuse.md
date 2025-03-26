# Default Service Account Abuse in Google Cloud

## Background

SIRT has received a [Google Cloud Instance Creation via gcloud signal](https://app.datadoghq.com/security?query=%40workflow.rule.type%3A%28%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22%29%20source%3Agcp&agg_m=count&agg_m_source=base&agg_t=count&column=time&event=AwAAAZWu1M22tVLd-QAAABhBWld1MU0yMkFBRG83eHgtZkdDTU5nQUEAAAAkMDE5NWFlZGYtMDg5Ny00YjM0LTg5MWEtM2EzMGUwY2FkMGU4AAADGA&fromUser=false&order=desc&product=siem&viz=stream&start=1742309350888&end=1742395750888&paused=false) that has been determined to be suspicious/malicious. Investigate the signal and determine how the threat actor accessed the environment and what they did with their access.

### Logs
The logs for this lab can be access via this link: [Google Cloud Project Logs](https://app.datadoghq.com/logs?query=source%3Agcp%2A%20project_id%3Adatadog-dfir-training-2025&agg_m=count&agg_m_source=base&agg_q=%40evt.name&agg_q_source=base&agg_t=count&cols=host%2Cservice&fromUser=true&messageDisplay=inline&refresh_mode=paused&storage=hot&stream_sort=desc&top_n=10&top_o=top&viz=stream&x_missing=true&from_ts=1742394300000&to_ts=1742395800000&live=false).

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
        - Multiple IP addresses:
            - `212.30.33.188`
            - `212.30.33.202`
            - `212.30.33.222`
        - User ID: `research-512-serivce-account@datadog-dfir-training-2025.iam.gserviceaccount.com`
        - Related resources:   
            - `projects/datadog-dfir-training-2025/zones/us-central1-b/instances/gpu-instance-1`
            - `projects/datadog-dfir-training-2025/zones/us-central1-b/instances/instance-1`
            - `projects/datadog-dfir-training-2025/zones/us-central1-b/instances/gpu-instance-2`

A good starting point is to understand the nature of the activity is to identify what the service account was used for.

??? question "What actions did the service account associated with the signal take?"
    ??? tip "Hint"
        Look at the event names associated with activity where the user ID is `research-512-serivce-account@datadog-dfir-training-2025.iam.gserviceaccount.com`. You can either do this with grouping by fields in Log Explorer or using Investigator against the service account. 

    ??? info "Answer"
        There are 6 different event types associated with this account:   

        - `v1 compute.instances.insert` 
        - `iam.serviceAccounts.actAs`
        - `v1.compute.instances.get`
        - `v1.compute.zoneOperations.wait`  
        - `v1.compute.zones.get` 

Most of the associated events are read-only activity, so let's focus on the first event type: `v1 compute.instances.insert`. This indicates attempts to deploy virtual machines on Google Cloud Compute.

??? question "How many virtual machines were deployed and what are their instance names/IDs?"
    ??? tip "Hint"
        Further filter the search for the project and service account using `@evt.name:v1.compute.instances.insert`. Look at `@data.protoPayload.resourceName` and `@data.resource.labels.instance_id` for the resource names and instance IDs.

    ??? info "Answer"
        - `instance-1` (`4005116539166594064`)
        - `gpu-instance-1` (`8182301838913530040`)
        - `gpu-instance-2` (`8506462674512996508`)

??? question "Why is there an error for one of the VM creation events?"
    ??? tip "Hint"
        Look at the event with `status:error`, indicated by a red bar next to log entry. Look at the response details of that event for more context.

    ??? info "Answer"
        `@data.protoPayload.response.error.message` contains the following error message:

        ```The resource 'projects/datadog-dfir-training-2025/zones/us-central1-b/instances/instance-1' already exists```

        This indicates that the instance name (`instance-1`) is non-unique within the project.


The logs don't provide full context. Let's look directly in Google Cloud at the virtual machines to see if there is anything interesting about the hosts that might point to attacker intent.

??? question "What interesting instance details could point to attacker intent?"
    ??? tip "Hint"
        Look at the `Machine configuration` and `Custom metadata`.

    ??? info "Answer"
        There's two key details of interest here:  

        1. The host has GPUs attached. Attackers often create GPU-enabled VMs for the purpose of cryptomining.
        2. There is a `startup-script` key with a bash script that downloads a file from a remote host and executes it.

        !!! note 
            The GPU usage is also present in the request details of the first `v1 compute.instances.insert` event for each instance creation. The startup script metadata implementation is _not_ visible in the event.

Now we've determined that the threat actor's intention was likely to leverage our compute infrastructure for cryptomining or another malicious activity, we should work backwards to determine how this service account was compromised in the first place. 


??? question "How did the threat actor authenticate the service account?"
    ??? tip "Hint"
        Look at `@data.protoPayload.authenticationInfo` in any of the logs associated with the account's activity.

    ??? info "Answer"
        The authenticationInfo field shows that there is an associated `serviceAccountKeyName`, indicating a key exists for the service account and was used to authenticate the user of the account.

??? question "What is the scope of access that this account has?"
    ??? tip "Hint"
        Use Policy Analyzer in Google Cloud to understand the service account's permissions. 

    ??? info "Answer"
        The service account has an Editor role grant on the project `Datadog Dfir Training 2025`.

It appears the threat actor has gotten a copy of a service account key in order to leverage the account's editor permissions to carry out their attack. There's one other "write" event from our initial list that we haven't looked at. Let's investigate that event.

??? question "What account was used to pivot to the `research-512-serivce-account@datadog-dfir-training-2025.iam.gserviceaccount.com` service account?"
    ??? tip "Hint"
        Look at the request details in the `iam.serviceAccounts.actAs` event.

    ??? info "Answer"
        The service account `222174030404-compute@developer.gserviceaccount.com` is associated with the `iam.serviceAccounts.actAs` event. Based on the naming convention of this account, its a Compute Engine default service account.


A search for that service account in the `@usr.email` or `@usr.id` field will return no results. Let's see about its presence in any other fields.

??? question "Outside of the `iam.serviceAccounts.actAs` event investigated above, what logs include a reference to the default service account?"
    ??? tip "Hint"
        Add a field for `*:222174030404-compute@developer.gserviceaccount.com`.

    ??? info "Answer"
        The only event in the results we haven't looked at doesn't have an event name and is an `undefined` service, but if you dig into the event, its a log entry associated with signal generated. It specifically is a signal for `Google Compute Engine service account used outside of Google Cloud`. If you expand the `Log Message` you can `View Security Signal`, which will provide a more readable view in Signal Explorer.

??? question "What events are associated with the signal?"
    ??? tip "Hint"
        Don't look at the `Related Logs` section; instead view the `@evt.name` list in the JSON.

    ??? info "Answer"
        Three events were tied to the signal:
        - `storage.buckets.list`
        - `storage.objects.list` 
        - `storage.objects.get`

        !!! note
            Because of the log indexing and exclusion filters discussed in the training, the full list of logs is not provided, only a single sample event (`storage.objects.get` in this case).

Since we can't see the details of the storage logs in Datadog, let's log into the Google Cloud console and use their native Log Explorer to review these events. Set your time range to 14:15 (2:15 PM) - 14:45 (2:45 PM) UTC on 3/19/2025 to ensure the expected activity is included.

??? question "What tool/program was used to perform the bucket-related actions?"
    ??? tip "Hint"
        Use the following search to narrow down the logs:
        ```
        resource.type="gcs_bucket"
        protoPayload.authenticationInfo.principalEmail="222174030404-compute@developer.gserviceaccount.com"
        ```
        Look at the user agent field of any of the events.

    ??? info "Answer"
        The user agent associated with the `requestMetadata` is `curl/8.1.2,gzip(gfe)`, indicating the usage of `curl` to perform the API calls to Google Cloud Storage.

??? question "After listing the buckets, which bucket was targeted with the `storage.objects.list` method?"
    ??? tip "Hint"
        Look at the resource name in the associated event.

    ??? info "Answer"
        The targeted bucket is `research-512-resources`.


??? question "Which file was downloaded from the above bucket?"
    ??? tip "Hint"
        Look at the resource name in a `storage.objects.get` event.

    ??? info "Answer"
        The targeted bucket is `research-512-service-account-creds.json`. Based on the name, there is a good chance this file contains credentials for the service account observed in the initial signal and is how the attacker was able to pivot.

At this point we've figured out that the attacker used the default service account to obtain creds stored in a bucket. Those creds were then used to deploy GPU instances. The remaining unanswered question is how did the attacker gain access to the default service account. We've looked for the account being referenced in all fields in Datadog already and there were no results. Let's look across all logs in Google Cloud in case there are other logs not collected by Datadog.

??? question "What resource is associated with the additional event?"
    ??? tip "Hint"
        Remove any other filters and field names from your search and just run a string search for `"222174030404-compute@developer.gserviceaccount.com"`. Look at the `resource` section of the log entry.

    ??? info "Answer"
        The associated resource is a container named `vulnerable-java-application-1` running on a cluster called `cluster-1`.   


??? question "What does the message tell us about how the attacker authenticated?"
    ??? tip "Hint"
        Look at the message field on the aforementioned event.

    ??? info "Answer"
        The message indicates that somewhere within the container's app, the attacker was able to inject the string `google.com>/dev/null && curl -H Metadata-Flavor:Google 169.254.169.254/computeMetadata/v1/instance/service-accounts/222174030404-compute@developer.gserviceaccount.com/token`. This is an attempt by the attacker to query the metadata service for the token associated with the service account, which is how they were able to proceed with their next steps.


??? question "Did the threat actor attempt to execute any other commands?"
    ??? tip "Hint"
        Search for `resource.labels.container_name="vulnerable-java-application-1"` to retrieve all of the application logs.

    ??? info "Answer"
        Prior to running the curl command to get the token, the following command was executed: `curl -H Metadata-Flavor:Google 169.254.169.254/computeMetadata/v1/instance/service-accounts/`. This would have returned a list of service accounts attached to the container/cluster, which is how they got the user ID needed to retrieve the token.

To prevent this vulnerable app from being exploited by a real threat actor, it's since been torn down. If further investigation into the container/cluster could have been performed, you would find that the vulnerable app was exposed as a service open to the world. 

To recap, the threat actor's attack path was to exploit a public container in order to query the metadata service and obtain the default service account token. This token had effective permissions (based on access scope) that allowed it to be used to query all buckets and their objects within the project. One of the buckets contained a credential file that could be used to authenticate as a service account with editor permissions at the project-level. The permissions were used to deploy GPU-enabled VMs.