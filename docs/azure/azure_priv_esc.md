# Azure Privilege Escalation
## Background
SIRT has received a [Azure AD member assigned Global Administrator role](https://app.datadoghq.com/security?query=%40workflow.rule.type%3A%28%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22%29%20source%3Aazure&agg_m=count&agg_m_source=base&agg_t=count&column=time&event=AwAAAZW5z0WMsD8eaQAAABhBWlc1ejBXTUFBQ1lIZHUyVnhISFF3QUEAAAAkMDE5NWJhNDctNTZhZS00ZTU4LTgyYjctMmVmMDg5MTQ2OWZkAAAAFA&fromUser=false&order=desc&product=siem&start=1742303529700&end=1742908329700&paused=false) **in the Security Research Datadog Org** that has been determined to be suspicious/malicious. Investigate the signal and determine the extent of the threat actor's activity.

### Logs
The timestamps for searches can be access via this link in the **Security Research** Datadog org: [Azure Logs](https://app.datadoghq.com/logs?query=source%3Aazure%2A&agg_m=count&agg_m_source=base&agg_t=count&clustering_pattern_field_path=message&cols=host%2Cservice&fromUser=true&messageDisplay=inline&refresh_mode=paused&storage=hot&stream_sort=desc&viz=stream&from_ts=1742572800000&to_ts=1742581800000&live=false). Further filters based on the originating signal will be required to narrow down the relevant activity.

## Investigation
Start by reviewing the triggering event and understanding what is happening. 

??? question "Which user was granted the global admin role?"
    ??? tip "Hint"
        Look at target resources to find the context of what changes were made.

    ??? info "Answer"
        `@properties.targetResources.userPrincipalName` tells us that `devindeveloper@pdedatadogoutlook.onmicrosoft.com` was granted global admin privileges.


??? question "What field gives us some insight into how the role was granted?"
    ??? tip "Hint"
        Look for an indication the program leveraged to perform these actions.

    ??? info "Answer"
        Based on `@properties.additionalDetails` the user agent associated with this request is `python-requests/2.23.0`. This tells us that the python requests library was used, indicating the attacker is likely executing a script to make requests to the API.

??? question "Which principal is responsible for granting the global admin role?"
    ??? tip "Hint"
        Look at the user associated with the event.

    ??? info "Answer"
        `DFIR Training - Top Dog Role Management` is the user that executed the action to grant the admin role. 

We know the principal performing the suspicious activity so let's see what other events can be tied to the user. 

??? question "What other events are present for the principal?"
    ??? tip "Hint"
        Execute a new search that focuses on Azure logs for the user `DFIR Training - Top Dog Role Management`.

    ??? info "Answer"
        There are two additional events tied to this principal, both are sign-in events.

??? question "What additional evidence seen in both of these events supports our finding that Python scripts may be in use by the threat actor?"
    ??? tip "Hint"
        Look for additional references to Python.

    ??? info "Answer"
        The `@properties.authenticationProcessingDetails` field indicates that the authentication library that processed this request is MSAL Python.

??? question "What additional evidence seen in both of these events supports our finding that Python scripts may be in use by the threat actor?"
    ??? tip "Hint"
        Look for additional references to Python.

    ??? info "Answer"
        The `@properties.authenticationProcessingDetails` field indicates that the authentication library that processed this request is MSAL Python.

??? question "What is the key difference between the two sign-in events that indicates why both events are present in a short period?"
    ??? tip "Hint"
        Focus on the resource associated with the authentication.

    ??? info "Answer"
        The `@properties.resourceDisplayName` field is different between the events. One is associated with `Azure Resource Manager` and the other is associated with `Graph API`.

We've reviewed all the activity tied to this service principal as the initiating actor but are still missing a lot of context. Let's broaden our search to find the presence of that principal in _any_ field. 

??? question "What is the earliest event that references the service principal?"
    ??? tip "Hint"
        Filter by `*:DFIR Training - Top Dog Role Management` and look at the timestamps to identify earliest event.

    ??? info "Answer"
        The first event is `Update service principal`. 

??? question "Which user is associated with this activity?"
    ??? info "Answer"
        `@usr.name` tells us `devindeveloper@pdedatadogoutlook.onmicrosoft.com` is the user performing the actions. This is interesting because before this user was the target of actions by the service prinicipal, whereas now the service principal is the target of the user.

??? question "What attribute differs from our previous events that provides insight into the methodology of the attacker?"
    ??? tip "Hint"
        Previously Python was in usage but we see a different access vector this time.

    ??? info "Answer"
        The `@properties.additionalDetails` field indicates that the user agent is `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0`. This indicates that these activities are taking place via a browser vs. a script.

This event alone does not provide a lot of additional context in its details. Let's understand the chain of events associated with this single one.

??? question "What other events are directly associated with this one?"
    ??? tip "Hint"
        The correlation ID can be used to tie together associated events.

    ??? info "Answer"
        2 additional events are associated with the same correlation ID:   
        -  `Update application – Certificates and secrets management`   
        - `Update application`

Let's start with the earliest of these additional events to see if we can expand our understanding of what is happening.

??? question "Which application was assigned a credential?"
    ??? tip "Hint"
        Look at the target resource.

    ??? info "Answer"
        The application that had a secret generated is `DFIR Training - Top Dog Role Management`, which is the application that the service principal we've observed is tied to.

??? question "What is the display name of the key?"
    ??? tip "Hint"
        Look at the target resource's modified properties.

    ??? info "Answer"
        The key description that was updated is `["[KeyIdentifier=480946b1-433f-4634-8b85-bfe21266007e,KeyType=Password,KeyUsage=Verify,DisplayName=test]"]`. We can see within that string that the display name is `test`.   


??? question "What is the other name for a key type of `Password`?"
    ??? tip "Hint"
        Check out Microsoft's documentation for [adding credentials](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=federated-credential%2Cexpose-a-web-api#add-credentials).

    ??? info "Answer"
        As can be seen with a Google search, at the reference link in the hint, or by going directly to the portal, there is no options to "Add password". The documentation mentions the following:  
        ```
        Sometimes called an application password, a client secret is a string value your app can use in place of a certificate to identify itself.
        ```    
        While the log references `password`, in the UI we would be adding a `client secret`. 
    
Feel free to look at the final `Update application` event but it does not provide any additional context that will assist in the investigation. Let's look at the credential that was created next.

??? question "What was the created key used for?"
    ??? tip "Hint"
        Run a search for the key identifier from the last question present in any field (using `*:`).

    ??? info "Answer"
        The key appears as `@properties.servicePrincipalCredentialKeyId` in the sign-in events that were previously reviewed. 

!!! warning 
    The below timeline should only be reviewed after completing the previous steps otherwise it will give away answers.

??? note "Timeline"
    Based on this information we know the following sequence of events:  
    1. `devindeveloper@pdedatadogoutlook.onmicrosoft.com` updates an application to associate a client secret with `DFIR Training - Top Dog Role Management`.    
    2. `DFIR Training - Top Dog Role Management` logs in using the client secret generated in step 1.   
    3. `DFIR Training - Top Dog Role Management` grants `devindeveloper@pdedatadogoutlook.onmicrosoft.com` global admin role.

The next step from here is to find out what the user did with the newly-granted global admin permissions. Since we see no more activity for the user account when searching for `@usr.name`, let's once again broaden the search via a wildcard field name search.

??? question "Excluding sign-in activity, what additional results are returned for the user in the broadened search?"
    ??? tip "Hint"
        Filter by `*:devindeveloper@pdedatadogoutlook.onmicrosoft.com` and look at unique event names.

    ??? info "Answer"
        The following events have not yet been reviewed:  

        - `User has elevated their access to User Access Administrator for their Azure Resources`   
        - `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`    
        - `MICROSOFT.SERIALCONSOLE/SERIALPORTS/CONNECT/ACTION`   
        - `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION`    
        - `Admin registered security info`

We'll review events in chronological order to find out what the threat actor did after receiving global admin access. The first event is the access elevation to User Access Administrator.

??? question "How does User Access Administrator differ from Global Admin?"
    ??? tip "Hint"
        Google or use GenerativeAI to learn about the difference.

    ??? info "Answer"
        Global admin is an **EntraID role** allowing management of EntraID users, groups, apps, and settings. It does not give access over all subscriptions and resource. User access administrator is an **RBAC role** and allows for viewing resources and assigning access at the subscription/resource level.

        As per [Microsoft documenation](https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-portal%2Centra-audit-logs#how-does-elevated-access-work):

        > Microsoft Entra ID and Azure resources are secured independently from one another. That is, Microsoft Entra role assignments do not grant access to Azure resources, and Azure role assignments do not grant access to Microsoft Entra ID. 

Now let's look at the resource management events to understand interactions with resources in our environment.

??? question "Why are there multiple events for each event type we observed (i.e. what is the key difference the events with the same type)?"
    ??? tip "Hint"
        Look at the fields in each one and identify a field that changes value and helps determine why there is multiple.

    ??? info "Answer"
        The `@evt.outcome` field shows us that these logs are indicating various "stages" of the action being taken; for example, `Start` followed by `Success`. The `Start` events show more context, so make sure you review those events specifically for the next set of questions.

??? question "With regards to the role assignment write event, what role was assigned (not the ID, the role name)?"
    ??? tip "Hint"
        Use Google to find context around the role definition ID located in the request body.

    ??? info "Answer"
        A quick Google search should inform you that the ID `b24988ac-6180-42a0-ab88-20f7382dd24c` is associated with the built-in `Contributor` role. 

??? question "Which principal/user was the role assigned to?"
    ??? tip "Hint"
        Take the principal ID from the request body and reference other logs from our investigation to tie that to an identity.

    ??? info "Answer"
        Other logs show us that `1606d62c-71bc-42ff-a03c-87809c6b0e68` is the ID associated with the `devindeveloper@pdedatadogoutlook.onmicrosoft.com` user.

??? question "What is the scope of the role?"
    ??? tip "Hint"
        
        Look at the request body again.

    ??? info "Answer"
        The request body specifies `subscriptions/fa3f98d4-2d5c-44ae-950f-ecbb74b5fab6` as the scope, meaning that Contributor permissions are granted to the user for the subscription and all resource groups and resources within.

??? question "What role provided the user with the ability to perform the role assignment?"

    ??? tip "Hint"
        Look at the identity information.

    ??? info "Answer"
        The `@identity.authorization.evidence.role` field tells us that the User Access Administrator role we previously saw `devindeveloper@pdedatadogoutlook.onmicrosoft.com` escalate to. 

The next event in the sequence is related to serial console access.

??? question "Which host did the attacker attempt to connect to the serial port on?"

    ??? tip "Hint"
       Look at the resource ID that represents a virtual machine.

    ??? info "Answer"
        The `@properties.entity` field indicates that `SpotVM` is the target of the serial port connect action.

The outcome fields in the logs lead us to believe the connection was successful. In reality, however, although the attacker was able to connect to the console, a network error due to network security rules prevented them from being able to actually interact with the host. At this point, it appears they took a different approach.

??? question "What does the presence of a RUNCOMMAND event indicate?"

    ??? tip "Hint"
       Research via Google or GenAI.

    ??? info "Answer"
        This indicates an attempt to run scripts on the virtual machine.

??? question "Which VM was the target of the RUNCOMMAND event?"

    ??? info "Answer"
        `@resource_name` shows that the threat actor is still targeting the SpotVM host, which makes sense if their serial console usage failed.

??? question "What context is missing and how can we find it?"

    ??? tip "Hint"
       What unanswered questions do we have in the context of this specific event that does not appear in the event details. Google to understand where that information is.

    ??? info "Answer"
        We don't know what scripts and commands were run via this action. Those events are not logged due to security reasons. To find that information, we would have to analyze the host that was targted. The following reference can provide more details on finding evidence of command execution: [Azure Run Command for Dummies](https://cloud.google.com/blog/topics/threat-intelligence/azure-run-command-dummies/)

One line of investigation we did not assess is the initial access vector for the user account that ultimately escalated privileges. The simulation for this lab did not include that activtiy and so we can make assumptions that the credentials were phished or something similar. In any other attack we would need to work backwards in time to identify the initial access vector.

# Attack Walkthrough
These labs were developed by Katie Knowles and she has graciously developed a [write-up](https://datadoghq.atlassian.net/wiki/spaces/~712020c4a4c505c6e144cd9e42314f3e9b4603/pages/4890951947/Attacker+Perspectives+Azure+SP+Attack+Paths) and [video walkthrough](https://drive.google.com/file/d/1lA8VPm6_vwSDOAgJxu9HaSAZPbxS4U11/view?usp=drive_link) from the attacker perspective so you can understand better what actions were taken and why, and what visibility gaps may be present. 
