# Lab 1: AWS Authentication at Datadog

This lab is to begin understanding what authentication looks like in the logs when users accesss AWS using SSO. 

Before walking through the questions below, navigate to the [AWS access portal](https://d-906757b57c.awsapps.com/start/#/?tab=accounts) and search for the `datadog-dfir-training-2025` account. Access it using the `security-admin` role. Within a few minutes, associated logs should be generated and shipped to the Datadog.

## Goal
The primary goal of this lab is to identify all event types that are generated when a Datadog user signs in with SSO. The upcoming slides in the training will go into detail about these events, but see what you can find yourself before we cover any gaps! 

If you think you've identified all relevant log entries, as a bonus challenge, identify other types of authentication that are occuring and notable properties associated with those events that could assist in investigating malicious activity. 