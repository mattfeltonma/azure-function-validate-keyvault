# Azure Key Vault Compliance Checker
This solution demonstrates a design pattern where Azure Functions are used to extend the capability of Azure Policy to the data plane of Azure Key Vault.  The Azure Key Vault instances within an Azure subscription are scanned to validate that each secret and key have an expiration set.

## What problem does this solve?
[Azure Policy](https://docs.microsoft.com/en-us/azure/governance/policy/overview) is a service used to monitor and enforce governance and compliance in Microsoft Azure.  At this time its ability to monitor the data plane of Azure resources such as Azure Key Vault is limited.  Many compliance frameworks such as [CIS](https://www.cisecurity.org/) have controls which may require specific configuration settings that are set at the data plane.  As an example the [CIS Azure Foundations Benchmarks](https://www.cisecurity.org/blog/cis-microsoft-azure-foundations-benchmark-v1-0-0-now-available/) include a recommendation for having an expiration set for keys and secrets stored in Key Vault.  Azure Policy can be extended into monitoring the data plane by using a combination of [Azure Functions](https://azure.microsoft.com/en-us/services/functions/) and [Resource Tags](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-using-tags).

This solution uses an Azure Function written in Python to list the keys and secrets of each Azure Key Vault within a subscription.  The function is triggered with an HTTP request which includes a query parameter with the subscription ID.  Each secret and key is checked to see whether the expiration date is set.  Key Vault instances containing keys or secrets without an expiration date are tagged with a tag of Compliant with a value of False.  Key Vault instances where all keys and secrets have an expiration date are tagged with a tag of Compliant with a value of True.  If the Azure Function is unable to access the Key Vault to perform a list keys or list secrets it is tagged with a tag of Compliant with a value of Error.  Additionally, the results of the function are returned as an HTTP response and include the id for any secret or key that does not have an expiration date set.  Once the tags are set, Azure Policy can be used to monitor for Vaults which do not have the Compliance tag set to True.

The [authentication and authorization](https://docs.microsoft.com/en-us/azure/app-service/overview-authentication-authorization) capabilities for Azure App Services is not yet available for the Azure Function Consumption Plan for Linux.  To help ensure the function can only be started by a trusted party, it is configured to use [function-specific API keys](https://docs.microsoft.com/en-us/azure/app-service/overview-authentication-authorization).

## Requirements

### Python Runtime and Modules
* [Python 3.6.X](https://www.python.org/downloads/release/python-360/)
* [Requests 2.22.0](https://realpython.com/python-requests/)

### Azure Requirements
* [Python Azure Function](https://docs.microsoft.com/en-us/azure/azure-functions/functions-create-first-function-python)
* [System-assigned Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) for the function
* Custom RBAC role contained in this repo
* [Gets Keys permission](https://docs.microsoft.com/en-us/rest/api/keyvault/getkeys) and [Get Secrets permission](https://docs.microsoft.com/en-us/rest/api/keyvault/getsecrets) granted on [access policy](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-secure-your-key-vault) for each Key Vault
* Function Application Settings below
  * "KV_API_VERSION": "7.0"
  * "KV_MGMT_API_VERSION": "2018-02-14"
  * "MGMT_API_VERSION": "2019-08-01"
  * "MSI_API_VERSION": "2017-09-01"

## Setup
1. Create new Python Azure Function with Azure Function Consumption Plan for Linux
2. Add the Application Settings in the Azure Requirements section
3. Enable system-assigned managed identity for the function
4. Grant the system-assigned identity Get Keys and List Keys permissions on each Azure Key Vault instance
5. Add the custom RBAC role included in this repository and create a role assignment at the subscription level or above for the system-assigned identity

## Example

https://<function_app_name>.azurewebsites.net/api/<function_name>?code=<FUNCTION_API_KEY>&subscription=<SUBSCRIPTION_ID>

