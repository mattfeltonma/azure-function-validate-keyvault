import datetime
import logging
import requests
import sys
import os
import json
from datetime import datetime, timezone
 
import azure.functions as func
 
# Reusable function to obtain access token using Managed Identity
def get_token(resource):
 
    # Set query parameters
    query_params = {
        'api-version': os.environ['MSI_API_VERSION'],
        'resource': resource
    }
 
    # Create the authentication header
    headers = {
        'secret': os.environ['MSI_SECRET']
    }
 
    # Issue the Get request to retrieve the access token
    response = requests.get(
        url=os.environ['MSI_ENDPOINT'],
        headers=headers,
        params=query_params
    )
 
    # Parse the response
    data = json.loads(response.text)
 
    # Validate that the response contains an access token and if not throw an exception
    if response.status_code == 200:
        token = data['access_token']
        return token
    else:
        logging.error("Unable to obtain access token")
        logging.error(f"Error was: {data['error']}")
        logging.error(f"Error description was: {data['error_description']}")
        logging.error(f"Error correlation_id was: {data['correlation_id']}")
        raise Exception('Failed to obtain access token')
 
# Convert the offset to a readable timestamp
def convert_time(utc_offset):
    utctimestamp = datetime.fromtimestamp(utc_offset, timezone.utc)
    return utctimestamp
 
# Query Azure REST API
def rest_api_request(action, url, token, query_params=None, tag_update=None):
 
    try:
 
        # Create authorization header
        headers = {'Content-Type': 'application/json',
                   'Authorization': 'Bearer {0}'.format(token)}
 
        # Issue Get request to API
        if action == 'get':
            logging.info(f"Issuing GET request to {url}")
            response = requests.get(
                headers=headers,
                url=url,
                params=query_params
            )
 
        # Issue Patch request to API to add or modify tags
        elif action == 'patch':
            logging.info(f"Issuing PATCH request to {url}")
            response = requests.patch(
                headers=headers,
                url=url,
                params=query_params,
                data=(json.dumps(tag_update))
            )
 
        # Validate that response is 200 (OK)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            logging.error('Error encountered querying Azure API')
            logging.error(
                f"Error code was: {(json.loads(response.text))['error']['code']}")
            logging.error(
                f"Error message was: {(json.loads(response.text))['error']['message']}")
            raise Exception
 
    except Exception:
        return json.loads(response.text)
 
def main(req: func.HttpRequest) -> func.HttpResponse:
 
    try:
        # Configure logging format
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        )
 
        # Application variables
        mgmt_api_version = os.environ['MGMT_API_VERSION']
        kv_mgmt_api_version = os.environ['KV_MGMT_API_VERSION']
        kv_api_version = os.environ['KV_API_VERSION']
        subscription_id = req.params.get('subscription')
        # Retrieve access token for Azure Resource Management API
        logging.info('Requesting acess token for Azure Resource Management API...')
        mgmt_api_token = get_token(
            resource='https://management.azure.com/'
        )
 
        # Retrieve access token for Key Vault API
        logging.info('Requesting acess token for Key Vault API...')
        keyvault_api_token = get_token(
            resource='https://vault.azure.net'
        )
 
        # Initialize empty array to store Key Vault instances
        vaults = []
 
        # Request a listing of Key Vault instances in a subscription
        query_params = {
            'api-version': mgmt_api_version,
            '$filter': "resourceType eq 'Microsoft.KeyVault/vaults'"
        }
 
        # Issue query to Azure REST API for listing of Key Vault instances
        vaults_response = rest_api_request(
            action='get',
            url=f"https://management.azure.com/subscriptions/{subscription_id}/resources",
            token=mgmt_api_token,
            query_params=query_params
        )
        vaults = vaults_response['value']
 
        # Handle paging when being returned listing of Key Vault instances
        while 'nextLink' in vaults_response:
            logging.info('Paged results returned...')
            vaults_response = rest_api_request(
                action='get',
                url=vaults_response['nextLink'],
                token=mgmt_api_token
            )
            vaults += vaults_response['value']
 
        # Initialize empty list to hold key and secret metadata
        key_vault_object_metadata = []
 
        # Set the query paramater for requests to the Key Vault API
        query_params = {
            'api-version': kv_api_version
        }
 
        # Initalize an empty list to hold compliance results
        compliance_results = []
 
        # Iterate through each Key Vault instance and evaluate key and secret metadata to determine if expiration date is set
        for vault in vaults:
 
            # Initialize an empty list to hold keys or secrets that do not have an expiration
            records = []
 
            # Initialize Vault Error Boolean
            vault_error = False
 
            for kv_object_type in ['keys','secrets']:
 
                # Get listing of metadata about keys
                response = rest_api_request(
                    action='get',
                    url=f"https://{vault['name']}.vault.azure.net/{kv_object_type}",
                    token=keyvault_api_token,
                    query_params=query_params
                )
 
                # Analyze the response to see if it was an error
                if 'error' not in response:
 
                    # Iterate through each secret or key and check to see if it has an expiration
                    for kv_object in response['value']:
                        if 'exp' not in kv_object['attributes']:
 
                            # Add keys or secrets without expirations to a list
                            record = {
                                'enabled':kv_object['attributes']['enabled'],
                                'age': ((datetime.now(timezone.utc) - (convert_time(kv_object['attributes']['created']))).days)
                            }
 
                            # Logic to handle different attributes returned by key vs secret
                            if kv_object_type == 'keys':
                                record['data_id'] = kv_object['kid']
                                record['data_type'] = 'key'
                            else:
                                record['data_id'] = kv_object['id']
                                record['data_type'] = 'secret'
 
                            # Append the record to the list
                            records.append(record)
 
                # If there is an error the Key Vault instance will be marked with a compliance status of error
                else:
                    vault_error = True
 
            # Create a compliance result for the vault indicating either keys or secrets could not be listed
            if vault_error == True:
                compliance_result = {
                    'key_vault': vault['name'],
                    'vault_id': vault['id'],
                    'message': f"Unable to list keys or secrets for Key Vault instance.",
                    'records': [],
                    'tags': vault['tags']
                    }
                compliance_results.append(compliance_result)
 
            # Create a compliance result for the vault listing out with the non-compliant keys or secrets
            elif len(records):
                compliance_result = {
                    'key_vault': vault['name'],
                    'vault_id': vault['id'],
                    'message': f"Key Vault instance contains non-compliant keys or secrets.",
                    'records': records,
                    'tags': vault['tags']
                    }
                compliance_results.append(compliance_result)
            
            else:
                compliance_result = {
                    'key_vault': vault['name'],
                    'vault_id': vault['id'],
                    'message': f"Key Vault instance is compliant.",
                    'records': [],
                    'tags': vault['tags']
                    }
                compliance_results.append(compliance_result)
 

        logging.info('Tagging resources...')
 
        # Tag resources as appropriate
        for compliance_result in compliance_results:
 
            # Tag non-compliant resources
            if len(compliance_result['records']):
                if 'Compliant' not in compliance_result['tags']:
                    logging.info(f"Tagging {compliance_result['key_vault']} as non-compliant")
                    tag_response = rest_api_request(
                        action='patch',
                        url=f"https://management.azure.com{compliance_result['vault_id']}",
                        token = mgmt_api_token,
                        query_params= {
                            'api-version':kv_mgmt_api_version
                        },
                        tag_update={
                            'tags': {
                                'Compliant':'False'
                            }
                        }
                    )
                elif compliance_result['tags']['Compliant'] != 'False':
                    logging.info(f"Tagging {compliance_result['key_vault']} as non-compliant")
                    tag_response = rest_api_request(
                        action='patch',
                        url=f"https://management.azure.com{compliance_result['vault_id']}",
                        token = mgmt_api_token,
                        query_params= {
                            'api-version':kv_mgmt_api_version
                        },
                        tag_update={
                            'tags': {
                                'Compliant':'False'
                            }
                        }
                    )
 
            # Tag resources with error
            elif 'Unable to' in compliance_result['message']:
                if 'Compliant' not in compliance_result['tags']:
                    logging.info(f"Tagging {compliance_result['key_vault']} as Error")
                    tag_response = rest_api_request(
                        action='patch',
                        url=f"https://management.azure.com{compliance_result['vault_id']}",
                        token = mgmt_api_token,
                        query_params= {
                            'api-version':kv_mgmt_api_version
                        },
                        tag_update={
                            'tags': {
                                'Compliant':'Error'
                            }
                        }
                    )
                elif compliance_result['tags']['Compliant'] != 'Error':
                    logging.info(f"Tagging {compliance_result['key_vault']} as Error")
                    tag_response = rest_api_request(
                        action='patch',
                        url=f"https://management.azure.com{compliance_result['vault_id']}",
                        token = mgmt_api_token,
                        query_params= {
                            'api-version':kv_mgmt_api_version
                        },
                        tag_update={
                            'tags': {
                                'Compliant':'Error'
                            }
                        }
                    )
            else:
                # Tag compliant resources
                if 'Compliant' not in compliance_result['tags']:
                    logging.info(f"Tagging{compliance_result['key_vault']} as compliant")
                    tag_response = rest_api_request(
                        action='patch',
                        url=f"https://management.azure.com{compliance_result['vault_id']}",
                        token = mgmt_api_token,
                        query_params= {
                            'api-version':kv_mgmt_api_version
                        },
                        tag_update={
                            'tags': {
                                'Compliant':'True'
                            }
                        }
                    )
                elif compliance_result['tags']['Compliant'] != 'True':
                    logging.info(f"Tagging {compliance_result['key_vault']} as compliant")
                    tag_response = rest_api_request(
                        action='patch',
                        url=f"https://management.azure.com{compliance_result['vault_id']}",
                        token = mgmt_api_token,
                        query_params= {
                            'api-version':kv_mgmt_api_version
                        },
                        tag_update={
                            'tags': {
                                'Compliant':'True'
                            }
                        }
                    )
 
        return func.HttpResponse(json.dumps(compliance_results))
 
    except Exception as e:
        return func.HttpResponse(
            f"Exception occurred: {e}",
            status_code=400
        )
 