# hubspot.py

from datetime import datetime
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import requests
import urllib.parse

from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

'''All the following values must match configuration settings in the hubspot app.

They will be used to build the OAuth URL, which users visit to begin Installing. If they don't match your app's configuration, users will see an error page.'''

CLIENT_ID = 'b1788c74-4f07-4e46-8c3a-ed1336ba08ea'
CLIENT_SECRET = '27f198e7-8028-4435-81b5-1c146f3e0983'

# Set the required scopes separated by spaces
SCOPES = 'crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read'

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    # Replace spaces in the SCOPES string with %20
    scopes = urllib.parse.quote(SCOPES)

    authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={scopes}&state={encoded_state}'

    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)

    return authorization_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error'))
    
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')
    
    async with httpx.AsyncClient() as client:
        response_body, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uri': REDIRECT_URI,
                    'code': code
                    }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )

    '''The response contains the refresh_token, access_token and an expires_in field which indicates when the access token will expire.
    
    Based on the airtable and notion architecture, as the credentials stored in the Redis Server are set to expire in 600 seconds, we do not need to obtain a new access token using the refresh_token.'''
         
    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response_body.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)
    
async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

# Use the hubspot contacts API to retrieve all contacts in an account
def fetch_all_contacts(access_token: str, url: str, aggregated_response: list, vidOffset=None) -> dict:

    params = {'vidOffset': vidOffset} if vidOffset is not None else {}
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        }
    parameters = urllib.parse.urlencode(params)
    get_url = f'{url}?{parameters}' if parameters else url
    response = requests.get(url=get_url, headers=headers)

    if response.status_code == 200:
        results = response.json().get('contacts', None)
        has_more = response.json().get('has-more', None)
        vidOffset = response.json().get('vidOffset', None)

        for item in results:
            aggregated_response.append(item)

        # If pagination is enabled, has_more will be true and we need to retrieve next set of contacts
        if has_more:
            fetch_all_contacts(access_token, url, aggregated_response, vidOffset)
        else:
            return

# Use the hubspot companies API to retrieve all companies in an account
def fetch_all_companies(access_token: str, url: str, aggregated_response: list, offset=None) -> dict:

    params = {'offset': offset,'properties':'name'} if offset is not None else {'properties':'name'}
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        }
    parameters = urllib.parse.urlencode(params)
    get_url = f'{url}?{parameters}'
    
    response = requests.get(url=get_url, headers=headers)

    if response.status_code == 200:
        results = response.json().get('companies', None)
        has_more = response.json().get('has-more', None)
        offset = response.json().get('offset', None)

        for item in results:
            aggregated_response.append(item)

        # If pagination is enabled, has_more will be true and we need to retrieve next set of companies
        if has_more:
            fetch_all_companies(access_token, url, aggregated_response, offset)
        else:
            return

# Use the hubspot deals API to retrieve all deals in an account
def fetch_all_deals(access_token: str, url: str, aggregated_response: list, offset=None) -> dict:

    params = {'offset': offset, 'properties':'dealname'} if offset is not None else {'properties':'dealname'}
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        }
    parameters = urllib.parse.urlencode(params)
    get_url = f'{url}?{parameters}'

    response = requests.get(url=get_url, headers=headers)

    if response.status_code == 200:
        results = response.json().get('deals', None)
        has_more = response.json().get('hasMore', None)
        offset = response.json().get('offset', None)

        for item in results:
            aggregated_response.append(item)

        # If pagination is enabled, has_more will be true and we need to retrieve next set of deals
        if has_more:
            fetch_all_deals(access_token, url, aggregated_response, offset)
        else:
            return

def create_integration_item_metadata_object(response_json: str, item_type: str) -> IntegrationItem:

    if item_type == "Contact":
        id = response_json.get('vid', None)

        if 'addedAt' in response_json and response_json['addedAt'] is not None:
            creation_time = datetime.utcfromtimestamp(response_json['addedAt']/1000).strftime('%Y-%m-%d %H:%M:%S')
        else:
            creation_time = None

        if 'properties' in response_json and response_json['properties'] is not None:
            properties = response_json['properties']
            if 'firstname' in properties and properties['firstname'] is not None:
                firstname = properties['firstname']
                if 'value' in firstname and firstname['value'] is not None:
                    name = firstname['value']
                else:
                    name = None
            else:
                name = None
    
            if 'lastmodifieddate' in properties and properties['lastmodifieddate'] is not None:
                lastmodifieddate = properties['lastmodifieddate']
                if 'value' in lastmodifieddate and lastmodifieddate['value'] is not None:
                    last_modified_time = datetime.utcfromtimestamp(int(lastmodifieddate['value'])/1000).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_modified_time = None
            else:
                last_modified_time = None
        else:
            name = None
            last_modified_time = None

        integration_item_metadata = IntegrationItem(
            id = id,
            name = name,
            type = item_type,
            creation_time = creation_time,
            last_modified_time = last_modified_time
            )
        
    elif item_type == "Company":
        id = response_json.get('companyId', None)

        if 'properties' in response_json and response_json['properties'] is not None:
            properties = response_json['properties']
            if 'name' in properties and properties['name'] is not None:
                company_name = properties['name']
                if 'value' in company_name and company_name['value'] is not None:
                    name = company_name['value']
                else:
                    name = None
                if 'timestamp' in company_name and company_name['timestamp'] is not None:
                    creation_time = datetime.utcfromtimestamp((company_name['timestamp'])/1000).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    creation_time = None
            else:
                name = None
                creation_time = None
        else:
            name = None
            creation_time = None

        integration_item_metadata = IntegrationItem(
            id = id,
            name = name,
            type = item_type,
            creation_time = creation_time
            )

    elif item_type == "Deal":
        id = response_json.get('dealId', None)

        if 'properties' in response_json and response_json['properties'] is not None:
            properties = response_json['properties']
            if 'dealname' in properties and properties['dealname'] is not None:
                deal_name = properties['dealname']
                if 'value' in deal_name and deal_name['value'] is not None:
                    name = deal_name['value']
                else:
                    name = None
                if 'timestamp' in deal_name and deal_name['timestamp'] is not None:
                    creation_time = datetime.utcfromtimestamp((deal_name['timestamp'])/1000).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    creation_time = None
            else:
                name = None
                creation_time = None
        else:
            name = None
            creation_time = None

        integration_item_metadata = IntegrationItem(
            id = id,
            name = name,
            type=item_type,
            creation_time = creation_time
            )
    
    return integration_item_metadata
    

async def get_items_hubspot(credentials) -> list[IntegrationItem]:

    credentials = json.loads(credentials)
    contacts_url = 'https://api.hubapi.com/contacts/v1/lists/all/contacts/all'
    companies_url = 'https://api.hubapi.com/companies/v2/companies/paged'
    deals_url = 'https://api.hubapi.com/deals/v1/deal/paged'

    list_of_integration_item_metadata = []

    list_of_contact_responses = []
    list_of_companies_responses = []
    list_of_deals_responses = []

    fetch_all_contacts(credentials.get('access_token'), contacts_url, list_of_contact_responses)

    for response in list_of_contact_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'Contact')
        )

    fetch_all_companies(credentials.get('access_token'), companies_url, list_of_companies_responses)

    for response in list_of_companies_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'Company')
        )

    fetch_all_deals(credentials.get('access_token'), deals_url, list_of_deals_responses)

    for response in list_of_deals_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'Deal')
        )

    print("\nList of Integration Items: \n")
    print(list_of_integration_item_metadata,"\n")
    
    for item in list_of_integration_item_metadata:
        print(f"ID: {item.id}")
        print(f"Type: {item.type}")
        print(f"Name: {item.name}")
        print(f"Creation Time (UTC): {item.creation_time}")
        print(f"Last Modified Time: {item.last_modified_time}")

        print("-" * 30)  # Separator between objects

    return list_of_integration_item_metadata
