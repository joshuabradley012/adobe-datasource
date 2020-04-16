import json
import jwt
import requests
import time
import pandas as pd
from datetime import date, datetime, timedelta
import numpy as np
from collections import Iterable

def read_file(file_name):
  f = open(file_name, 'r')
  contents = f.read()
  f.close()
  return contents

def write_file(file_name, contents):
  f = open(file_name, 'w')
  f.write(contents)
  f.close()

def read_json(file_name):
  return json.loads(read_file(file_name))

def write_json(file_name, data):
  write_file(file_name, json.dumps(data))

def chunk(ls, size):
  for i in range(0, len(ls), size):
    yield ls[i:i + size]

def encode_jwt(payload, secret):
  payload['exp'] = round(time.time()) + 30 * 60
  encoded_jwt = jwt.encode(payload, secret, algorithm='RS256')
  return encoded_jwt

def authenticate_adobe(callback):
  conf = read_json('adobe_conf.json')
  encoded_jwt = encode_jwt(read_json('adobe_jwt_payload.json'), read_file('private.key'))
  conf['jwt_token'] = encoded_jwt

  r = requests.post('https://ims-na1.adobelogin.com/ims/exchange/jwt/',
    headers={
      'Cache-Control': 'no-cache',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    data=conf)
  data = r.json()

  access_token = {}
  access_token['access_token'] = data['access_token']

  write_json('adobe_access_token.json', access_token)
  return callback()

def get_datasource_id():
  data = {
    'reportSuiteID': 'REPORT_SUITE_ID',
  }
  get_adobe_1_4('?method=DataSources.UploadData', json.dumps(data))

def get_adobe_1_4(endpoint, payload=None):
  if payload is None:
    payload={}

  conf = read_json('adobe_conf.json')
  token = read_json('adobe_access_token.json')['access_token']

  r = requests.post(url=conf['adobe_api_1-4']+endpoint,
    headers={
      'Accept': '*/*',
      'Authorization': 'Bearer ' + token,
      'X-ADOBE-DMA-COMPANY': 'COMPANY_NAME',
    },
    data=payload)
  data = r.json()

  if isinstance(data, Iterable) and 'error_description' in data and data['error_description'] == 'The access token provided has expired':
    return authenticate_adobe(lambda: get_adobe_1_4(endpoint, payload))
  else:
    return data

def get_adobe_2_0(endpoint, payload=None):
  if payload is None:
    payload={}

  conf = read_json('adobe_conf.json')
  token = read_json('adobe_access_token.json')['access_token']

  r = requests.post(url=conf['adobe_api']+conf['company_id']+endpoint,
    headers={
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
      'x-api-key': conf['client_id'],
      'x-proxy-global-company-id': conf['company_id'],
    },
    json=payload)
  data = r.json()

  if 'error_code' in data and 'message' in data and data['message'] == 'Oauth token is not valid':
    return authenticate_adobe(lambda: get_adobe_2_0(endpoint, payload))
  else:
    return data

def authenticate_marketo(callback):
  conf = read_json('marketo_conf.json')

  params = {
    'grant_type': 'client_credentials',
    'client_id': conf['client_id'],
    'client_secret': conf['secret_id']
  }

  r = requests.get(url=conf['munchkin_id']+'/identity/oauth/token',
    params=params)
  data = r.json()

  access_token = {}
  access_token['access_token'] = data['access_token']

  write_json('marketo_access_token.json', access_token)
  return callback()

def get_marketo(endpoint, params=None):
  if params is None:
    params={}

  api = read_json('marketo_conf.json')['munchkin_id']
  token = read_json('marketo_access_token.json')

  payload = {**token, **params}

  r = requests.get(url=api+endpoint,
    headers={'Accept-Encoding': 'gzip'},
    params=payload)
  data = r.json()

  if 'errors' in data and 'message' in data['errors'][0] and data['errors'][0]['message'] == 'Access token invalid':
    return authenticate_marketo(lambda: get_marketo(endpoint, params))
  else:
    return data

def get_marketo_pages(endpoint, params=None, previousResults=None):
  if params is None:
    params={}

  if previousResults is None:
    previousResults=[]

  data = get_marketo(endpoint, params)

  if data and 'result' in data:
    previousResults.extend(data['result'])

  if data and 'moreResult' in data and data['moreResult']:
    params['nextPageToken'] = data['nextPageToken'].replace('=', '')
    return get_marketo_pages('/rest/v1/leads.json', params, previousResults)
  else:
    return previousResults

def store_mcvisid():
  df = pd.read_csv('example-data-feed.tsv',
    names=['MC Visitor ID', 'Marketo ID'], sep='\t', dtype=str)
  df.drop_duplicates(subset=None, inplace=True)
  usersdf = df[df['Marketo ID'].isnull()]
  users = list(usersdf['MC Visitor ID'].to_numpy())
  write_json('adobe_users_without_marketo_id.json', users)

def get_marketo_user_data():
  users = read_json('adobe_users_without_marketo_id.json')
  user_chunks = list(chunk(users, 300))

  all_data = []

  for user_chunk in user_chunks:
    params = {
      'fields': 'id,Adobe_Visitor_ID,Account_Type__c,Account_Segment__c,Account_Status2__c,leadStatus,leadScore,Persona1__c,demoRequested,Company_Type_2_c__c',
      'filterType': 'Adobe_Visitor_ID',
      'filterValues': ','.join(user_chunk),
    }
    data = get_marketo_pages('/rest/v1/leads.json', params)
    all_data.extend(data)

  write_json('marketo_users.json', all_data)

def create_upload_file():
  adobe_df = pd.read_csv('example-data-feed.tsv',
    names=['MC Visitor ID', 'Marketo ID'], sep='\t', dtype=str)
  adobe_df.drop_duplicates(subset=None, inplace=True)
  adobe_df = adobe_df[adobe_df['Marketo ID'].isnull()]
  adobe_df = adobe_df.drop(columns=['Marketo ID'])
  adobe_df = adobe_df.rename(
    columns={'MC Visitor ID':'transactionID'})

  marketo_users = read_json('marketo_users.json')
  # These are the columns from the Marketo User data
  marketo_df = pd.DataFrame(marketo_users,
    columns=[
      'Adobe_Visitor_ID',
      'id',
      'Account_Type__c',
      'Account_Segment__c',
      'Account_Status2__c',
      'leadStatus',
      'leadScore',
      'Persona1__c',
      'demoRequested',
      'Company_Type_2_c__c'])
  # Renaming to the correct eVar
  marketo_df = marketo_df.rename(
    columns={
      'Adobe_Visitor_ID':'transactionID',
      'id': 'Evar 22',
      'Account_Type__c':'Evar 23',
      'Account_Segment__c':'Evar 24',
      'Account_Status2__c':'Evar 25',
      'leadStatus':'Evar 26',
      'leadScore':'Evar 27',
      'Persona1__c':'Evar 28',
      'demoRequested':'Evar 29',
      'Company_Type_2_c__c':'Evar 30'})

  joined_df = pd.merge(adobe_df, marketo_df, on='transactionID')
  # These columns are necessary for the upload to work
  joined_df.insert(0, 'Date', datetime.strftime(date.today(), '%m/%d/%Y')+'/00/00/00')
  # This is the custom success event we created earlier
  joined_df.insert(2, 'Event 51', '1')
  joined_df.to_csv('datasource_upload.txt', sep='\t', index=False)

def api_upload_adobe_datasource():
  adobe_df = pd.read_csv('datasource_upload.txt', sep='\t', dtype=str)
  data = {
    'columns': adobe_df.columns.values.tolist(),
    'dataSourceID': 'DATASOURCE_ID',
    'finished': 'true',
    'jobName': 'upload',
    'reportSuiteID': 'REPORT_SUITE_ID',
    'rows': adobe_df.replace(np.nan, '', regex=True).values.tolist()
  }
  get_adobe_1_4('?method=DataSources.UploadData', json.dumps(data))