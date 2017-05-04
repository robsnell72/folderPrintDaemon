from __future__ import print_function
import httplib2
import os
import requests
import json

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

import logging
from os import listdir
from os.path import isfile, join
logging.basicConfig(filename='fpdae.log',level=logging.DEBUG)
logging.info('Logging started...')

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/drive-python-quickstart.json
SCOPES = 'https://www.googleapis.com/auth/drive.metadata.readonly'
CLIENT_SECRET_FILE = 'client_secret_966801068790-rsok0db4lmig29imghlov1utcg09tpjo.apps.googleusercontent.com.json'
APPLICATION_NAME = 'Drive API Python Quickstart'

def get_credentials():
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   'drive-python-quickstart.json')

    store = Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else: # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials

def transfer_text_file(full_path, google_path, auth_token):
    logging.info("transfering text file %s to %s" % (full_path, google_path))
    content_length = str(os.path.getsize(full_path))
    logging.debug("Content-Length: %s" % content_length)
    headers = {'Content-Type': 'text/html',
    'Content-Length': content_length,
    'Authorization': "Bearer %s" % auth_token}
    
    with open(full_path, 'r') as myfile:
        r = requests.post('https://www.googleapis.com/upload/drive/v3?uploadType=media HTTP/1.1', data = myfile, headers = headers)
        logging.info(r)

def transfer_pdf_file(full_path, google_path, auth_token):
    logging.info("transfering pdf file %s to %s" % (full_path, google_path))

def transfer_arbitrary_file(full_path, google_path, auth_token):
    logging.info("transfering arbitrary file %s to %s" % (full_path, google_path))

def main():
    """Shows basic usage of the Google Drive API.

    Creates a Google Drive API service object and outputs the names and IDs
    for up to 10 files.
    """
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('drive', 'v3', http=http)

    results = service.files().list(
        pageSize=10,fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])
    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print('{0} ({1})'.format(item['name'], item['id']))
            
    #write to log file
    mypath = r"C:\temp\2Print"
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    logging.info(onlyfiles)
    
    #get auth token
    auth_token = ""
    with open(CLIENT_SECRET_FILE) as data_file:    
        data = json.load(data_file)
        logging.debug(data)
        auth_token = data["installed"]["client_secret"]
        logging.debug("auth_token:%s" % auth_token)

    google_path = "Rob/2017/2Print"
    for file in onlyfiles:
        full_path = os.path.join(mypath, file)
        if file.endswith(".txt"):
            transfer_text_file(full_path, google_path, auth_token)
        elif file.endswith(".pdf"):
            transfer_pdf_file(full_path, google_path, auth_token)
        else:
            transfer_arbitrary_file(full_path, google_path, auth_token)

if __name__ == '__main__':
    main()