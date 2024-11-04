import os
import json
import html
import requests
import csv
from datetime import datetime

def main():
    env_not_found = False
    for env_key in ['CONTRAST_AUTHORIZATION', 'CONTRAST_API_KEY', 'CONTRAST_ORG_ID']:
        if not env_key in os.environ:
            print('環境変数 %s が設定されていません。' % env_key)
            env_not_found |= True
    if env_not_found:
        print()
        print('CONTRAST_BASEURL         : https://eval.contrastsecurity.com/Contrast')
        print('CONTRAST_AUTHORIZATION   : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==')
        print('CONTRAST_API_KEY         : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
        print('CONTRAST_ORG_ID          : XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')
        print('CONTRAST_APP_NAME        : e.g. PetClinicForAgentTest')
        return

    API_KEY=os.environ['CONTRAST_API_KEY']
    AUTHORIZATION=os.environ['CONTRAST_AUTHORIZATION']
    ORG_ID=os.environ['CONTRAST_ORG_ID']
    BASEURL='https://eval.contrastsecurity.com/Contrast'
    if 'CONTRAST_BASEURL' in os.environ:
        BASEURL=os.environ['CONTRAST_BASEURL']
    APP_NAME='PetClinicForAgentTest'
    if 'CONTRAST_APP_NAME' in os.environ:
        APP_NAME=os.environ['CONTRAST_APP_NAME']
    API_URL="%s/api/ng/%s" % (BASEURL, ORG_ID)

    headers = {"Accept": "application/json", "API-Key": API_KEY, "Authorization": AUTHORIZATION}

    url_applications = '%s/applications/name' % (API_URL)
    r = requests.get(url_applications, headers=headers)
    data = r.json()
    #print(json.dumps(data, indent=4))
    if not data['success']:
        print('Authorizationヘッダ, APIキー, 組織ID, TeamServerのURLが正しいか、ご確認ください。')
        return
    #print(len(data['traces']))
    #print('総アプリケーション数: %d' % len(data['applications']))
    app_id = None
    for app in data['applications']:
        if APP_NAME == app['name']:
            print(app['app_id'], app['name'])
            app_id = app['app_id']

    if app_id is None:
        return

    url_application_reset = '%s/applications/%s/reset?expand=skip_links' % (API_URL, app_id)
    r = requests.put(url_application_reset, headers=headers)
    data = r.json()
    print(json.dumps(data, indent=4))

if __name__ == '__main__':
    main()

