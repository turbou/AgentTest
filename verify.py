import os
import sys
import json
import html
import requests
import csv
from datetime import datetime

CHECK_RULE_LIST = [
    "crypto-bad-mac",
    "cache-controls-missing",
    "clickjacking-control-missing",
    "csp-header-insecure",
    "csp-header-missing",
    "xcontenttype-header-missing",
    "crypto-bad-mac",
    "hql-injection",
]

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
    app_id = None
    for app in data['applications']:
        if APP_NAME == app['name']:
            app_id = app['app_id']

    if app_id is None:
        return

    print(app['app_id'])

    err_msg_buffer = []

    # 脆弱性チェック
    url_traces = '%s/traces/%s/ids' % (API_URL, app_id)
    r = requests.get(url_traces, headers=headers)
    data = r.json()
    print(json.dumps(data, indent=4))
    for trace_id in data['traces']:
        url_trace = '%s/traces/%s/trace/%s' % (API_URL, app_id, trace_id)
        r = requests.get(url_trace, headers=headers)
        data = r.json()
        print(data['trace']['rule_name'])
        CHECK_RULE_LIST.remove(data['trace']['rule_name'])
    if len(CHECK_RULE_LIST) > 0:
        err_msg_buffer.append('これらの脆弱性が検出されていません。%s' % (', '.join(CHECK_RULE_LIST)))

    if len(err_msg_buffer) > 0:
        print('\n'.join(err_msg_buffer))
        sys.exit(1)

if __name__ == '__main__':
    main()

