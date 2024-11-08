import os
import sys
import json
import html
import requests
import csv
from datetime import datetime

CHECK_RULE_LIST = [
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
    #print(app['app_id'])

    err_msg_buffer = []

    # 脆弱性チェック
    url_traces = '%s/traces/%s/ids' % (API_URL, app_id)
    r = requests.get(url_traces, headers=headers)
    data = r.json()
    #print(json.dumps(data, indent=4))
    for trace_id in data['traces']:
        url_trace = '%s/traces/%s/trace/%s' % (API_URL, app_id, trace_id)
        r = requests.get(url_trace, headers=headers)
        data = r.json()
        #print(data['trace']['rule_name'])
        if data['trace']['rule_name'] in CHECK_RULE_LIST:
            CHECK_RULE_LIST.remove(data['trace']['rule_name'])
    if len(CHECK_RULE_LIST) > 0:
        err_msg_buffer.append('これらの脆弱性が検出されていません。%s' % (', '.join(CHECK_RULE_LIST)))

    # ライブラリチェック
    all_libraries = []
    all_vuln_libraries = []
    url_libraries = '%s/applications/%s/libraries?limit=50&offset=%d&expand=vulns&quickFilter=ALL' % (API_URL, app_id, len(all_libraries))
    r = requests.get(url_libraries, headers=headers)
    data = r.json()
    #print(json.dumps(data, indent=4))
    totalCnt = data['count']
    #print(totalCnt)
    for library in data['libraries']:
        #print(library['file_name'])
        all_libraries.append(library['hash'])
        if len(library['vulns']) > 0:
            all_vuln_libraries.append(library['hash'])

    libraryIncompleteFlg = True
    libraryIncompleteFlg = totalCnt > len(all_libraries)
    while libraryIncompleteFlg:
        url_libraries = '%s/applications/%s/libraries?limit=50&offset=%d&expand=vulns&quickFilter=ALL' % (API_URL, app_id, len(all_libraries))
        r = requests.get(url_libraries, headers=headers)
        data = r.json()
        for library in data['libraries']:
            #print(library['file_name'])
            all_libraries.append(library['hash'])
            if len(library['vulns']) > 0:
                all_vuln_libraries.append(library['hash'])
        libraryIncompleteFlg = totalCnt > len(all_libraries)

    if len(all_libraries) < 112:
        err_msg_buffer.append('ライブラリの数が足りません。%d/112' % (len(all_libraries)))
    if len(all_vuln_libraries) < 29:
        err_msg_buffer.append('脆弱ライブラリの数が足りません。%d/29' % (len(all_vuln_libraries)))

    # /Contrast/api/ng/442311fd-c9d6-44a9-a00b-2b03db2d816c/applications/9c6ce833-0fea-46e1-875e-c5371ecd2bbe/route?expand=skip_links
    all_routes = []
    all_pass_routes = []
    all_vuln_routes = []
    all_crit_routes = []
    url_routes = '%s/applications/%s/route?expand=skip_links' % (API_URL, app_id)
    r = requests.get(url_routes, headers=headers)
    data = r.json()
    for route in data['routes']:
        sig = route['signature']
        all_routes.append(sig)
        if route['exercised']:
            all_pass_routes.append(sig)
            if route['vulnerabilities'] > 0:
                all_vuln_routes.append(sig)
            if route['critical_vulnerabilities'] > 0:
                all_crit_routes.append(sig)

    if len(all_routes) < 17:
        err_msg_buffer.append('ルート数が足りません。%d/17' % (len(all_routes)))
    if len(all_pass_routes) < 5:
        err_msg_buffer.append('ルート疎通済み数が足りません。%d/5' % (len(all_pass_routes)))
    if len(all_vuln_routes) < 2:
        err_msg_buffer.append('ルート疎通済み(脆弱性検知)数が足りません。%d/2' % (len(all_vuln_routes)))
    if len(all_crit_routes) < 1:
        err_msg_buffer.append('ルート疎通済み(クリティカル脆弱性検知)数が足りません。%d/2' % (len(all_crit_routes)))

    if len(err_msg_buffer) > 0:
        print('\n'.join(err_msg_buffer))
        sys.exit(1)

    print('すべての検証が成功しました。')

if __name__ == '__main__':
    main()

