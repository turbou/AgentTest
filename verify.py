import os
import sys
import json
import html
import requests
import csv
import time
import re
import PyPDF2
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
    for env_key in ['CONTRAST_AUTHORIZATION', 'CONTRAST_API_KEY', 'CONTRAST_ORG_ID', 'CONTRAST_USER_NAME']:
        if not env_key in os.environ:
            print('環境変数 %s が設定されていません。' % env_key)
            env_not_found |= True
    if env_not_found:
        print()
        print('CONTRAST_BASEURL(optional)  : https://eval.contrastsecurity.com/Contrast')
        print('CONTRAST_AUTHORIZATION      : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==')
        print('CONTRAST_API_KEY            : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
        print('CONTRAST_ORG_ID             : XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')
        print('CONTRAST_USER_NAME          : e.g. taka.shiozaki@contrastsecurity.com')
        print('CONTRAST_APP_NAME(optional) : e.g. PetClinicForAgentTest')
        sys.exit(1)

    API_KEY=os.environ['CONTRAST_API_KEY']
    AUTHORIZATION=os.environ['CONTRAST_AUTHORIZATION']
    ORG_ID=os.environ['CONTRAST_ORG_ID']
    USER_NAME=os.environ['CONTRAST_USER_NAME']
    BASEURL='https://eval.contrastsecurity.com/Contrast'
    if 'CONTRAST_BASEURL' in os.environ:
        BASEURL=os.environ['CONTRAST_BASEURL']
    APP_NAME='PetClinicForAgentTest'
    if 'CONTRAST_APP_NAME' in os.environ:
        APP_NAME=os.environ['CONTRAST_APP_NAME']
    API_URL="%s/api/ng/%s" % (BASEURL, ORG_ID)

    headers = {"Accept": "application/json", "Content-Type": "application/json", "API-Key": API_KEY, "Authorization": AUTHORIZATION}

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

    result_msg_buffer = []
    err_msg_buffer = []

    # 脆弱性チェック
    exist_vul_msg = []
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
            exist_vul_msg.append(data['trace']['rule_name'])
            CHECK_RULE_LIST.remove(data['trace']['rule_name'])
    result_msg_buffer.append('+ これらの脆弱性が検出されました。(%d件)\n%s' % (len(exist_vul_msg), ''.join(list(map(lambda word: f'  - {word}\n', exist_vul_msg))).rstrip("\n")))
    if len(CHECK_RULE_LIST) > 0:
        err_msg_buffer.append('* これらの脆弱性が検出されていません。%s' % (', '.join(CHECK_RULE_LIST)))

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

    result_msg_buffer.append('+ %d/%d のライブラリを検知しました。' % (len(all_vuln_libraries), len(all_libraries)))
    if len(all_libraries) < 112:
        err_msg_buffer.append('* ライブラリの数が足りません。%d/112' % (len(all_libraries)))
    if len(all_vuln_libraries) < 29:
        err_msg_buffer.append('* 脆弱ライブラリの数が足りません。%d/29' % (len(all_vuln_libraries)))

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

    result_msg_buffer.append('+ ルートカバレッジは以下のとおりです。')
    result_msg_buffer.append('  - ルート数: %d' % len(all_routes))
    result_msg_buffer.append('  - 疎通済み数: %d' % len(all_pass_routes))
    result_msg_buffer.append('    - 脆弱性検知数: %d' % len(all_vuln_routes))
    result_msg_buffer.append('    - クリティカル脆弱性検知数: %d' % len(all_crit_routes))
    if len(all_routes) < 17:
        err_msg_buffer.append('* ルート数が足りません。%d/17' % (len(all_routes)))
    if len(all_pass_routes) < 5:
        err_msg_buffer.append('* ルート疎通済み数が足りません。%d/5' % (len(all_pass_routes)))
    if len(all_vuln_routes) < 1:
        err_msg_buffer.append('* ルート疎通済み(脆弱性検知)数が足りません。%d/1' % (len(all_vuln_routes)))
    if len(all_crit_routes) < 1:
        err_msg_buffer.append('* ルート疎通済み(クリティカル脆弱性検知)数が足りません。%d/2' % (len(all_crit_routes)))

    url_attestation = '%s/applications/%s/attestation' % (API_URL, app_id)
    payload = '{"vulnerabilityStatuses":[],"vulnerabilitySeverities":[],"vulnerabilityTypes":[],"vulnerabilityTags":[],"serverEnvironments":[],"serverTags":[],"complianceReports":["owasp-2021"],"showVulnerabilitiesDetails":false,"showRouteObservations":true}'
    r = requests.post(url_attestation, headers=headers, data=payload)
    data = r.json()
    if not data['success']:
        print('コンプライアンスレポートの発行リクエストに失敗しました。')
        sys.exit(1)

    time.sleep(15)
    url_notification = '%s/notifications?expand=skip_links&limit=10&offset=0' % (API_URL)
    r = requests.get(url_notification, headers=headers)
    data = r.json()
    link_msg = None
    sorted_data = sorted(data['notifications'], key=lambda x: x['timestamp'])
    for n in sorted_data:
        if n['source_type'] == 'REPORT_SUCCESS' and n['messageVariables']['applicationNameKey'] == APP_NAME:
            link_msg = n['message']
    pattern = r"ATTESTATION_REPORT_DOWNLOAD:(.*?)\$\$LINK_DELIM\$\$"
    match = re.search(pattern, link_msg)
    if match:
        download_id = match.group(1)
        url_download = '%s/reports/download/%s/%s' % (API_URL, USER_NAME, download_id)
        r = requests.post(url_download, headers=headers, stream=True)
        r.raise_for_status() 
        with open('report.pdf', 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192): 
                f.write(chunk)
        text = ""
        with open('report.pdf', 'rb') as pdf_file:
          pdf_reader = PyPDF2.PdfReader(pdf_file)
          for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text += page.extract_text()
        if 'HQLインジェクション' in text:
            result_msg_buffer.append('+ レポートPDFは日本語で出力されていません。')
        else:
            err_msg_buffer.append('* レポートPDFには「HQLインジェクション」が含まれていません。')

    output_buffer = []
    output_buffer.append('結果発表') 
    output_buffer.append('-------------------------------------------------') 
    output_buffer.append('\n'.join(result_msg_buffer))
    output_buffer.append('-------------------------------------------------') 
    if len(err_msg_buffer) > 0:
        output_buffer.append('検証が失敗しました。')
        output_buffer.append('\n'.join(err_msg_buffer))
    else:
        output_buffer.append('検証が成功しました。')

    with open("output.txt", "w") as f:
        for output in output_buffer:
            f.write(output + "\\n")
    print('\n'.join(output_buffer)) 

    #if len(err_msg_buffer) > 0:
    #    sys.exit(1)
    #sys.exit(0)

if __name__ == '__main__':
    main()

