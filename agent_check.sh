#!/bin/sh

AGENT_POM_FILE='pom.xml'
BACKUP_POM_FILE_NAME='pom_agent.xml.versionsBackup'

# 現在のエージェントバージョンを取得
CURRENT_VERSION=`mvn -f ${AGENT_POM_FILE} help:evaluate -Dexpression=project.dependencies[0].version -q -DforceStdout`

#mvn versions:display-dependency-updates -f ${AGENT_POM_FILE}
# バックアップpomファイルを削除
rm -f ${BACKUP_POM_FILE_NAME}
# エージェントの最新バージョンがあるかチェック
mvn versions:use-latest-versions -f ${AGENT_POM_FILE} > /dev/null 2>&1
if [ ! -e ${BACKUP_POM_FILE_NAME} ]; then
    # バックアップpomファイルが存在しないということはエージェントの更新がなかったということで終了
    exit 1
fi
# pomのバックアップファイルをリネーム
mv "${BACKUP_POM_FILE_NAME}" "pom_agent_${CURRENT_VERSION}.xml"
# エージェントの最新バージョンを取得
NEWER_VERSION=`git diff ${AGENT_POM_FILE} | grep '^+' | awk -F '[<>]' '/version/{print $3}'`

echo "${CURRENT_VERSION} -> ${NEWER_VERSION}"

# 実際に最新版のエージェントをダウンロード
mvn dependency:copy-dependencies -f ${AGENT_POM_FILE}

# 最新バージョンとなったpomファイルをコミット、プッシュ
#pwd
#ls -l
#git config --global --unset-all credential.helper
#git config --global credential.helper '!aws codecommit credential-helper $@'
#git config --global credential.UseHttpPath true
#git checkout main
#git config --global user.name ${GITHUB_USER_NAME}
#git config --global user.email ${GITHUB_USER_EMAIL}
#git commit -m "${AGENT_OLD_VERSION} -> ${AGENT_NEW_VERSION}." ${AGENT_POM_FILE}
#git commit -m "update from codebuild(${CURRENT_VERSION} -> ${NEWER_VERSION})." ${AGENT_POM_FILE}
#git branch
#git remote -v
#git push origin main

exit 0

