#!/usr/bin/bash
set -e
git config --global --add safe.directory $(pwd)
# avoid the release loop by checking if the latest commit is a release commit
readonly local last_release_commit_hash=$(git log --author="$GIT_RELEASE_BOT_NAME" --pretty=format:"%H" -1)
echo "Last $GIT_RELEASE_BOT_NAME commit: ${last_release_commit_hash}"
echo "Current commit: ${GITHUB_SHA}"
if [[ "${last_release_commit_hash}" = "${GITHUB_SHA}" ]]; then
     echo "Skipping for $GIT_RELEASE_BOT_NAME commit"
     exit 0
fi

# Making sure we are on top of the branch
echo "Git checkout branch ${GITHUB_REF##*/}"
git checkout ${GITHUB_REF##*/}
echo "Git reset hard to ${GITHUB_SHA}"
git reset --hard ${GITHUB_SHA}

# This script will do a release of the artifact according to http://maven.apache.org/maven-release/maven-release-plugin/
echo "Setup git user name to '$GIT_RELEASE_BOT_NAME'"
git config --global user.name "$GIT_RELEASE_BOT_NAME";
echo "Setup git user email to '$GIT_RELEASE_BOT_EMAIL'"
git config --global user.email "$GIT_RELEASE_BOT_EMAIL";

# Setup GPG
echo "GPG_ENABLED '$GPG_ENABLED'"
if [[ $GPG_ENABLED == "true" ]]; then
     echo "Enable GPG signing in git config"
     git config --global commit.gpgsign true
     echo "Using the GPG key ID $GPG_KEY_ID"
     git config --global user.signingkey $GPG_KEY_ID
     echo "GPG_KEY_ID = $GPG_KEY_ID"
     echo "Import the GPG key"
     echo  "$GPG_KEY" | base64 -d > private.key
     gpg --import ./private.key
     rm ./private.key
else
  echo "GPG signing is not enabled"
fi

# Do the release
echo "Do mvn release:prepare with settings $MAVEN_SETTINGS_OPTION and arguments $MAVEN_ARGS"
./mvnw -Dusername=$GITHUB_ACCESS_TOKEN release:prepare -s $GITHUB_WORKSPACE/settings.xml -B -Darguments="$MAVEN_ARGS"

echo "Do mvn release:perform with arguments $MAVEN_ARGS"
./mvnw release:perform -s $GITHUB_WORKSPACE/settings.xml -B -Darguments="$MAVEN_ARGS"

