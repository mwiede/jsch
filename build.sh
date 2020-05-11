#!/bin/sh

echo
echo "JSch Build System"
echo "-----------------"

export OLD_ANT_HOME=$ANT_HOME
ANT_HOME=./tools

export OLD_CLASSPATH=$CLASSPATH



export CLASSPATH

chmod u+x ${ANT_HOME}/bin/antRun
chmod u+x ${ANT_HOME}/bin/ant

export PROPOSAL=""


${ANT_HOME}/bin/ant -emacs $@

export CLASSPATH=$OLD_CLASSPATH
export ANT_HOME=$OLD_ANT_HOME
