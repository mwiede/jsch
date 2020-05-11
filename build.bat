@echo off

echo.
echo JSch Build System
echo -----------------

set OLD_ANT_HOME=%ANT_HOME%
set ANT_HOME=tools

set OLD_CLASSPATH=%CLASSPATH%

%ANT_HOME%\bin\ant.bat -emacs %1 %2 %3 %4 %5 %6 %7 %8
goto cleanup

:cleanup
set ANT_HOME=%OLD_ANT_HOME%
set CLASSPATH=%OLD_CLASSPATH%
