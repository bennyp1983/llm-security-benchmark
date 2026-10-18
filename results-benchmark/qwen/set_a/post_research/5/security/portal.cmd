@echo off
rem Start the portal or run one administrative subcommand (Windows counterpart of portal.sh).
rem
rem Same rules as the shell launcher: the classpath is this directory's out\main and nothing
rem else. No "." and no wildcard, so the JVM cannot pick up a class that another account
rem dropped into the working directory, and CLASSPATH is cleared rather than trusted.
rem
rem Subcommands: login, add-user, set-password, disable-user, status, version, portal.
rem Configuration comes from the environment and the config file only -- see
rem config\portal.properties.example. Never pass a password here: it would show up in the
rem process list for every other account on the host.
setlocal
set ROOT=%~dp0
set MAIN=%ROOT%out\main

if not exist "%MAIN%\com\portal\auth\Main.class" (
  echo %MAIN% is not built. Run build.bat or javac first. 1>&2
  exit /b 1
)

set JAVA=java
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set JAVA="%JAVA_HOME%\bin\java.exe"

set CLASSPATH=
%JAVA% -cp "%MAIN%" -Djava.awt.headless=true -Dfile.encoding=UTF-8 com.portal.auth.Main %*
exit /b %ERRORLEVEL%
