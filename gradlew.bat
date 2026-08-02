@echo off
setlocal
set APP_HOME=%~dp0
set WRAPPER_JAR=%APP_HOME%gradle\wrapper\gradle-wrapper.jar
if not exist "%WRAPPER_JAR%" (
  java "%APP_HOME%gradle\wrapper\WrapperBootstrap.java" "%WRAPPER_JAR%" || exit /b 1
)
java -Dorg.gradle.appname=gradlew -jar "%WRAPPER_JAR%" %*
exit /b %ERRORLEVEL%
