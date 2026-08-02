#!/bin/sh
set -eu
APP_HOME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
WRAPPER_JAR="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
if [ ! -f "$WRAPPER_JAR" ]; then
    java "$APP_HOME/gradle/wrapper/WrapperBootstrap.java" "$WRAPPER_JAR"
fi
exec java -Dorg.gradle.appname=gradlew -jar "$WRAPPER_JAR" "$@"
