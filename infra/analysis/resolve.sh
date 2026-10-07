#!/bin/sh
set -eu
if [ "${SMARTSCA_GUARDED:-}" != 1 ]; then
  export SMARTSCA_GUARDED=1
  exec timeout --signal=TERM --kill-after=5s "${SMARTSCA_TIMEOUT_SECONDS:-180}" /bin/sh "$0" "$@"
fi
mkdir -p /workspace/project /tmp/repository
cp -R /input/. /workspace/project/
cp -R /opt/maven-cache/. /tmp/repository/
cd /workspace/project
for format in json tgf; do
  verbose=false
  if [ "$format" = tgf ]; then verbose=true; fi
  mvn -B -ntp -s /opt/smartsca/settings.xml -Dmaven.repo.local=/tmp/repository \
    -Dmaven.wagon.http.retryHandler.count=1 -Dmaven.wagon.rto=15000 \
    org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree \
    "-DoutputType=$format" "-Dverbose=$verbose" "-DoutputFile=target/smartsca-tree.$format" "$@"
done
jar --create --file /workspace/results.zip --no-manifest -C /workspace/project .
touch /workspace/success
# Keep tmpfs mounted until the backend copies results; the outer timeout also bounds orphaned jobs.
sleep 600
