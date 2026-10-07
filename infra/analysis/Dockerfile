FROM maven:3.9.9-eclipse-temurin-21@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e
COPY settings.xml warm-pom.xml /opt/smartsca/
RUN mvn -B -ntp -s /opt/smartsca/settings.xml -f /opt/smartsca/warm-pom.xml \
    -Dmaven.repo.local=/opt/maven-cache org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree
COPY resolve.sh /opt/smartsca/resolve.sh
RUN chmod 755 /opt/smartsca/resolve.sh
ENV HOME=/tmp JAVA_TOOL_OPTIONS="-Xmx384m"
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["/bin/sh", "/opt/smartsca/resolve.sh"]
