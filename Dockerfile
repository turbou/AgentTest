FROM eclipse-temurin:8-jdk
ARG JAR_FILE=petclinicdemo/target/spring-petclinic-1.5.1.jar
COPY contrast.jar contrast.jar
COPY contrast_security.yaml contrast_security.yaml
ENV JAVA_TOOL_OPTIONS "-javaagent:contrast.jar"
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar", "--server.port=8001"]
