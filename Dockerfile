FROM openjdk:8-jdk-alpine
ARG JAR_FILE=spring-petclinic-1.5.1.jar
COPY contrast.jar contrast.jar
ENV JAVA_TOOL_OPTIONS "-javaagent:contrast.jar"
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar", "--server.port=8001"]
