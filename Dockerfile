FROM openjdk:17-oracle
EXPOSE 8888
COPY target/*.jar app.jar
ENTRYPOINT ["java" "-jar" "app.jar"]
