FROM openjdk:17-oracle
EXPOSE 8761
COPY target/*.jar app.jar
ENTRYPOINT ["java" "-jar" "app.jar"]
