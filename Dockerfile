# Multi-stage Docker build for Spring Boot app

FROM eclipse-temurin:17-jdk AS build
WORKDIR /app
COPY gradlew gradlew
COPY gradle gradle
COPY build.gradle settings.gradle ./
COPY src src
RUN chmod +x gradlew \
    && ./gradlew --no-daemon clean bootJar -x test

FROM eclipse-temurin:17-jre AS run
WORKDIR /app
ENV JAVA_OPTS=""
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]

