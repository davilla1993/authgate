# ====== 1. Étape de build ======
FROM maven:3.9.6-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml /app
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests

# ====== 2. Étape de runtime ======
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]

