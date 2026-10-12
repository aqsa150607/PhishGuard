FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

COPY . .

RUN chmod +x mvnw
RUN ./mvnw -B clean package -DskipTests

CMD ["sh", "-c", "java -jar target/*.jar"]