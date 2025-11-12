# ----- Stage 1: Build -----
FROM eclipse-temurin:17-jdk-jammy AS builder

WORKDIR /app

# Copy everything from repository root
COPY . .

# Grant execute permission to maven wrapper
RUN chmod +x ./mvnw

# Build the application
RUN ./mvnw clean package -DskipTests

# ----- Stage 2: Run -----
FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

# Copy the built jar (using the finalName from pom.xml)
COPY --from=builder /app/target/ssoapp.jar app.jar

# Expose port 8080
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
```

---

## 3. Create `.dockerignore` File

Create `.dockerignore` in your project root to speed up builds:
```
target/
.mvn/wrapper/maven-wrapper.jar
.idea/
*.iml
.vscode/
*.log