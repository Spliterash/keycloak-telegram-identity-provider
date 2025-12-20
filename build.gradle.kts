plugins {
    `java-library`
    id("io.freefair.lombok") version "8.10.2"
}

version = "1.0.3"

repositories {
    mavenCentral()
}

java {
    toolchain {
        setSourceCompatibility(17)
        setTargetCompatibility(17)
    }
}

dependencies {
    compileOnly("org.keycloak:keycloak-services:26.0.0")
    implementation("commons-codec:commons-codec:1.17.1")

    compileOnly("com.google.auto.service:auto-service:1.1.1")
    annotationProcessor("com.google.auto.service:auto-service:1.1.1")
}