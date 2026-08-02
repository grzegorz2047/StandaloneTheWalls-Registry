import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification
import org.gradle.testing.jacoco.tasks.JacocoReport

plugins {
    java
    application
    jacoco
}

group = "pl.grzegorz2047.standalonethewalls"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}

dependencies {
    testImplementation("org.junit.platform:junit-platform-console-standalone:1.13.4")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass = "pl.grzegorz2047.standalonethewalls.registry.RegistryTool"
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    failFast = false
    testLogging {
        events("failed", "skipped")
    }
}

jacoco {
    toolVersion = "0.8.15"
}

val coverageClassDirectories = files(sourceSets.main.get().output.asFileTree.matching {
    exclude("**/RegistryTool.class")
})

tasks.named<JacocoReport>("jacocoTestReport") {
    classDirectories.setFrom(coverageClassDirectories)
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    dependsOn(tasks.test)
    classDirectories.setFrom(coverageClassDirectories)
    violationRules {
        rule {
            element = "BUNDLE"
            limit {
                counter = "INSTRUCTION"
                value = "COVEREDRATIO"
                minimum = "0.70".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                value = "COVEREDRATIO"
                minimum = "0.55".toBigDecimal()
            }
        }
    }
}

val repositoryText = fileTree(layout.projectDirectory) {
    include(
        "**/*.java",
        "**/*.kt",
        "**/*.kts",
        "**/*.md",
        "**/*.json",
        "**/*.yml",
        "**/*.yaml",
        "**/*.txt",
        "**/*.properties",
        "**/*.xml",
        "gradlew",
        "gradlew.bat",
    )
    exclude(".gradle/**", "build/**")
}

val formatCheck = tasks.register("formatCheck") {
    group = "verification"
    description = "Rejects tabs, trailing whitespace and missing final newlines in repository text."
    inputs.files(repositoryText).withPathSensitivity(PathSensitivity.RELATIVE)
    doLast {
        val failures = mutableListOf<String>()
        repositoryText.files.sortedBy { it.invariantSeparatorsPath }.forEach { file ->
            val bytes = file.readBytes()
            val isExactConsumerVector =
                file.invariantSeparatorsPath.endsWith("src/test/resources/snapshot-v1-vector.json")
            if (!isExactConsumerVector && bytes.isNotEmpty() && bytes.last() != '\n'.code.toByte()) {
                failures.add("${file.invariantSeparatorsPath}: missing final newline")
            }
            file.readLines().forEachIndexed { index, line ->
                if ('\t' in line) {
                    failures.add("${file.invariantSeparatorsPath}:${index + 1}: tab")
                }
                if (line != line.trimEnd()) {
                    failures.add("${file.invariantSeparatorsPath}:${index + 1}: trailing whitespace")
                }
            }
        }
        if (failures.isNotEmpty()) {
            throw GradleException("Formatting violations:\n" + failures.joinToString("\n"))
        }
    }
}

val sourcePolicy = tasks.register("sourcePolicy") {
    group = "verification"
    description = "Rejects unsafe serialization, wildcard imports and private-key fixtures."
    val sources = fileTree("src") { include("**/*.java") }
    inputs.files(sources).withPathSensitivity(PathSensitivity.RELATIVE)
    doLast {
        val forbidden = listOf(
            "ObjectInputStream",
            "ObjectOutputStream",
            "java.io.Serializable",
            "import java.*.*",
            "BEGIN " + "PRIVATE KEY",
            "BEGIN ED25519 " + "PRIVATE KEY",
        )
        val failures = mutableListOf<String>()
        sources.files.sortedBy { it.invariantSeparatorsPath }.forEach { file ->
            val text = file.readText()
            forbidden.filter { it in text }.forEach { needle ->
                failures.add("${file.invariantSeparatorsPath}: $needle")
            }
        }
        if (failures.isNotEmpty()) {
            throw GradleException("Source policy violations:\n" + failures.joinToString("\n"))
        }
    }
}

val secretScan = tasks.register<Exec>("secretScan") {
    group = "verification"
    commandLine("bash", "scripts/scan-secrets.sh")
}

tasks.named("check") {
    dependsOn(formatCheck)
    dependsOn(sourcePolicy)
    dependsOn(secretScan)
    dependsOn(tasks.named("jacocoTestReport"))
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}
