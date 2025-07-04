import java.util.*

plugins {
	kotlin("jvm") version "2.2.0"
	id("org.jetbrains.dokka-javadoc") version "2.0.0"
	`maven-publish`
	`java-library`
	signing
	application
}

group = "org.bread_experts_group"
version = "4.0.1"

repositories {
	mavenCentral()
	maven { url = uri("https://maven.breadexperts.group/") }
}

dependencies {
	implementation("org.bread_experts_group:bread_server_lib-code:2.51.9")
}

tasks.test {
	useJUnitPlatform()
}
application {
	mainClass = "org.bread_experts_group.http_router.RouterMainKt"
	applicationDefaultJvmArgs = listOf(
		"-XX:+UseZGC", "-Xms256m", "-Xmx1G", "-XX:SoftMaxHeapSize=128m", "-server",
		"-XX:MaxDirectMemorySize=128m", "-XX:+AlwaysPreTouch", "-XX:+UseLargePages",
		"-XX:+DisableExplicitGC", "-XX:MaxTenuringThreshold=1", "-XX:MaxGCPauseMillis=20",
		"-Djdk.tls.rejectClientInitiatedRenegotiation=true", "-XX:MaxDirectMemorySize=128m"
	)
}

java {
	withJavadocJar()
	withSourcesJar()
}
kotlin {
	jvmToolchain(21)
}
tasks.register<Jar>("dokkaJavadocJar") {
	dependsOn(tasks.dokkaGeneratePublicationJavadoc)
	from(tasks.dokkaGeneratePublicationJavadoc.flatMap { it.outputDirectory })
	archiveClassifier.set("javadoc")
}
val localProperties = Properties().apply {
	rootProject.file("local.properties").reader().use(::load)
}
publishing {
	publications {
		create<MavenPublication>("mavenKotlinDist") {
			artifact(tasks.distZip)
			artifact(tasks.distTar)
		}
		create<MavenPublication>("mavenKotlin") {
			artifactId = "$artifactId-code"
			from(components["kotlin"])
			artifact(tasks.kotlinSourcesJar)
			artifact(tasks["dokkaJavadocJar"])
			pom {
				name = "Routing micro-server"
				description = "Distribution of software for Bread Experts Group operated port/shared file routing servers."
				url = "https://breadexperts.group"
				signing {
					sign(publishing.publications["mavenKotlin"])
					sign(configurations.archives.get())
				}
				licenses {
					license {
						name = "GNU General Public License v3.0"
						url = "https://www.gnu.org/licenses/gpl-3.0.en.html"
					}
				}
				developers {
					developer {
						id = "mikoe"
						name = "Miko Elbrecht"
						email = "miko@breadexperts.group"
					}
				}
				scm {
					connection = "scm:git:git://github.com/Bread-Experts-Group/http_router.git"
					developerConnection = "scm:git:ssh://git@github.com:Bread-Experts-Group/http_router.git"
					url = "https://breadexperts.group"
				}
			}
		}
	}
	repositories {
		maven {
			url = uri("https://maven.breadexperts.group/")
			credentials {
				username = localProperties["mavenUser"] as String
				password = localProperties["mavenPassword"] as String
			}
		}
	}
}
signing {
	useGpgCmd()
	sign(publishing.publications["mavenKotlinDist"])
	sign(publishing.publications["mavenKotlin"])
}
tasks.javadoc {
	if (JavaVersion.current().isJava9Compatible) {
		(options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
	}
}