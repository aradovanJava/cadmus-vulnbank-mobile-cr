# CADMUS VulnBank Mobile

**Deliberately vulnerable Android training application**
CADMUS-CR-16 — Secure Coding Mobile
WP3 — Training Programs Design and Curricula

---

## ⚠️ WARNING — READ BEFORE USE

This application contains **intentional security vulnerabilities**. It exists solely as a
teaching artefact for the CADMUS-CR-16 course.

- **Never** deploy this application to a production environment.
- **Never** publish it to Google Play, F-Droid, or any public distribution channel.
- **Never** install it on a device holding real personal or corporate data.
- Run it only inside the CADMUS Cyber Range sandbox or an isolated emulator.
- All credentials, keys, IBANs, and customer records in this codebase are **fabricated**.
- The backend endpoints are non-routable placeholders (`10.0.2.2`, `vulnbank.local`) that
  resolve only inside the training sandbox.

The application is a mock retail-banking client. Its feature set is deliberately small so
that participants can read the entire codebase within a single training session.

---

## Purpose

VulnBank provides one realistic, self-consistent codebase that carries at least one defect
from **every** category of the OWASP Mobile Top 10 (2024 Final Release). This lets a single
application serve the whole CR-16 learning path:

| Node | Use of VulnBank |
|------|-----------------|
| N1 (Secure-by-Design Foundations) | Source excerpts for the mapping and root-cause exercises |
| N2 (Deep Dive & Defensive Patterns) | Side-by-side insecure/secure refactoring targets |
| N3 (Secure Code Review & SAST) | SonarQube / MobSF scan target, false-positive triage |
| CR1 (Vulnerability Identification) | Primary scan target in the Cyber Range |
| CR2 (Secure Refactoring) | Remediation target, validated against `secure/` reference |
| CR3 (Dependency Remediation) | Snyk / SCA target via the pinned vulnerable dependencies |
| CR4 (Security Validation) | CI/CD pipeline verification |

---

## Repository layout

```
vulnbank/
├── README.md                         This file
├── VULNERABILITY_MAP.md              Authoritative defect inventory (instructor copy)
├── build.gradle                      Project-level build script
├── settings.gradle
├── gradle.properties
└── app/
    ├── build.gradle                  M2/M7 defects: outdated deps, disabled minification
    ├── proguard-rules.pro
    └── src/main/
        ├── AndroidManifest.xml       M8 defects: exported components, backup, cleartext
        ├── res/xml/
        │   ├── network_security_config.xml   M5 defect: cleartext + user CA trust
        │   └── backup_rules.xml
        ├── res/values/strings.xml    M1 defect: secrets in resources
        └── java/eu/cadmus/vulnbank/
            ├── insecure/             The vulnerable implementation
            │   ├── LoginActivity.java
            │   ├── SessionManager.java
            │   ├── CryptoHelper.java
            │   ├── ApiClient.java
            │   ├── AccountDatabase.java
            │   ├── TransferActivity.java
            │   ├── SupportWebViewActivity.java
            │   └── AnalyticsReporter.java
            └── secure/               Reference remediation (instructor answer key)
                ├── SecureSessionManager.java
                ├── SecureCryptoHelper.java
                ├── SecureApiClient.java
                └── SecureAccountDatabase.java
```

The `secure/` package is a **reference implementation**, not a drop-in replacement. It is
excluded from the participant distribution — see "Preparing the participant build" below.

---

## Build instructions

**Requirements**

- Android Studio Ladybug (2024.2) or newer
- JDK 17
- Android SDK Platform 34, Build Tools 34.0.0
- An emulator image (API 30–34) or an isolated physical test device

**Steps**

```bash
git clone <sandbox-repo-url>/vulnbank.git
cd vulnbank
./gradlew assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

Install to an emulator:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**Note on dependency resolution.** The `app/build.gradle` pins deliberately outdated library
versions so that SCA tooling reports real CVEs. If your organisation runs a filtering artifact
proxy (Nexus/Artifactory with a policy gate), these versions may be blocked. Mirror them into
a dedicated training repository, or temporarily allow the `eu.cadmus.training` group.

**Demo credentials** (fabricated, see `LoginActivity.java`):

```
username: a.novak     password: Spring2024!
username: demo        password: demo
```

---

## Preparing the participant build

Participants must not receive the answer key. Before distribution:

```bash
rm -rf app/src/main/java/eu/cadmus/vulnbank/secure/
rm VULNERABILITY_MAP.md
git add -A && git commit -m "Participant distribution"
```

Keep the full version in a separate instructor branch.

---

## Scanning the application

**SonarQube (SAST)** — used in CR1/A3–A4:

```bash
./gradlew sonar \
  -Dsonar.projectKey=cadmus-vulnbank \
  -Dsonar.host.url=http://sonarqube.sandbox.local:9000 \
  -Dsonar.token=$SONAR_TOKEN
```

**MobSF (static + dynamic)** — used in CR1/A1–A2:

Upload `app-debug.apk` to the MobSF web interface at `http://mobsf.sandbox.local:8000`.
The static analyser will flag the manifest, crypto, and storage defects directly. The dynamic
analyser requires a rooted emulator image.

**OWASP ZAP (DAST)** — used against the mock backend, not the APK itself. Configure ZAP as an
upstream proxy for the emulator and exercise the login and transfer flows.

**Snyk (SCA)** — used in CR3:

```bash
snyk test --file=app/build.gradle --package-manager=gradle
```

---

## Expected findings

`VULNERABILITY_MAP.md` lists every planted defect with its file, OWASP category, CWE, and
reference fix. Tools will also surface findings **not** on that list — that is intentional and
forms the basis of the false-positive triage exercise in N3.

---

## Licence and attribution

Prepared for the CADMUS project under Grant Agreement No. 101190006, supported by the European
Health and Digital Executive Agency (HaDEA). Released for use within CADMUS partner training
delivery.

OWASP®, OWASP Mobile Top 10, MASVS, and MASTG are trademarks of the OWASP Foundation. This
material is derived from publicly available OWASP documentation and is not endorsed by OWASP.
