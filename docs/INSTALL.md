# Build & installation

## Requirements
* Android Studio (Ladybug or newer), JDK 17+, Android SDK Platform 36.
* Internet access to `google()`, `mavenCentral()`, `gradlePluginPortal()` and `services.gradle.org`.

## Build
```
git clone https://github.com/marufurrahmanmoni-ops/BANKVAULT
cd BANKVAULT
./gradlew :core:test              # 43 platform-free security tests
./gradlew :app:assembleDebug      # app/build/outputs/apk/debug/app-debug.apk
./gradlew :testbank:assembleDebug # dummy bank for tests
```
If Android Studio proposes newer AGP / Kotlin / library versions (gradle/libs.versions.toml), accepting them is safe.

## Release build
Create `keystore.properties` in the project root (git-ignored):
```
storeFile=/path/to/bankvault-release.jks
storePassword=…
keyAlias=bankvault
keyPassword=…
```
`./gradlew :app:assembleRelease` → `app/build/outputs/apk/release/app-release.apk` (R8-minified).
Record the signing-certificate SHA-256 (`apksigner verify --print-certs`) here so users can compare it with
More → Security monitoring → App signature.

## Install & first run
1. `adb install app-debug.apk` (or open the APK on the phone).
2. Open BANKVAULT → set PIN and recovery PIN.
3. More → Permissions: grant Usage access, Display over other apps, Notifications.
4. Apps → Add apps → pick banking apps.
5. More → Network isolation method → Local blackhole VPN (accept Android's VPN dialog) – or Root firewall.
6. Optional: Settings > Network > VPN > BANKVAULT > Always-on VPN.
7. More → DNS protection: set Private DNS to a filtering hostname.
8. Add the *Emergency Lock* tile to Quick Settings (needed before hiding BANKVAULT's icon).
9. Realme/ColorOS: Settings > Privacy > Hide apps for the banking apps (optional).
