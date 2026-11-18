# Room / WorkManager ship their own consumer rules.
-keep class com.bankvault.managed.BankVaultAdminReceiver { *; }
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters** { *; }
-dontwarn org.bouncycastle.**
# Strip verbose logging from release builds.
-assumenosideeffects class android.util.Log { public static int d(...); public static int v(...); }
