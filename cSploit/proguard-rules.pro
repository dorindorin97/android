# ProGuard/R8 rules for cSploit

# Keep source file names and line numbers for better crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep all native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep all classes with @Keep annotation
-keep @androidx.annotation.Keep class * {*;}

# Keep all public classes in the main package
-keep public class org.csploit.android.** {
    public protected *;
}

# Keep all plugin classes and their methods
-keep class * extends org.csploit.android.core.Plugin {
    public protected *;
}

# Keep all Activity classes
-keep class * extends android.app.Activity {
    public protected *;
}

# Keep all Fragment classes
-keep class * extends androidx.fragment.app.Fragment {
    public protected *;
}

# Keep all Service classes
-keep class * extends android.app.Service {
    public protected *;
}

# Keep custom views
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}

-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# Keep enum classes
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep Parcelable implementations
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# Keep Serializable classes
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Keep native library loading
-keep class org.csploit.android.core.Client {
    public protected *;
}

# Keep WiFi algorithm classes - they may use reflection
-keep class org.csploit.android.wifi.algorithms.** {
    public protected *;
}

# Keep network/metasploit classes
-keep class org.csploit.android.net.** {
    public protected *;
}

-keep class org.csploit.android.net.metasploit.** {
    public protected *;
}

# Keep tool classes
-keep class org.csploit.android.tools.** {
    public protected *;
}

# ACRA crash reporting
-keep class org.acra.** { *; }
-dontwarn org.acra.**

# Apache Commons
-dontwarn org.apache.commons.**
-keep class org.apache.commons.** { *; }

# MessagePack
-dontwarn org.msgpack.**
-keep class org.msgpack.** { *; }

# Suppress warnings for known issues
-dontwarn javax.annotation.**
-dontwarn javax.inject.**
-dontwarn sun.misc.Unsafe

# Keep AndroidX libraries
-keep class androidx.** { *; }
-dontwarn androidx.**

# Material Design
-keep class com.google.android.material.** { *; }
-dontwarn com.google.android.material.**

# Remove logging in release builds for performance
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

# Optimization settings
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Allow optimization but keep meaningful stack traces
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*

# Security: Obfuscate all class names except main components
-repackageclasses ''
-allowaccessmodification

# Keep custom exceptions for better debugging
-keep public class * extends java.lang.Exception

# Keep view binding if used
-keep class * extends androidx.viewbinding.ViewBinding {
    public static ** inflate(...);
    public static ** bind(...);
}
