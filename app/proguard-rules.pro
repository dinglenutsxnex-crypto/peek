# Peek — ProGuard rules
# Native JNI methods must not be stripped or renamed
-keepclasseswithmembernames class com.nex.peek.PeekNative {
    native <methods>;
}
-keep class com.nex.peek.model.** { *; }
