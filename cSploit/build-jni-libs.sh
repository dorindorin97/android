#!/bin/bash
# Simplified build script for cSploitClient and cSploitCommon JNI libraries
# These are the minimum required libraries for the Android app to communicate
# with the cSploit daemon.
#
# This script should be run from the cSploit directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNI_DIR="$SCRIPT_DIR/jni"
cd "$SCRIPT_DIR"

echo "=== Building cSploit JNI Libraries ==="
echo "Script dir: $SCRIPT_DIR"
echo "JNI dir: $JNI_DIR"

# Check JNI directory exists and has content
if [ ! -d "$JNI_DIR/cSploitClient" ]; then
    echo "ERROR: JNI source not found at $JNI_DIR/cSploitClient"
    echo "Make sure git submodules are initialized: git submodule update --init --recursive"
    exit 1
fi

echo "Contents of JNI_DIR:"
ls -la "$JNI_DIR"

# Check for NDK
echo "Checking for NDK..."
echo "ANDROID_NDK_HOME: ${ANDROID_NDK_HOME:-not set}"

NDK_BUILD=""
if [ -n "$ANDROID_NDK_HOME" ]; then
    if [ -f "$ANDROID_NDK_HOME/ndk-build" ]; then
        NDK_BUILD="$ANDROID_NDK_HOME/ndk-build"
        echo "Using ndk-build from ANDROID_NDK_HOME: $NDK_BUILD"
    else
        echo "WARNING: ndk-build not found in ANDROID_NDK_HOME"
    fi
fi

if [ -z "$NDK_BUILD" ]; then
    NDK_BUILD=$(which ndk-build 2>/dev/null) || true
    if [ -n "$NDK_BUILD" ]; then
        echo "Using ndk-build from PATH: $NDK_BUILD"
    else
        echo "ERROR: ndk-build not found. Set ANDROID_NDK_HOME or add NDK to PATH"
        exit 1
    fi
fi

# ABIs to build for
ABIS="armeabi-v7a arm64-v8a x86 x86_64"
APP_PLATFORM="android-23"  # Matches minSdkVersion

# Output directory
OUTPUT_DIR="$SCRIPT_DIR/src/main/jniLibs"
mkdir -p "$OUTPUT_DIR"

echo "Building for ABIs: $ABIS"
echo "Platform: $APP_PLATFORM"
echo "Output: $OUTPUT_DIR"

# Create a temporary Android.mk that only builds the client libraries
# Note: -Werror removed to allow building with older code that has warnings
# -fgnu89-inline uses GNU inline semantics (inline definitions also serve as external definitions)
cat > "$JNI_DIR/Android_client_only.mk" << 'MKEOF'
LOCAL_PATH := $(call my-dir)

# cSploitCommon - shared library
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Wno-error -fgnu89-inline
LOCAL_EXPORT_LDLIBS := -ldl
LOCAL_SRC_FILES := $(wildcard $(LOCAL_PATH)/cSploitCommon/*.c)
LOCAL_MODULE := cSploitCommon
include $(BUILD_SHARED_LIBRARY)

# cSploitClient - shared library
include $(CLEAR_VARS)
LOCAL_CFLAGS := -Wall -Wno-error -fgnu89-inline -D_U_="__attribute__((unused))"
LOCAL_SHARED_LIBRARIES := cSploitCommon
LOCAL_LDLIBS := -llog
LOCAL_C_INCLUDES := $(LOCAL_PATH)/cSploitCommon $(LOCAL_PATH)/cSploitHandlers
LOCAL_SRC_FILES := $(wildcard $(LOCAL_PATH)/cSploitClient/*.c)
LOCAL_MODULE := cSploitClient
include $(BUILD_SHARED_LIBRARY)
MKEOF

# Build for each ABI
for ABI in $ABIS; do
    echo ""
    echo "=== Building for $ABI ==="
    
    OBJ_DIR="$JNI_DIR/obj/$ABI"
    LIB_DIR="$JNI_DIR/libs"
    
    mkdir -p "$OBJ_DIR"
    mkdir -p "$LIB_DIR"
    mkdir -p "$OUTPUT_DIR/$ABI"
    
    # Run ndk-build from jni directory
    # NDK_LIBS_OUT will create an $ABI subdirectory automatically
    "$NDK_BUILD" \
        NDK_PROJECT_PATH="$JNI_DIR" \
        APP_BUILD_SCRIPT="$JNI_DIR/Android_client_only.mk" \
        APP_ABI="$ABI" \
        APP_PLATFORM="$APP_PLATFORM" \
        NDK_OUT="$OBJ_DIR" \
        NDK_LIBS_OUT="$LIB_DIR" \
        -j$(nproc) \
        cSploitCommon cSploitClient
    
    # Copy the built libraries
    # ndk-build creates $LIB_DIR/$ABI/ structure
    echo "Looking for libraries in $LIB_DIR/$ABI/"
    ls -la "$LIB_DIR/$ABI/" 2>/dev/null || echo "Directory not found"
    
    if [ -f "$LIB_DIR/$ABI/libcSploitCommon.so" ]; then
        cp "$LIB_DIR/$ABI/libcSploitCommon.so" "$OUTPUT_DIR/$ABI/"
        cp "$LIB_DIR/$ABI/libcSploitClient.so" "$OUTPUT_DIR/$ABI/"
        echo "✓ Built and copied libraries for $ABI"
    else
        echo "WARNING: Libraries not found at $LIB_DIR/$ABI/"
        # Try alternate location
        find "$JNI_DIR" -name "libcSploitCommon.so" 2>/dev/null | head -5
    fi
done

# Cleanup temporary files
rm -f "$JNI_DIR/Android_client_only.mk"
rm -rf "$JNI_DIR/obj/"
rm -rf "$JNI_DIR/libs/"

echo ""
echo "=== Build Complete ==="
echo "Libraries installed to: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"/*/lib*.so 2>/dev/null || echo "No libraries found!"
