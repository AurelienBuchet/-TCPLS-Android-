export ANDROID_NDK=/home/aubuchet/Android/Sdk/ndk/23.0.7599858

export target=arm64-v8a
cd picotcpls
make clean

cmake . -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=${target} -DANDROID_NATIVE_API_LEVEL=28 -DCMAKE_BUILD_TYPE=Release -DASSIMP_BUILD_STATIC_LIB="On" -DBUILD_SHARED_LIBS="On" -DOPENSSL_INCLUDE_DIR="../openssl/include"
make

cp libpicotcpls-jni.so liblog.so libpicotls-core.so libpicotls-minicrypto.so libpicotls-openssl.so /home/aubuchet/Documents/tcpls_app/app/app/libs/$target
