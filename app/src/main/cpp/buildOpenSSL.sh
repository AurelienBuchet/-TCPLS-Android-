export ANDROID_NDK_ROOT=/home/aubuchet/Android/Sdk/ndk/23.0.7599858
OPENSSL_DIR=openssl
toolschains_path=$(python toolschains_path.py --ndk ${ANDROID_NDK_ROOT})
PATH=$toolschains_path/bin:$PATH
ANDROID_API=28
target=android-arm64
cd ${OPENSSL_DIR}
./Configure ${target} -D__ANDROID_API__=$ANDROID_API

make clean

make

ln -s "$(pwd)/openssl/libssl.a" $ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/lib/libssl.a
ln -s "$(pwd)/openssl/libcrypto.a" $ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/lib/libcrypto.a
