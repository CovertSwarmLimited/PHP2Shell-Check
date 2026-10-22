#!/usr/bin/env bash
# Build minimal PHP CLI + CGI binaries from official php.net tarballs for the
# isolated signature-validation lab. No root and no Docker needed.
#
#   lab/local/build_php.sh /opt/php2shell-lab 8.4.26 8.4.27 8.5.11 8.5.12
#
# Requires gcc, make and pkg-config. Release tarballs ship pre-generated
# parsers, so bison and re2c are not needed. Each build takes about 1-2 minutes.
set -euo pipefail
dest=${1:?usage: build_php.sh DEST VERSION...}; shift
mkdir -p "$dest"
for v in "$@"; do
  (
    cd "$dest"
    [ -f "php-$v.tar.xz" ] || curl -fsSLo "php-$v.tar.xz" "https://www.php.net/distributions/php-$v.tar.xz"
    rm -rf "src-$v" && mkdir "src-$v" && tar -xJf "php-$v.tar.xz" -C "src-$v" --strip-components=1
    cd "src-$v"
    ./configure --prefix="$dest/inst-$v" --disable-all --enable-session --enable-cli --enable-cgi \
      --disable-phpdbg --without-pcre-jit > "../configure-$v.log" 2>&1
    make -j"$(nproc)" > "../make-$v.log" 2>&1
    make install > "../install-$v.log" 2>&1
    echo "built $v -> $dest/inst-$v"
  ) &
done
wait
