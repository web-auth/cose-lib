# Build of the OSS Scanner (https://github.com/anthropics/oss-scanner), with the repository root as context.
# It starts from the phpqa image the CI jobs run in, so phpunit-11 behaves as it does on CI. That image has PHP 8.4
# with OpenSSL 3.5 and the sodium, gmp and bcmath extensions, so every algorithm of the library is available,
# ML-DSA included. COSE_ML_DSA_EXPECTED is set as in the PHP 8.4 job of the CI, so that MLDSATest checks the
# platform gate instead of being skipped. The scan runs without network access: every dependency is installed here.
FROM ghcr.io/spomky-labs/phpqa:8.4

USER root

ENV COSE_ML_DSA_EXPECTED=yes

COPY . /src
WORKDIR /src

RUN composer install --no-interaction --no-progress

RUN composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist --no-progress \
    || echo "WARNING: PHPUnit reported failures"
