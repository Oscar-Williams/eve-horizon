# eclipse-temurin:21-jdk-jammy
FROM eclipse-temurin@sha256:a8b6e4da662e2ff710459e76be515a14746045c7a7493531d0901ca10a231501 AS build
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip \
    && curl -sSL https://github.com/JetBrains/kotlin/releases/download/v2.0.21/kotlin-compiler-2.0.21.zip -o /tmp/kotlin.zip \
    && mkdir -p /tmp/kotlin && unzip -q /tmp/kotlin.zip -d /tmp/kotlin \
    && mkdir -p /toolchain/kotlin/bin /toolchain/kotlin/lib /toolchain/jdk \
    && cp -a /tmp/kotlin/kotlinc/bin/* /toolchain/kotlin/bin/ \
    && cp -a /tmp/kotlin/kotlinc/lib/* /toolchain/kotlin/lib/ \
    && cp -a /opt/java/openjdk/* /toolchain/jdk/ \
    && rm -rf /tmp/kotlin /tmp/kotlin.zip /var/lib/apt/lists/*

# env.sh for runtime setup (JAVA_HOME from kotlin takes precedence)
RUN printf '#!/bin/sh\nexport JAVA_HOME=/opt/eve/toolchains/kotlin/jdk\nexport PATH="/opt/eve/toolchains/kotlin/kotlin/bin:${JAVA_HOME}/bin:${PATH}"\n' > /toolchain/env.sh

# busybox:stable
FROM busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
COPY --from=build /toolchain /toolchain
