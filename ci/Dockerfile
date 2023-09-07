ARG BUILD_IMAGE
FROM ${BUILD_IMAGE}
ARG BUILD_IMAGE
ARG RPMS="cmake openssl openssl-devel gcc rpm-build"

# Ensure BUILD_IMAGE is set, fail the container build otherwise
RUN if [[ -z "${BUILD_IMAGE}" ]]; then exit 1; fi

# Install the dependencies for the given image
RUN if [[ "${BUILD_IMAGE}" == *"fedora"* ]]; then dnf install -y ${RPMS}; fi
RUN if [[ "${BUILD_IMAGE}" == *"almalinux"* ]]; then yum install -y ${RPMS}; fi
RUN if [[ "${BUILD_IMAGE}" == *"opensuse"* ]]; then zypper install -y ${RPMS}; fi
