# The workflow resolves this official image to a content digest once per run.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN pacman -Syu --noconfirm --needed \
    git rust cmake ninja openssh qt6-base qt6-svg qt6-wayland layer-shell-qt \
    systemd pam python polkit at-spi2-core dbus glib2 pkgconf && \
    useradd --uid 1000 --create-home builder && \
    install -d -o builder -g builder /build
USER builder
WORKDIR /build
