# The workflow resolves this official image to a content digest once per run.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
# Omarchy stable uses this mirror for the Arch core/extra repositories. Sync the
# whole disposable environment, including downgrades from the current Arch base;
# replacing only Qt would create an unsupported partial upgrade/downgrade.
RUN printf 'Server = https://stable-mirror.omarchy.org/$repo/os/$arch\n' > /etc/pacman.d/mirrorlist && \
    pacman -Syyuu --noconfirm --needed \
    git rust cmake ninja openssh qt6-base qt6-svg qt6-wayland layer-shell-qt \
    systemd pam python polkit at-spi2-core dbus glib2 pkgconf && \
    pacman -Dk && \
    useradd --uid 1000 --create-home builder && \
    install -d -o builder -g builder /build
USER builder
WORKDIR /build
