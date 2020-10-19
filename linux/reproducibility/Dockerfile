FROM ubuntu:18.04

RUN apt-get update \
        && apt-get install -y curl python perl git \
        && mkdir -p /nix /etc/nix \
        && chmod a+rwx /nix \
        && echo 'sandbox = false' > /etc/nix/nix.conf \
        && rm -rf /var/lib/apt/lists/*

#add a user for Nix
RUN adduser user --home /home/user --disabled-password --gecos "" --shell /bin/bash
CMD /bin/bash -l
USER user
ENV USER user
WORKDIR /home/user

#install the required software
RUN touch .bash_profile \
&& curl https://nixos.org/releases/nix/nix-2.2.1/install | sh \
&& . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-env -i /nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27

COPY shell.nix /home/user/
#config nix-shell
RUN . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-shell
