FROM ubuntu:20.04

RUN apt-get update \
        && apt-get install -y curl python-is-python3 perl git \
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

#create the shell config
RUN echo "{ pkgs ? import <nixpkgs> {} }: \n\
with pkgs; \n\
\n\
stdenvNoCC.mkDerivation { \n\
\tname = \"sgx-build-nix\"; \n\
\tbuildInputs = [ \n\
\t\t/nix/store/n0wh7aglap7fl8jfnmgnn1vdv71a9br9-autoconf-2.69 \n\
\t\t/nix/store/laf3s9p2rsk2sz78v83ni7wvp4qsbii3-automake-1.16.5 \n\
\t\t/nix/store/b7qjybcjdym24qi6yrcaf5kcxhq79gld-libtool-2.4.7 \n\
\t\t/nix/store/sx7m5a7xwh76jzb05g07f3nbhl44qw4z-ocaml-4.13.1 \n\
\t\t/nix/store/ncqmw9iybd6iwxd4yk1x57gvs76k1sq4-ocamlbuild-0.12.0 \n\
\t\t/nix/store/ja1iw47v9jkfgnj97l5cjivzn84160w2-file-5.41 \n\
\t\t/nix/store/h2yqbmb203mb75rnqpg0x72w8fyw0vmz-cmake-3.22.3 \n\
\t\t/nix/store/h3811zhzwfjzl3csh82xhr31hd5awaiz-gnum4-1.4.19 \n\
\t\t/nix/store/xk45sn1w4fcs5vrn0zjinjswscwf52mx-openssl-3.1.4 \n\
\t\t/nix/store/8m90kan2g80r6s1brn4zzmlghbb74s6m-openssl-3.1.4-dev \n\
\t\t/nix/store/0gz8dq0z6gx6lka4dbnmvbh47x1piri3-gnumake-4.2.1 \n\
\t\t/nix/store/1j1i0x8p9xajqdlf0h0m38dpmb8ipxa6-linux-headers-5.17 \n\
\t\t/nix/store/xmprbk52mlcdsljz66m8yf7cf0xf36n1-glibc-2.38-44 \n\
\t\t/nix/store/wp7kc5y840ldi5sd8j81fj4dabccff2d-binutils-wrapper-2.38 \n\
\t\t/nix/store/95nvd0v2xzf9vcv3kk4nmkjlcalc1jn7-gcc-wrapper-9.5.0 \n\
\t\t/nix/store/bwc29jqdwk3gqya220f2lr3yvyw02rrm-nasm-2.16.01 \n\
\t]; \n\
\n\
\tshellHook = '' \n\
\techo \"SGX build enviroment\" \n\
\t''; \n\
} \n\
" > /home/user/shell.nix

#install the required software
RUN touch .bash_profile \
&& curl https://releases.nixos.org/nix/nix-2.9.0/install | sh \
&& . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-env -i /nix/store/n0wh7aglap7fl8jfnmgnn1vdv71a9br9-autoconf-2.69 \
&& nix-env -i /nix/store/laf3s9p2rsk2sz78v83ni7wvp4qsbii3-automake-1.16.5 \
&& nix-env -i /nix/store/b7qjybcjdym24qi6yrcaf5kcxhq79gld-libtool-2.4.7 \
&& nix-env -i /nix/store/sx7m5a7xwh76jzb05g07f3nbhl44qw4z-ocaml-4.13.1 \
&& nix-env -i /nix/store/ncqmw9iybd6iwxd4yk1x57gvs76k1sq4-ocamlbuild-0.12.0 \
&& nix-env -i /nix/store/ja1iw47v9jkfgnj97l5cjivzn84160w2-file-5.41 \
&& nix-env -i /nix/store/h2yqbmb203mb75rnqpg0x72w8fyw0vmz-cmake-3.22.3 \
&& nix-env -i /nix/store/h3811zhzwfjzl3csh82xhr31hd5awaiz-gnum4-1.4.19 \
&& nix-env -i /nix/store/xk45sn1w4fcs5vrn0zjinjswscwf52mx-openssl-3.1.4 \
&& nix-env -i /nix/store/8m90kan2g80r6s1brn4zzmlghbb74s6m-openssl-3.1.4-dev \
&& nix-env -i /nix/store/0gz8dq0z6gx6lka4dbnmvbh47x1piri3-gnumake-4.2.1 \
&& nix-env -i /nix/store/1j1i0x8p9xajqdlf0h0m38dpmb8ipxa6-linux-headers-5.17 \
&& nix-env -i /nix/store/xmprbk52mlcdsljz66m8yf7cf0xf36n1-glibc-2.38-44 \
&& nix-env -i /nix/store/wp7kc5y840ldi5sd8j81fj4dabccff2d-binutils-wrapper-2.38 \
&& nix-env --set-flag priority 10 binutils-wrapper-2.38 \
&& nix-env -i /nix/store/95nvd0v2xzf9vcv3kk4nmkjlcalc1jn7-gcc-wrapper-9.5.0 \
&& nix-env -i /nix/store/bwc29jqdwk3gqya220f2lr3yvyw02rrm-nasm-2.16.01


#config nix-shell
RUN . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-shell
