{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/10e61bf5be57736035ec7a804cb0bf3d083bf2cf.tar.gz") {} }:
with pkgs;

stdenvNoCC.mkDerivation {
  inherit ipp_crypto asldobjdump;
  name = "sgx-build-nix";
  buildInputs = [
    autoconf
    automake
    libtool
    ocaml
    ocamlPackages.ocamlbuild
    file
    cmake
    gnum4
    openssl
    gnumake
    linuxHeaders
    #glibc
    /nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27
    binutils-unwrapped
    #/nix/store/1kl6ms8x56iyhylb2r83lq7j3jbnix7w-binutils-2.31.1
    gcc8
    #/nix/store/lvwq3g3093injr86lm0kp0f61k5cbpay-gcc-wrapper-8.3.0
    texinfo
    bison
    flex
    perl
    python3
    which
    git
  ];
  dontBuild = true;
  dontInstall = true;
  dontFixup = true;
  shellHook = ''
  echo "SGX build enviroment"
  '';
}
