FROM ubuntu:22.04
RUN apt-get update
RUN apt install -y build-essential binutils-mips-linux-gnu
RUN  make -C test/basic_app download_kmc
