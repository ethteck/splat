FROM ubuntu:22.04
RUN apt-get update
RUN apt install -y build-essential make binutils-mips-linux-gnu python3 python3-pip wget
