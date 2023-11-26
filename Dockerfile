FROM ubuntu:22.04
RUN apt-get update
RUN apt install -y build-essential make binutils-mips-linux-gnu python3 python3-pip
RUN python3 -m pip install U -r requirements.txt
RUN make -C test/basic_app download_kmc
