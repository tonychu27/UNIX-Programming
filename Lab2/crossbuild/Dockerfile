FROM debian:bookworm

RUN if [ `uname -m` != 'x86_64'  ]; then dpkg --add-architecture amd64; fi
RUN if [ `uname -m` != 'aarch64' ]; then dpkg --add-architecture arm64; fi
RUN dpkg --add-architecture armel
RUN dpkg --add-architecture mipsel	# no mips

RUN apt-get update && apt-get upgrade -y && apt-get install -y tini \
		xz-utils gcc make autoconf automake gawk pkg-config file less bzip2 \
		gcc-arm-linux-gnueabi gcc-mips-linux-gnu gcc-mipsel-linux-gnu \
		flex bison bc libncurses-dev patch rsync \
		vim
RUN if [ `uname -m` != 'x86_64'  ]; then apt-get update && apt-get upgrade -y && apt-get install -y gcc-x86-64-linux-gnu; fi
RUN if [ `uname -m` != 'aarch64' ]; then apt-get update && apt-get upgrade -y && apt-get install -y gcc-aarch64-linux-gnu; fi

ENTRYPOINT [ "/usr/bin/tini", "--" ]
CMD [ "/usr/bin/sleep", "infinity" ]
