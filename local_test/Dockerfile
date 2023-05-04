FROM ubuntu:latest

RUN apt update && DEBIAN_FRONTEND=noninteractive TZ=Europe/Berlin apt install -y git gcc g++ cmake libacl1-dev libncurses5-dev pkg-config

# ICEORYX
RUN git clone https://github.com/eclipse-iceoryx/iceoryx.git
RUN cd iceoryx && cmake -Bbuild -Hiceoryx_meta && cmake --build build && cmake --build build --target install

# DPDPK
RUN apt update && DEBIAN_FRONTEND=noninteractive TZ=Europe/Berlin apt install -y build-essential python3 meson ninja-build python3-pyelftools libnuma-dev wget
RUN wget https://fast.dpdk.org/rel/dpdk-22.11.1.tar.xz && tar xf dpdk-22.11.1.tar.xz
RUN cd dpdk-stable-22.11.1 && pwd && meson setup build && cd build && ninja && ninja install && ldconfig


# SSH server
RUN apt update && DEBIAN_FRONTEND=noninteractive TZ=Europe/Berlin apt install openssh-server sudo gdb -y
COPY res/ssh_host_* /etc/ssh/

RUN useradd -rm -d /home/dds-perf -s /bin/bash -g root -G sudo -u 1000 dds-perf
RUN echo "dds-perf:dds-perf" | chpasswd
USER dds-perf
WORKDIR /home/dds-perf/


EXPOSE 22

CMD ["/usr/sbin/sshd","-D"]
