# Dockerfile for the 'python4' challenge.
# Run the following commands in order to build and run the docker:
#  $ echo "CTF{flag}" > ./flag
#  $ sudo docker build -t python4 .
#  $ sudo docker run -d -p 9023:1024 --rm -it python4 

FROM ubuntu:focal-20200606 

RUN useradd --create-home --home-dir /home/ctf/ --shell /bin/bash ctf
WORKDIR /home/ctf
COPY python4 /home/ctf/
COPY ynetd /home/ctf/
COPY flag /home/ctf/

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

USER ctf
CMD /home/ctf/ynetd -p 1024 /home/ctf/python4

