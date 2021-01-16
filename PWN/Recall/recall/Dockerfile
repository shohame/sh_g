# Dockerfile for the 'recall' challenge.
# Run the following commands in order to build and run the docker:
#  $ echo "CTF{flag}" > ./flag
#  $ sudo docker build -t recall .
#  $ sudo docker run -d -p 9022:1024 --rm -it --cap-add=SYS_PTRACE recall 
# Notice: '--cap-add=SYS_PTRACE' in mandatory to make the sandbox work.
# Notice: you must run kernel 5.3+ in order to be able to run the challenge

FROM ubuntu:20.04

RUN useradd --create-home --home-dir /home/ctf/ --shell /bin/bash ctf
WORKDIR /home/ctf
COPY sandbox /home/ctf/
COPY ynetd /home/ctf/
COPY flag /home/ctf/

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

USER ctf
CMD /home/ctf/ynetd -p 1024 /home/ctf/sandbox

