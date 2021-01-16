# Dockerfile for the 'paging' challenge.
# Run the following commands in order to build and run the docker:
#  $ echo "CTF{flag}" > ./flag
#  $ sudo docker build -t paging .
#  $ sudo docker run -d -p 9021:1024 --rm -it paging 

FROM ubuntu:focal-20200606 

RUN useradd --create-home --home-dir /home/ctf/ --shell /bin/bash ctf
WORKDIR /home/ctf
COPY *.py /home/ctf/
COPY requirements.txt /home/ctf/
COPY ynetd /home/ctf/
COPY flag /home/ctf/

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

RUN apt update && apt install -y python3 python3-pip && \
    python3 -m pip install --upgrade pip && \ 
    python3 -m pip install -r /home/ctf/requirements.txt

USER ctf
CMD /home/ctf/ynetd -p 1024 "python3 -u /home/ctf/main.py"
