FROM ubuntu:focal

RUN apt update -y ; apt upgrade -y ; apt install python3 -y ; apt install python3-pip -y ; apt install git -y ; apt install nmap -y ; apt autoremove -y

RUN git clone https://github.com/k4m4/kickthemout.git

WORKDIR /kickthemout

RUN pip3 install -r requirements.txt

CMD python3 kickthemout.py


