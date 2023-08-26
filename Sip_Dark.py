import sys
import os
import pyshark
import json
import argparse
import shlex
username = ""
realm = ""
nonce = ""
uri = ""
respons = ""

flag = False

parser=argparse.ArgumentParser()

parser.add_argument("-p","--pcapng")
parser.add_argument("-l","--passwordList")
args=parser.parse_args()

path_Pcapng = args.pcapng
path_PasswordList=args.passwordList
capture = pyshark.FileCapture(path_Pcapng)
for packet in capture:
    if hasattr(packet, "sip"):
        keys = packet.sip._all_fields
        values = packet.sip._all_fields.values()

        for key, value in zip(keys, values):
            
            if key == "sip.auth.username":
                username = value
            elif key == "sip.auth.realm":
                realm = value
            elif key == "sip.auth.nonce":
                nonce = value
            elif key == "sip.auth.uri":
                tmp = (str)(value)
                uri = tmp.split(":")[0]
            elif key == "sip.auth.digest.response":
                respons = value
                if (
                    username != ""
                    and realm != ""
                    and nonce != ""
                    and uri != ""
                    and respons != ""
                ):
                    pattern = f"$sip$***{username}*{realm}*INVITE*sip*{uri}**{nonce}****MD5*{respons}"
                    print(f"\n\npattern: {pattern}\n")
                    flag= True
                    break
        if(flag):
            break
command = f"echo {pattern} > hash.txt && echo hashcat hash.txt {path_PasswordList}"
command = shlex.quote(command)
print(command)               
os.system(command)



