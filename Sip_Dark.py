import os
import pyshark
import shlex
import argparse

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
                uri = tmp.split(":")[1]
            elif key == "sip.auth.digest.response":
                respons = value
                if (
                    username != ""
                    and realm != ""
                    and nonce != ""
                    and uri != ""
                    and respons != ""
                ):
                    #import IPython; IPython.embed()
                    username = username.strip('"')
                    realm=realm.strip('"')
                    nonce=nonce.strip('"')
                    uri=uri.strip('"')
                    respons=respons.strip('"')
                    pattern = f"$sip$***{username}*{realm}*INVITE*sip*{uri}**{nonce}****MD5*{respons}"
                    print(f"\n\npattern: {pattern}\n")
                    file = open("hash.txt", "w")
                    file.write(pattern)
                    file.close()
                    flag= True
                    break
        if(flag):
            break
command = f"hashcat hash.txt {path_PasswordList}"
os.system(command)

