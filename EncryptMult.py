#!/usr/bin/python3
import codecs
import hashlib
import time


start_time = time.time()
import sys
from Crypto import Random

import ssl
import json
import paho.mqtt.client as mqtt
from LW12prime import *
from LW12_util import *
import psutil

p = psutil.Process()
print("Process INFO: " + str(p) + "")

import paho.mqtt.publish as publish


# make sure that the number chosen is a prime number!

G = ModuloIntegersPairingGroup(1977020977483867625323910033330321311950683593750001)

# deserealizer=PairingGroup("SS512")
universe = set([
    "manager",
    "scientist",
    "intern",
    "secret clearance",
    "top secret clearance",
    "needs to know",
])
lw = LW12prime()
MSK = lw.setup(universe, G)

policy = "(scientist)and(intern)"
temp = open("/sys/bus/acpi/devices/LNXTHERM:00/thermal_zone/temp").read().strip().rstrip('000')



import os

k1=codecs.encode(os.urandom(16), "hex").decode()
k2=codecs.encode(os.urandom(16), "hex").decode()

k3="%0.2x" % (int(k1, 16) ^ int(k2, 16))





# Import Public parameters of the Master Key.
import pickle

path = "/home/angel"
with open(str(path) + '/PP.pickle', 'rb') as handle:
    rawKey = pickle.load(handle)

# Variables for MK Public parameters

g_pow_b1 = [None] * len(lw.PP.g_pow_b1[0])
g_pow_b2 = [None] * len(lw.PP.g_pow_b2[0])
g_pow_b10 = [None] * len(lw.PP.g_pow_b10[0])
g_pow_b20 = [None] * len(lw.PP.g_pow_b20[0])
dict_list_g_pow_bjiValues = None
dict_list_g_pow_bjiKeys = None
pair_gg_pow_alpha2psi = None
pair_gg_pow_alpha1psi = None

# Extract MK values from pickle file
rawg_pow_b2 = rawKey.get("g_pow_b2")
rawg_pow_b20 = rawKey.get("g_pow_b20")
rawg_pow_b1 = rawKey.get("g_pow_b1")
rawg_pow_b10 = rawKey.get("g_pow_b10")
rawdict_list_g_pow_bjiValues = rawKey.get("dict_list_g_pow_bjiValues")
rawdict_list_g_pow_bjiKeys = rawKey.get("dict_list_g_pow_bjiKeys")
pair_gg_pow_alpha1psi = ModuloInt(rawKey.get("pair_gg_pow_alpha1psi"), 1977020977483867625323910033330321311950683593750001, True)
pair_gg_pow_alpha2psi = ModuloInt(rawKey.get("pair_gg_pow_alpha2psi"), 1977020977483867625323910033330321311950683593750001, True)

# Parse of MK variables
for x in range(0, len(rawg_pow_b2)):
    g_pow_b2[x] = ModuloInt(rawg_pow_b2[x], 1977020977483867625323910033330321311950683593750001, True)
g_pow_b2 = Matrix(1, 3, [g_pow_b2])

for x in range(0, len(rawg_pow_b20)):
    g_pow_b20[x] = ModuloInt(rawg_pow_b20[x], 1977020977483867625323910033330321311950683593750001, True)
g_pow_b20 = Matrix(1, 3, [g_pow_b20])

for x in range(0, len(rawg_pow_b1)):
    g_pow_b1[x] = ModuloInt(rawg_pow_b1[x], 1977020977483867625323910033330321311950683593750001, True)
g_pow_b1 = Matrix(1, 3, [g_pow_b1])

for x in range(0, len(rawg_pow_b10)):
    g_pow_b10[x] = ModuloInt(rawg_pow_b10[x], 1977020977483867625323910033330321311950683593750001, True)
g_pow_b10 = Matrix(1, 3, [g_pow_b10])

dict_list_g_pow_bjiKeys = [None] * len(lw.PP.dict_list_g_pow_bji.keys())

dict_list_g_pow_bjiValues = [[[[None] for n in range(6)] for n1 in range(4)] for n2 in
                             range(len(lw.PP.dict_list_g_pow_bji.values()))]

rawMatr = [[1] * 2 for n in range(3)]

count = 0
temp = [[None] for n in range(6)]
mat = [[None] for n in range(4)]
list_g_pow_bjiValues = [[None] for n in range(6)]

#
for value in rawdict_list_g_pow_bjiValues:
    matrixs = None
    for y in range(0, len(value)):
        matrixs = value[y]
        temp = [[None] for n in range(6)]
        for x in range(0, len(matrixs)):
            temp[x] = ModuloInt(matrixs[x], 1977020977483867625323910033330321311950683593750001, True)

        mat[y] = (Matrix(1, 6, [temp]))
    list_g_pow_bjiValues[count] = mat
    count += 1
    mat = [[None] for n in range(4)]


# Create dictionary for dict_list_g_pow_bji
def get_dic_from_two_lists(keys, values):
    return {keys[i]: values[i] for i in range(len(keys))}


dict_list_g_pow_bji = get_dic_from_two_lists(rawdict_list_g_pow_bjiKeys, list_g_pow_bjiValues)

# Assign MKs Public Parameters to local LW instance.
lw.PP = lw.PublicParameters(universe, lw.group, g_pow_b1, g_pow_b2, g_pow_b10, g_pow_b20, dict_list_g_pow_bji,
                             pair_gg_pow_alpha1psi, pair_gg_pow_alpha2psi)
print("\nLoaded MK public parameters from file: " + str(path) + "PP.pickle")


sw = True
payload1=None
payload2=None
# called while client tries to establish connection with the server
def on_connect(CT):
    global count
    global payload1, payload2
    global iv
    global sw
    global lw
    if 0 == 0:
        if (True):
            # Sending Ciphertext
            temp1 = [[[None] for n in range(3)] for n1 in range(2)]
            count = 0
            while (count < 3):
                temp1[0][count] = CT.C[0][count].a
                temp1[1][count] = CT.C0[0][count].a

                count += 1

            temp = [[[None] for n in range(6)] for n1 in range(len(CT.Cj))]

            count = 0
            count1 = 0
            while (count < len(CT.Cj)):
                while (count1 < 6):
                    order = str(count) + str(count1)

                    temp[count][count1] = CT.Cj[count][0][count1].a
                    count1 += 1
                count += 1
                count1 = 0
            t = [temp, temp1]

            accessstruct = [[None] * 2 for n in range(len(CT.Cj))]
            count = 0
            count1 = 0
            while count1 < len(CT.Cj):
                while count < 2:
                    accessstruct[count1][count] = CT.lsss.accessstruct.mat[count1][count].a
                    count += 1
                count1 += 1
                count = 0
            count1 = 0

            dict = {"C": temp1[0], "C0": temp1[1], "Cj": temp, "Mprime": int(CT.Mprime.a), "accessmat": accessstruct,
                    "lab": CT.lsss.lab}


            if(payload1==None):
                payload1 = json.dumps(dict)

            elif(payload2==None):
                payload2=json.dumps(dict)



print("\nEncrypting 1st key: " + str(k2))
on_connect(lw.encryptFromPolicyStringAndPlainText(policy,k2))
print("\nEncrypting 2st key: " + str(k3))
on_connect(lw.encryptFromPolicyStringAndPlainText(policy,k3))
from Crypto.Cipher import AES

iv = Random.new().read(AES.block_size)
cipher = AES.new(k1, AES.MODE_CFB, iv)

message="234.32"
for x in range(0,16-len(message)):
    message=message+random.choice("ABCDEFGHIJKLMNOPQRSTVWXYZ")
print(message)


import re



msg=cipher.encrypt(message)
                                                    # CAn use CTR mode,? only one that dosent require iv



print("\nEncrytping message")

dict = {"msg": codecs.encode(msg, "base64").decode()[:-1], "iv": codecs.encode(iv, "base64").decode()[:-1]}
payload = json.dumps(dict)


tlsdict = {'ca_certs': "/home/angel/share/root-CA.crt", 'certfile': "/home/angel/share/certificate.pem.crt",
           'keyfile': "/home/angel/share/736e622c17-private.pem.key", 'tls_version': ssl.PROTOCOL_TLSv1_2,
           'ciphers': None}

msgs = [{'topic':"$aws/things/angelitos/shadow/update/documents", 'payload':payload1},
                {'topic': "$aws/things/angelitos/shadow/update/documents", 'payload': payload2},
                {'topic': "$aws/things/angelitos/shadow/update/documents", 'payload': payload}]
print("Sending keys and message")
publish.multiple(msgs, hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com", port=8883, client_id="sda2", will=None, auth=None, tls=tlsdict, protocol=mqtt.MQTTv311)
print("\nSent")

# publish.single("$aws/things/angelitos/shadow/update/documents", payload=payload, qos=1, retain=False,
#                hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
#                port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
#                protocol=mqtt.MQTTv311)


cpuTime = p.cpu_times()
runTime = time.time() - start_time
memUsed = p.memory_full_info()

import logging

logger = logging.getLogger('myapp')
hdlr = logging.FileHandler('/home/angel/results.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)
logger.info("\n------Sent EncryptPublisher----")

logger.info("Total bytes sent: " + str(sys.getsizeof(payload)))
logger.info("Memory Used: " + str(memUsed))
logger.info("CPU time Used: " + str(cpuTime))
logger.info("Time script ran for: " + str(runTime) + 's')
