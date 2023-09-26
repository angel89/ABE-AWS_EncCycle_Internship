#!/usr/bin/python3
import time
start_time = time.time()
import ssl
import paho.mqtt.client as mqtt
from LW12prime import *
from LW12_util import *
import psutil

p=psutil.Process()
print("Process INFO: "+str(p)+"\n")

#Setup for LW instance
universe = set([
    "manager",
    "scientist",
    "intern",
    "secret clearance",
    "top secret clearance",
    "needs to know",
])

G = ModuloIntegersPairingGroup(1977020977483867625323910033330321311950683593750001)
lw = LW12prime()
MSK = lw.setup(universe,G) #Master Key created
attrset = set(["manager", "intern", "scientist"])

import pickle
path = "/home/angel"
with open(str(path) + '/SK.pickle', 'rb') as handle:
    rawKey = pickle.load(handle)

attrset = rawKey.get("attrset")
rawK = rawKey.get("K")
rawK0 = rawKey.get("K0")
rawKivalues = rawKey.get("Kivalues")
rawKikeys = rawKey.get("Kikeys")

K = [None] * len(rawK)
Kivalues=[[None]*6 for n in range(0,len(rawKivalues))]
Kikeys=[None]*len(rawKivalues)
K0 = [None] * len(rawK0)





# Parse of MK variables
for x in range(0, len(rawK)):
    K[x] = ModuloInt(rawK[x], 1977020977483867625323910033330321311950683593750001, True)
K = Matrix(3, 1, [[K[0]], [K[1]], [K[2]]])

for x in range(0, len(rawK0)):
    K0[x] = ModuloInt(rawK0[x], 1977020977483867625323910033330321311950683593750001, True)
K0 = Matrix(3, 1, [[K0[0]], [K0[1]], [K0[2]]])


count = 0

for y in range(0,len(rawKivalues)):
    temp = [[None] for n in range(6)]
    Kikeys[y]=rawKikeys[y]
    for x in range(0, len(rawKivalues[0])):
        temp[x]=ModuloInt(rawKivalues[y][x], 1977020977483867625323910033330321311950683593750001, True)

    Kivalues[y] = (Matrix(6, 1, [[temp[0]], [temp[1]], [temp[2]], [temp[3]], [temp[4]], [temp[5]]]))


def get_dic_from_two_lists(keys, values):
    return {keys[i]: values[i] for i in range(len(keys))}

Ki = [None] * len(rawKikeys)


Ki = get_dic_from_two_lists(Kikeys,Kivalues)

# Create dictionary for dict_list_g_pow_bji
def get_dic_from_two_lists(keys, values):
    return {keys[i]: values[i] for i in range(len(keys))}

Ki = get_dic_from_two_lists(Kikeys, Kivalues)
secretkey=lw.createSecretKey(attrset,K,K0,Ki)
print("SecretKey Created")

sw=True
#called while client tries to establish connection with the server
def on_connect(mqttc, obj, flags, rc):
    global sw
    if rc==0:
        print ("Connected successfully to A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com")
        if (sw):
            sw=False
            mqttc.subscribe("$aws/things/angelitos/shadow/update/documents",
                            qos=1)
    elif rc==1:
        print ("Subscriber Connection status code: "+str(rc)+" | Connection status: Connection refused")

def on_subscribe(mqttc, obj, mid, granted_qos):
    # global count2
    if 0==0 :          # First time used to receive the messages.
        print("Subscribed successfully to topic '$aws/things/angelitos/shadow/update/documents' with Qos= "+str(granted_qos))
        print("\nWaiting for k1\n")

#Variables used in on_message to create ciphertext object.

iv=None
message=None

k1 = None
k2 = None
k3 = None
#called when a message is received by a topic
def on_message(mqttc, obj, msg):
    global k1
    global k2
    global k3
    global iv
    global message

    print("Recieved Payload")

    count = 0
    count1 = 0

    t = [[None] * 3] * 1
    t2 = [[None] * 3] * 1
    t31 = [[None] * 6] * 1
    t32 = [[None] * 6] * 1
    t33 = [[None] * 6] * 1
    t3 = [None] * 3
    t3[0] = t31
    t3[1] = t32
    t3[2] = t33
    Mprime = None





    import ast
    tmp = msg.payload.decode('unicode-escape')
    rawdump = ast.literal_eval(tmp)

    if(rawdump.get("Mprime")!=None):

        rawCj=rawdump.get("Cj")
        rawC=rawdump.get("C")
        rawC0=rawdump.get("C0")
        Mprime=ModuloInt(rawdump.get("Mprime"), 1977020977483867625323910033330321311950683593750001, True)
        rawmat=rawdump.get("accessmat")
        # rawln=rawdump.get("lsss.ln")
        lab=rawdump.get("lab")


        count=0
        listC=[None]*3
        listC0 = [None] * 3
        while (count < 3):
            listC[count]=ModuloInt(rawC[count], 1977020977483867625323910033330321311950683593750001, True)
            listC0[count]= ModuloInt(rawC0[count], 1977020977483867625323910033330321311950683593750001, True)

            count += 1
        count1 = 0
        count=0
        temp=[None]*6
        Cj=[None]*len(lab)
        while (count < len(lab)):
            while (count1 < 6):


                temp[count1] = ModuloInt(rawCj[count][count1], 1977020977483867625323910033330321311950683593750001, True)
                count1 += 1
            Cj[count]=Matrix(1,6,[temp])
            temp =[None]*6
            count += 1
            count1 = 0
        count1 = 0
        count = 0


        temp=[[None]*2 for n in range(3)]

        while count1 < len(lab):
            while count < 2:
                temp[count1][count] = ModuloInt(rawmat[count1][count], 1977020977483867625323910033330321311950683593750001, False)
                count += 1
            count1 += 1
            count = 0
        count1 = 0
        count = 0
        accessstruct=Matrix(len(lab),2,temp)
        C=Matrix(1,3,[listC])

        C0=Matrix(1,3,[listC0])

        accessstructure = AccessStructure(accessstruct, lab)

        lsss = LSSS(accessstructure)
        CT=LW12prime.createCipherText(lw,lsss,Mprime,C,C0,Cj)


        print("\nDecrypting key")

        plain = lw.decryptToPlainText(CT, secretkey)


        if(k1==None):
            k1 = str(plain)
            print("Decrypted key K1: " + k1)
            print("\nWaiting for k2\n")

        elif (k2 == None):

            k2 = str(plain)
            print("Decrypted Key K2: " + k2)
            print("\nWaiting for message\n")

            k3 = "%0.2x" % (int(k1, 16) ^ int(k2, 16))


    else:
        import ast, codecs
        tmp = msg.payload.decode('unicode-escape')
        print("Decrypting message")

        rawdump = ast.literal_eval(tmp)
        rawmessage = rawdump.get("msg")
        iv = codecs.decode(rawdump.get("iv").encode(), "base64")

        message = codecs.decode(rawmessage.encode(), "base64")




    if iv!=None and message!=None and k3!=None :
        from Crypto.Cipher import AES

        cipher = AES.new(k3,AES.MODE_CFB, iv)
        import re

        rawtext=str(cipher.decrypt(message))[2:-1]

        print(rawtext[:re.search("([A-Z]+)", rawtext).start()])


        k1 = None
        k2 = None
        k3 = None
        iv = None
        message=None


#Setup for MQTT client and callback functions
mqttc = mqtt.Client(client_id="mqt-est")
mqttc.on_connect = on_connect
mqttc.on_subscribe = on_subscribe
mqttc.on_message = on_message

#Configure network encryption and authentication options. Enables SSL/TLS support.
#adding client-side certificates and enabling tlsv1.2 support as required by aws-iot service
mqttc.tls_set("/home/angel/share/root-CA.crt",
                certfile="/home/angel/share/certificate.pem.crt",
                keyfile="/home/angel/share/736e622c17-private.pem.key",
              tls_version=ssl.PROTOCOL_TLSv1_2,
              ciphers=None)

#connecting to aws-account-specific-iot-endpoint
mqttc.connect("A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com", port=8883, ) #AWS IoT service hostname and portno


#automatically handles reconnecting
mqttc.loop_forever()


