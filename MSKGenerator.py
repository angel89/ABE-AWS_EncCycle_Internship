#!/usr/bin/python3
import json
from LW12prime import *
from LW12_util import *
import ssl
import sys


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








while(True):



    option=input("\nPress 1 to send PP to AWS. Press 2 to save SecretKey.")

    if(option=="1"):

        g_pow_b1 = [None] * len(lw.PP.g_pow_b1[0])
        g_pow_b2 = [None] * len(lw.PP.g_pow_b2[0])
        g_pow_b10 = [None] * len(lw.PP.g_pow_b10[0])
        g_pow_b20 = [None] * len(lw.PP.g_pow_b20[0])

        # Serialize MK values to save as a pickle file or send using MQTT(Not implemented)

        for x in range(0, len(lw.PP.g_pow_b1[0])):
            g_pow_b1[x] = lw.PP.g_pow_b1[0][x].a

        for x in range(0, len(lw.PP.g_pow_b2[0])):
            g_pow_b2[x] = lw.PP.g_pow_b2[0][x].a

        for x in range(0, len(lw.PP.g_pow_b20[0])):
            g_pow_b20[x] = lw.PP.g_pow_b20[0][x].a

        for x in range(0, len(lw.PP.g_pow_b10[0])):
            g_pow_b10[x] = lw.PP.g_pow_b10[0][x].a

        pair_gg_pow_alpha1psi = lw.PP.pair_gg_pow_alpha1psi.a
        pair_gg_pow_alpha2psi = lw.PP.pair_gg_pow_alpha2psi.a

        dict_list_g_pow_bjiKeys = [None] * len(lw.PP.dict_list_g_pow_bji.keys())

        dict_list_g_pow_bjiValues = [[[[None] for n in range(6)] for n1 in range(4)] for n2 in
                                     range(len(lw.PP.dict_list_g_pow_bji.values()))]

        count = 0
        for key, value in lw.PP.dict_list_g_pow_bji.items():
            matrixs = None

            dict_list_g_pow_bjiKeys[count] = key

            for y in range(0, len(value)):

                matrixs = value[y]
                for x in range(0, len(matrixs[0])):
                    dict_list_g_pow_bjiValues[count][y][x] = matrixs.mat[0][x].a

            count += 1

        dictPP = {"pair_gg_pow_alpha1psi": pair_gg_pow_alpha1psi, "pair_gg_pow_alpha2psi": pair_gg_pow_alpha2psi,
                  'g_pow_b2': g_pow_b2, 'g_pow_b20': g_pow_b20, 'g_pow_b10': g_pow_b10, "g_pow_b1": g_pow_b1,
                  "dict_list_g_pow_bjiValues": dict_list_g_pow_bjiValues,
                  "dict_list_g_pow_bjiKeys": dict_list_g_pow_bjiKeys}

        import paho.mqtt.publish as publish
        import paho.mqtt.client as mqtt

        tlsdict = {'ca_certs': "/home/angel/share/root-CA.crt", 'certfile': "/home/angel/share/certificate.pem.crt",
                   'keyfile': "/home/angel/share/736e622c17-private.pem.key", 'tls_version': ssl.PROTOCOL_TLSv1_2,
                   'ciphers': None}
        # mqttc.publish("$aws/things/angelitos/shadow/update/documents", payload, qos=1)
        publish.single("MSK/exchange", payload=json.dumps(dictPP), qos=1, retain=False,
                       hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
                       port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
                       protocol=mqtt.MQTTv311)

        print("MSK Public Params published to MSK/exchange topic")



    elif(option=="2"):
        import pickle
        attrset = set()

        n=int(input("\nHow many attributes?"))
        for x in range(0,n):
            tmp=input("\nEnter attribute "+str(x))
            print(tmp)
            attrset.add(tmp)
        secretkey = lw.keyGen(MSK, attrset)

        Kikeys = [None] * len(secretkey.Ki.keys())
        Kivalues = [[None] * 6 for n in range(len(secretkey.Ki.keys()))]
        count = 0
        for key, value in secretkey.Ki.items():
            matrixs = None

            Kikeys[count] = key

            for x in range(0, value.row):
                Kivalues[count][x] = value.mat[x][0].a

            count += 1
        K = [None] * secretkey.K.row

        for x in range(0, secretkey.K.row):
            K[x] = secretkey.K[x][0].a

        K0 = [None] * secretkey.K0.row

        for x in range(0, secretkey.K0.row):
            K0[x] = secretkey.K0[x][0].a

        dictSK = {"Kikeys": Kikeys, "Kivalues": Kivalues, "K": K, "K0": K0, "attrset": secretkey.attribset}

        print(secretkey)

        with open('/home/angel/SK.pickle', 'wb') as handle:
            pickle.dump(dictSK, handle)



































# while(True):
#     option=input("Press 1 to send Public Parameter, 2 to send secretekey.")
#     if(int(option)==1):
#
#
#
#         #Create dictionary to save MK values in a pickle file
#
#
#         # mqttc.publish("$aws/things/angelitos/shadow/update/documents", payload, qos=1)
#         publish.single("MSK/PP/exchange", payload=json.dumps(dict), qos=1, retain=False,
#                    hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
#                    port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
#                    protocol=mqtt.MQTTv311)
#         print("Public Params Sent")
#     elif (int(option) == 2):
#         attrset=list()
#         n=int(input("Enter number of attributes"))
#         for x in range(0,n):
#
#             attrset.append(input("Enter an attribute: "))
#
#         attrset = set(attrset)
#
#         print("Atrribute list: " + str(attrset))
#
#         secretkey = lw.keyGen(MSK, attrset)
#
#         # Variables for MK Public parameters
#         k = [None] * secretkey.K.row
#         k0 = [None] * secretkey.K0.row
#         kiv = [[None] * 6 for n in range(0, len(secretkey.Ki))]
#         Sattrset = [None] * len(secretkey.attribset)
#         kikeys = [None] * len(secretkey.Ki)
#         count = 0
#
#         # Serialize MK values to save as a pickle file or send using MQTT(Not implemented)
#
#         for x in range(0, secretkey.K.row):
#             k[x] = secretkey.K[x][0].a
#
#         for x in range(0, secretkey.K0.row):
#             k0[x] = secretkey.K0[x][0].a
#
#         for key, value in secretkey.Ki.items():
#             kikeys[count] = key
#
#             for x in range(0, value.row):
#                 kiv[count][x] = value[x][0].a
#             count += 1
#
#         SKdict = {"k": k, "k0": k0, "ki": kiv, "kikeys": kikeys}
#
#         import chilkat
#
#         dhBob = chilkat.CkDh()
#         dhAlice = chilkat.CkDh()
#
#         success = dhBob.UnlockComponent("Anything for 30-day trial")
#
#         dhBob.UseKnownPrime(2)
#
#         p = dhBob.p()
#         g = dhBob.get_G()
#
#         dict1={"p":p, "g":g }
#         publish.single("SK/exchange", payload=json.dumps(dict1), qos=1, retain=False,
#                        hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
#                        port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
#                        protocol=mqtt.MQTTv311)
#
#         success = dhAlice.SetPG(p, g)
#
#
#         eBob = dhBob.createE(256)
#
#         eAlice = dhAlice.createE(256)
#
#         publish.single("SK/exchange", payload=json.dumps(eBob), qos=1, retain=False,
#                        hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
#                        port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
#                        protocol=mqtt.MQTTv311)
#
#
#         # connecting to aws-account-specific-iot-endpoint
#         mqttc.connect("A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com", port=8883, )  # AWS IoT service hostname and portno
#
#         # automatically handles reconnecting
#         mqttc.loop_forever()
#         kBob = dhBob.findK(eAlice)
#         kAlice = dhAlice.findK(eBob)
#
#
#         print("Bob's shared secret:")
#         print(kBob)
#         print("Alice's shared secret (should be equal to Bob's)")
#         print(kAlice)
#
#
#         crypt = chilkat.CkCrypt2()
#         success = crypt.UnlockComponent("Anything for 30-day trial.")
#
#         crypt.put_EncodingMode("hex")
#         crypt.put_HashAlgorithm("md5")
#
#         sessionKey = crypt.hashStringENC(kBob)
#
#         print("128-bit Session Key:")
#         print(sessionKey)
#
#         crypt.put_CryptAlgorithm("aes")
#         crypt.put_KeyLength(128)
#         crypt.put_CipherMode("cbc")
#
#
#         iv = crypt.hashStringENC(sessionKey)
#
#         print("Initialization Vector:")
#         print(iv)
#
#         crypt.SetEncodedKey(sessionKey, "hex")
#         crypt.SetEncodedIV(iv, "hex")
#
#
#         crypt.put_EncodingMode("base64")
#
#
#
#
#         cipherText64 = crypt.encryptStringENC(json.dumps(SKdict))
#
#         publish.single("SK/exchange", payload=cipherText64, qos=1, retain=False,
#                        hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
#                        port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
#                        protocol=mqtt.MQTTv311)
#
#
#
#
#
#     # mqttc.publish("$aws/things/angelitos/shadow/update/documents", payload, qos=1)
#         publish.single("SK/exchange", payload=cipherText64, qos=1, retain=False,
#                    hostname="A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com",
#                    port=8883, client_id="sda2", keepalive=60, will=None, auth=None, tls=tlsdict,
#                    protocol=mqtt.MQTTv311)
#
#
#
#
#
#
#
#









