#!/usr/bin/python3


import ssl

import paho.mqtt.client as mqtt
import ast

sw=True
def on_connect(mqttc, obj, flags, rc):
    global sw
    if rc==0:
        print ("Connected successfully to A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com")

        if(0==0):

            mqttc.subscribe("MSK/exchange",
            qos=1)

    elif rc==1:
        print ("Subscriber Connection status code: "+str(rc)+" | Connection status: Connection refused")
#called when a topic is successfully subscribed to
def on_subscribe(mqttc, obj, mid, granted_qos):
    print("Subscribed successfully to topic MSK/exchange with Qos= "+str(granted_qos))
    print("\nWaiting for messages\n")

def on_message(mqttc, obj, msg):
    print("heeeeeey")
    tmp = msg.payload.decode('unicode-escape')
    rawdump = ast.literal_eval(tmp)
    path = ("/home/angel")


    import pickle
    with open(str(path) + '/PP.pickle', 'wb') as handle:
        pickle.dump(rawdump, handle)
    mqttc.disconnect()


mqttc = mqtt.Client(client_id="mqt-est")
mqttc.on_connect = on_connect
mqttc.on_subscribe = on_subscribe
mqttc.on_message = on_message

mqttc.tls_set("/home/angel/share/root-CA.crt",
              certfile="/home/angel/share/certificate.pem.crt",
              keyfile="/home/angel/share/736e622c17-private.pem.key",
              tls_version=ssl.PROTOCOL_TLSv1_2,
              ciphers=None)

# connecting to aws-account-specific-iot-endpoint
mqttc.connect("A19WEVQQPFZLYK.iot.us-west-2.amazonaws.com", port=8883, )  # AWS IoT service hostname and portno

# automatically handles reconnecting
mqttc.loop_forever()
