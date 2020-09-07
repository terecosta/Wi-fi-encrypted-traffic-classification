import pyshark, numpy
import json
import matplotlib.pyplot as plt, itertools
from sklearn import svm

#Offline part / training part
#Variable for loading the testing files
files=["./Youtube_2p.pcapng","./Whatsup_p.pcapng","./Chrome_1p.pcapng"]

#Constants
MAC_MOBILE='a4:50:46:3d:fe:59'
MAC_AP='dc:53:7c:35:7d:65'
AV_PACKETS_OFFLINE=50
AV_PACKETS_ONLINE=10

#Initialization of the lists for SVM
X_u=[]
y_u=[]
X_d=[]
y_d=[]

print("The program of classifying traffic flows started!")
print("Doing the training part.")
for f in files:
    #Read the capture
    cap = pyshark.FileCapture(f)

    #Define the variables
    u_no_packets=0
    u_av_lenght=0
    u_av_rate=0
    u_av_inter_arrival=0
    u_inter_arrival=0.0
    d_no_packets=0
    d_av_lenght=0
    d_av_rate=0
    d_av_inter_arrival=0
    d_inter_arrival=0.0
    d_time_relative=0
    u_time_relative=0

    #initialize lists for loop on all packets captured
    u_list_arrival=[]
    u_list_length=[]
    u_list_data_rate=[]
    d_list_arrival=[]
    d_list_length=[]
    d_list_data_rate=[]

    #Capture of the current traffic flow,loop on the packets captured
    for packet in cap:
        try:            #used to deal with malformed packets
            if(packet.wlan.da == MAC_MOBILE and packet.wlan.sa==MAC_AP) :    #access only if the packet is a probe request.
                #Downlink. Features computed
                d_inter_arrival=float(packet.frame_info.time_delta)
                d_list_arrival.append(d_inter_arrival)
                d_time_relative=float(packet.frame_info.time_relative)

                d_packet_len=int(packet.frame_info.len)
                d_list_length.append(d_packet_len)
                d_data_rate=float(packet.wlan_radio.data_rate)
                d_list_data_rate.append(d_data_rate)
                d_no_packets+=1
                #Average of the features and add to the training part
                if d_no_packets==AV_PACKETS_OFFLINE:
                    X_d.append([numpy.mean(d_list_length), numpy.mean(d_list_data_rate)])
                    y_d.append(files.index(f))
                    d_list_arrival=[]
                    d_list_length=[]
                    d_list_data_rate=[]
                    d_no_packets=0

            elif (packet.wlan.sa == MAC_MOBILE and (packet.wlan.da==MAC_AP or packet.wlan.ta==MAC_AP)):
                #Uplink Features computed
                u_inter_arrival = float(packet.frame_info.time_delta)
                u_list_arrival.append(u_inter_arrival)
                u_time_relative=float(packet.frame_info.time_relative)
                u_packet_len=int(packet.frame_info.len)
                u_list_length.append(u_packet_len)
                u_data_rate=float(packet.wlan_radio.data_rate)
                u_list_data_rate.append(u_data_rate)

                u_no_packets+=1
                # Average of the features and add to the training part
                if u_no_packets==AV_PACKETS_OFFLINE:
                    X_u.append([numpy.mean(u_list_length), numpy.mean(u_list_data_rate)])
                    y_u.append(files.index(f))
                    u_list_arrival=[]
                    u_list_length=[]
                    u_list_data_rate=[]
                    u_no_packets=0


        except:
            print('some prob')
        pass    #skip if problems


    try:
        #Uplink
        #Average of the features and add to the training part
        if (len(u_list_length) != 0):
            u_av_rate=numpy.mean(u_list_data_rate)
            u_av_lenght=numpy.mean(u_list_length)
            u_av_inter_arrival=numpy.mean(u_list_arrival)

            X_u.append([u_av_lenght, u_av_rate])
            y_u.append(files.index(f))

        #Downlink
        # Average of the features and add to the training part
        if(len(d_list_length)!=0):
            d_av_rate=numpy.mean(d_list_data_rate)
            d_av_lenght=numpy.mean(d_list_length)
            d_av_inter_arrival=numpy.mean(d_list_arrival)

            X_d.append([d_av_lenght, d_av_rate])
            y_d.append(files.index(f))
        #Close the capture for not having errors
        cap.close()
    except:
        print("Error")

#Initialize the classifiers
print("Uplink traning samples")
print(X_u)
print(y_u)
print("Downlink traning samples")
print(X_d)
print(y_d)

weights_samples_u=[]
weights_samples_d=[]
#Put the weights on the samples, taking into account the number of samples of each traffic. Normalize
for cls in y_d:
    if cls==0:
        weights_samples_d.append(3)
    elif cls==1:
        weights_samples_d.append(28)
    elif cls==2:
        weights_samples_d.append(1)
for cls in y_u:
    if cls==0:
        weights_samples_u.append(2)
    elif cls==1:
        weights_samples_u.append(16)
    elif cls==2:
        weights_samples_u.append(1)


#Train the classifiers
clf_u = svm.SVC()
clf_u.fit(X_u, y_u,weights_samples_u)
clf_d = svm.SVC()
clf_d.fit(X_d, y_d,weights_samples_d)

print("Start the online part")
#Sniff

#Initialization of the list for flows
features_packet=[]
act_pack_len_u=[]
act_pack_rate_u=[]
act_pack_ia_u=[]
act_pack_len_d=[]
act_pack_rate_d=[]
act_pack_ia_d=[]
inter_arrival_act_d=0.0
inter_arrival_act_u=0.0
predict_flow=[]
packets_u=0
packets_d=0

#initialize the sniffing
cap_o = pyshark.LiveCapture(interface='wlo1', bpf_filter='(wlan host a4:50:46:3d:fe:59)')
print("Start sniffing packets")
#Analysis of the sniffing
for packet in cap_o.sniff_continuously():
    if len(packet.layers) == 4 and packet.highest_layer == 'DATA':
        if (packet.wlan.sa == MAC_MOBILE):

            inter_arrival_act_u = float(packet.frame_info.time_delta)
            act_pack_len_u.append(int(packet.frame_info.len))
            act_pack_rate_u.append(float(packet.wlan_radio.data_rate))
            act_pack_ia_u.append(inter_arrival_act_u)

            packets_u += 1

            if (packets_u == AV_PACKETS_ONLINE):
                print("Uplink")
                features_packet = [[numpy.mean(act_pack_len_u), numpy.mean(act_pack_rate_u)]]
                print(features_packet)
                act_pre = clf_u.predict(features_packet)
                print(act_pre)
                predict_flow.append(act_pre)

                packets_u = 0
                act_pack_ia_u = []
                act_pack_len_u = []
                act_pack_rate_u = []

        elif (packet.wlan.da == MAC_MOBILE):

            inter_arrival_act_d = float(packet.frame_info.time_delta)
            act_pack_len_d.append(int(packet.frame_info.len))
            act_pack_rate_d.append(float(packet.wlan_radio.data_rate))
            act_pack_ia_d.append(inter_arrival_act_d)
            packets_d += 1
            if (packets_d == AV_PACKETS_ONLINE):
                print("Downlink")
                features_packet = [[numpy.mean(act_pack_len_d), numpy.mean(act_pack_rate_d)]]
                print(features_packet)
                act_pre = clf_d.predict(features_packet)
                packets_d = 0
                act_pack_ia_d = []
                act_pack_len_d = []
                act_pack_rate_d = []
                print(act_pre)
                predict_flow.append(act_pre)
print("Final result")
print(predict_flow)
print(numpy.mean(predict_flow))
cap_o.close()
