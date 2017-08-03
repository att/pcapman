# Function to get Flows From Pcap data


import time
from datetime import datetime
from datetime import timedelta

IpProtocol = {}
IpProtocol[0]="HOPOPT"
IpProtocol[1]="ICMP"
IpProtocol[6]="TCP"
IpProtocol[17]="UDP"
IpProtocol[47]="GRE"
IpProtocol[50]="ESP"
IpProtocol[132]="OTHER"

def GetUnixTime(timestamp):
    time_form1 = '%Y-%m-%d %H:%M:%S.%f'
    time_form2 = '%Y-%m-%d %H:%M:%S'
    time_form3 = '%m-%d %H:%M:%S'
    try :
        milis = timestamp[-3:]
        time0 = time.mktime(datetime.strptime(timestamp,time_form1).timetuple()) *1000 + int(milis)
        #(datetime.strptime(timestamp,time_form1)-datetime(1970,1,1)).microsecond
    except ValueError :
        time0 = time.mktime(datetime.strptime(timestamp,time_form2).timetuple())*1000 + int(milis)
    except ValueError : 
        time0 = time.mktime(datetime.strptime(timestamp,time_form3).timetuple())*1000 + int(milis)
    return time0



def GetFlowData(df, FlowData={}) :
    def UpdateFlows(flag,aflow,i):
        if flag :
            #print "This is a new flow : ", aflow
            flowdata[aflow] = {}
            flowdata[aflow]['Npackets']     = 1
            flowdata[aflow]['Indeces']      = [i]
            flowdata[aflow]['Timestamp']    = [GetUnixTime(df['Timestamp'][i])]
            flowdata[aflow]['PacketLength'] = [df['packetLength'][i]]
            flowdata[aflow]['FlowSize'] = df['packetLength'][i]
            flowdata[aflow]['TcpSequence']  = [df['tcpSequence'][i]]
            flowdata[aflow]['IPProtocols']  = [df['ipProtocol'][i]]
            if i > 0 :
                time1 = GetUnixTime(df['Timestamp'][i])
                time0 = GetUnixTime(df['Timestamp'][i-1])
                deltat   = (time1 - time0) #.total_seconds()*1000000000
                flowdata[aflow]['InterArrivalTime'] = [deltat]
        else:
            flowdata[aflow]['Indeces'].append(i)
            flowdata[aflow]['Npackets'] += 1
            flowdata[aflow]['Timestamp'].append(GetUnixTime(df['Timestamp'][i]))
            flowdata[aflow]['PacketLength'].extend([df['packetLength'][i]])
            flowdata[aflow]['FlowSize'] += df['packetLength'][i]
            flowdata[aflow]['TcpSequence'].extend([df['tcpSequence'][i]])
            flowdata[aflow]['IPProtocols'].append(df['ipProtocol'][i])
            if i > 0 :
                time1 = GetUnixTime(df['Timestamp'][i])
                time0 = GetUnixTime(df['Timestamp'][i-1])
                deltat   = (time1 - time0) #.total_seconds()*1000000000
                flowdata[aflow]['InterArrivalTime'].append(deltat)
        return flowdata

    # Initialize the New flowdata dictionary
    flowdata = FlowData
    flows  =  []
    ignoredflows = []
    flowcounter = {}
    flowflag = {}
    count_udp = 0
    count_tcp = 0
    count_syn = 0
    for i in df.index.values :
        try :
            ippcl =  IpProtocol[df.ipProtocol[i]]
        except KeyError :
            ippcl = "Other"
        aflow = str(df.srcIP[i])  + "_" + str(df.dstIP[i]) + "_" + str(df.srcPort[i])+ "_" + str(df.dstPort[i]) + "_" + ippcl
        if df.ipProtocol[i]== 17 :  
            flag = 0
            if aflow not in flows:
                flag = 1
                flows.append(aflow)
                count_udp +=1
            flowdata = UpdateFlows(flag,aflow+"_0",i) 
        elif df.ipProtocol[i]==6 :
            count_tcp +=1
            if aflow not in flowcounter.keys(): flowcounter[aflow]=0
            if aflow not in flowflag.keys():flowflag[aflow]=0
            if df.synFlag[i] == 1:
                count_syn +=1
                if aflow in flows:
                    flowcounter[aflow] += 1
                else:
                    flowflag[aflow] = 1
                flows.append(aflow)
                flowdata = UpdateFlows(flowflag[aflow],aflow+"_"+str(flowcounter[aflow]),i)
            elif df.synFlag[i] ==0 and df.finFlag[i] ==1:
                if aflow in flows:
                    flowdata = UpdateFlows(flowflag[aflow],aflow+"_"+str(flowcounter[aflow]),i) 
                    #flowcounter[aflow] += 1
                else :
                    #print "Igoring Flow as flow start data not available: ",aflow
                    ignoredflows.append(aflow)
            elif df.synFlag[i] ==0 and df.finFlag[i] == 0:
                if aflow in flows:
                    flowdata = UpdateFlows(flowflag[aflow],aflow+"_"+str(flowcounter[aflow]),i) 
                else:
                    #print "Igoring Flow as flow start data not available: ",aflow
                    ignoredflows.append(aflow)   
        else:
            ignoredflows.append(aflow)  
            
    print "Total Flows created : ", len(flows),"Ignore flows:", len(ignoredflows)
    print "UDP flow count :", count_udp
    print "TCP flow count :", count_tcp
    print "SYN flow count :", count_syn
    return flowdata
