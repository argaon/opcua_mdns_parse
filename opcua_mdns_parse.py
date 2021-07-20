import socket
import binascii
import time
import struct

MDNS_GRP = '224.0.0.251'
MDNS_PORT = 5353
MULTICAST_TTL = 255

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
s.settimeout(5)

mdns_query = binascii.unhexlify('0000000000010000000000010a5f6f706375612d746370045f746370056c6f63616c00000c000100002905a000001194000c000400080000005056aa07a6')
#send MDNS PTR "QM" question, Name : _opcua-tcp._tcp.local

s.sendto(mdns_query,(MDNS_GRP,MDNS_PORT))

time.sleep(1)

while 1 :
    data, address = s.recvfrom(4096)
    res = data

    Answer_RRs = struct.unpack('!H',res[6:8])[0]       #Answer count
    Additional_RRs = struct.unpack('!H',res[10:12])[0] #Additional count
    
    Query_Name = res[12:35]
    Query_Type = res[35:37]
    Query_Class = res[37:39]
    print("Name : " , Query_Name.decode("utf-8","ignore"))

    pc = 39             #packet controller
    if Answer_RRs != 0: 
        for i in range(0,Answer_RRs):
            Answer_info = res[pc:pc+10]
            pc = pc +10
            Domain_Name_Len = struct.unpack('!H',res[pc:pc+2])[0]
            pc = pc + 2
#            print(Domain_Name_Len)
            Domain_Name = res[pc:pc + Domain_Name_Len]
            pc = pc + Domain_Name_Len
            print("Domain_Name : "+Domain_Name.decode("utf-8","ignore"))
            print("Last_PC : ",pc)
    else:
        print("No Answer_RRs")
    if Additional_RRs != 0:
        for i in range(0,Additional_RRs):
            print("Add start PC : ",pc)
            Add_Info = res[pc:pc + 2]
            pc = pc + 2
            Additional_Type = struct.unpack('!H',res[pc:pc+2])[0]
            print("Additional_Type : ", Additional_Type)
            pc = pc + 2 + 6
            Additional_Data_Len = struct.unpack('!H',res[pc:pc+2])[0]
            print("Additional_Data_Len : ",Additional_Data_Len)

            if Additional_Type == 0x21 :
                pc = pc + 2 + 4
                Add_port = struct.unpack('!H',res[pc:pc+2])[0]
                pc = pc + 2
                print("Port : " ,Add_port)
                Add_Target = res[pc:pc+Additional_Data_Len-7]
                pc = pc + Additional_Data_Len-6
                print("Target Name : "+ Add_Target.decode("utf-8","ignore"))
                print("Last pc : ",pc )
            else :
                pc = pc + Additional_Data_Len+2
                print("Last pc : ",pc )
    else:
        print("No Additional_RRs")


    if not res:
        break
    
s.close()
