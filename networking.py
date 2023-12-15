import pyshark
import pandas as pd

vizioIp = "192.168.1.110"
offState = "OffStatePackets.pcapng"
menuState = "MenuStatePackets.pcapng"
appState = "ApplicationStatePackets.pcapng"

def readPacketSize(filename):
    #Read Packet information from the file based on the IP address
    cap = pyshark.FileCapture(filename, display_filter='ip.addr == ' + vizioIp, only_summaries=True)
    fileData = []

    for p in cap:
        fileData.append(int(p.length))

    #Calculate the total number of packets in the file
    numberOfPackets = len(fileData)

    #Calculate the total size of the packets and the average size of the packets
    fileDataSize = sum(fileData)
    avgPacketSize = fileDataSize / numberOfPackets

    #Stop the capture
    cap.close()
    return fileDataSize, avgPacketSize

def packetInterval(filename):
    #Read Packet information from the file based on the IP address
    cap = pyshark.FileCapture(filename, display_filter='ip.addr == ' + vizioIp)

    #Initial value for interval calulation and list to store the intervals
    startTime = 0
    firstPacket = True
    intervals = []

    #load the intervals from the capture
    for p in cap:
        #Check for only TCP packets
        if 'TCP' in p:
            packetTime = float(p.sniff_timestamp)
            if not firstPacket:
                interval = packetTime - startTime
                intervals.append(interval)
            else:
                firstPacket = False
            #Store the start time for the next packet
            startTime = packetTime

    #calulate the average interval
    avgInterval = sum(intervals) / len(intervals)
    cap.close()
    return(avgInterval)

def retransmissions(filename):
    #Read Packet information from the file based on the IP address
    cap = pyshark.FileCapture(filename, display_filter='ip.addr == ' + vizioIp)

    #initialize the number of retransmissions
    numOfRetransmissions = 0
    for p in cap:
        if 'TCP' in p:
            if hasattr(p.tcp, 'analysis_retransmissions'):
                numOfRetransmissions += 1
    
    cap.close()
    return(numOfRetransmissions)



def main():
    #Run data through all the functions
    offStatePackets = readPacketSize(offState)
    menuStatePackets = readPacketSize(menuState)
    appStatePackets = readPacketSize(appState)

    offStateIntervals = packetInterval(offState)
    menuStateIntervals = packetInterval(menuState)
    appStateIntervals = packetInterval(appState)
                                   
    offStateRetransmissions = retransmissions(offState)
    menuStateRetransmissions = retransmissions(menuState)
    appStateRetransmissions = retransmissions(appState)

#Create a dataframe to store the data
    data = [
        {"State": "Off", "Size of packets": offStatePackets[0], "Average packet size": offStatePackets[1], "Average Interval": offStateIntervals, "Number of Retransmissions": offStateRetransmissions},
        {"State": "Menu Screen", "Size of packets": menuStatePackets[0], "Average packet size": menuStatePackets[1], "Average Interval": menuStateIntervals, "Number of Retransmissions": menuStateRetransmissions},
        {"State": "In Application", "Size of packets": appStatePackets[0], "Average packet size": appStatePackets[1], "Average Interval": appStateIntervals, "Number of Retransmissions": appStateRetransmissions}
        ]

    df = pd.DataFrame(data)
    print(df)

if __name__ == "__main__":
    main()