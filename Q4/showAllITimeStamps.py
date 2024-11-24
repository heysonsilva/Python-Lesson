import struct, datetime

fd = open ("./2024-nov-05--cap01.pcap", "rb")

fd.seek(24, 0)
nPacket = 0
packetHeader = fd.read(16)
while packetHeader != b'':
    ts, mTs, capLen, capOrig = struct.unpack("<IIII", packetHeader)
    nPacket += 1
    print (f"#{nPacket}: {datetime.datetime.fromtimestamp(ts)}")
    packet = fd.seek(capLen, 1)
    packetHeader = fd.read(16)
fd.close()