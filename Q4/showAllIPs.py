import struct

fd = open ("./2024-nov-05--cap01.pcap", "rb")

fd.read(24)

packetHeader = fd.read(16)

while packetHeader != b'':
    ts, mTs, capLen, capOrig = struct.unpack("<IIII", packetHeader)
    packet = fd.read(capLen)
    if packet[12:14] == b'\x08\x00':
        ipPacket = packet[14:]
        ipSrc = [str(ipPacket[i]) for i in range(12, 16)]
        ipDst = [str(ipPacket[i]) for i in range(16, 20)]
        
        ipSrc = ".".join(ipSrc)
        ipDst = ".".join(ipDst)
        print (f"{ipSrc} -> {ipDst}")
    packetHeader = fd.read(16)
    
fd.close()