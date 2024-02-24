import socket
from sg_ip import dns_to_ip

port = 53
ip = '0.0.0.0'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def getflags(flags):
    byte1, byte2 = flags

    QR = 1  # Response
    OPCODE = (byte1 & 120) >> 3  # Opcode is bits 4-7 of byte 1
    AA = (byte1 & 4) >> 2  # Authoritative Answer
    TC = (byte1 & 2) >> 1  # Truncated Response
    RD = byte1 & 1  # Recursion Desired

    # Byte 2
    RA = (byte2 & 128) >> 7  # Recursion Available

    # Other flags are set to 0
    Z = 0
    RCODE = 0

    # Construct 16-bit flags
    flags_int = (QR << 15) | (OPCODE << 11) | (AA << 10) | (TC << 9) | (RD << 8) | (RA << 7) | (Z << 4) | RCODE

    return flags_int.to_bytes(2, byteorder='big')

def getquestiondomain(data):
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    ip_address = dns_to_ip('.'.join(domain))

    print('.'.join(domain))
    
    if ip_address is not None:
        return ([{'ttl': 3600, 'value': ip_address}], 'a', domain)
    else:
        # Handle the case where DNS resolution fails
        return ([], None, domain)

def buildquestion(domainname, rectype):
    qbytes = b''
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')
    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')
    qbytes += (1).to_bytes(2, byteorder='big')
    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    rbytes = b'\xc0\x0c'
    if rectype == 'a' and recval is not None:
        rbytes = rbytes + bytes([0]) + bytes([1])
        rbytes = rbytes + bytes([0]) + bytes([1])
        rbytes += int(recttl).to_bytes(4, byteorder='big')
        rbytes = rbytes + bytes([0]) + bytes([4])
        # for part in recval.split('.'):
        #     rbytes += bytes([int(part)])
    else:
        # Handle the case where there are no A records
        rbytes = b'\xc0\x0c' + bytes([0]) + bytes([1]) + bytes([0]) + bytes([1]) + int(recttl).to_bytes(4, byteorder='big') + bytes([0]) + bytes([0])
    
    return rbytes

def buildresponse(data):
    # Transaction ID
    TransactionID = data[:2]

    # Get the flags
    Flags = getflags(data[2:4])

    # Question Count
    QDCOUNT = b'\x00\x01'

    # Answer Count
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additonal Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # Create DNS body
    dnsbody = b''

    # Get answer for query
    records, rectype, domainname = getrecs(data[12:])

    dnsquestion = buildquestion(domainname, rectype)

    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody

while True:
    data, addr = sock.recvfrom(512)
    r = buildresponse(data)
    sock.sendto(r, addr)