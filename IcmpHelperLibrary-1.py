# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select

import sys, signal

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        def __init__(self, helper):
            self.helper = helper

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):

            # confirm sequence number
            seq_num, reply_seq_num = self.getPacketSequenceNumber(), icmpReplyPacket.getIcmpSequenceNumber()
            if seq_num == reply_seq_num:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
            print(f"Sent packet sequence number: {seq_num}. recieved packet sequence number {reply_seq_num}.") if self.__DEBUG_IcmpPacket else 0
            
            # confirm packet identifier
            id, reply_id = self.getPacketIdentifier(), icmpReplyPacket.getIcmpIdentifier()
            if id == reply_id:
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            print(f"Sent packet identifier: {id}. recieved packet identifier {reply_id}.") if self.__DEBUG_IcmpPacket else 0

            # confirm raw data
            raw_data, reply_raw_data = self.getDataRaw(), icmpReplyPacket.getIcmpData()
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIcmpData_isValid(True)
            print(f"Sent packet raw data: {raw_data}. recieved packet raw data{reply_raw_data}.") if self.__DEBUG_IcmpPacket else 0

            # set the validity of the reply packet
            if icmpReplyPacket.getIcmpSequenceNumber_isValid() & icmpReplyPacket.getIcmpIdentifier_isValid() & icmpReplyPacket.getIcmpData_isValid(): 
                icmpReplyPacket.setIsValidResponse(True)
            print(f"Icmp reply packet is valid: {icmpReplyPacket.isValidResponse()}") if self.__DEBUG_IcmpPacket else 0

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, tracerouteBool=False):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))

                self.helper.incPacketsSent()                        # count packets sent

                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                    return False
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    return False

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded

                        codeTxt = "(Time to Live exceeded in Transit)"          # only two possible codes with type 11
                        if icmpCode == 1:
                            codeTxt = "(Fragment Reassembly Time Exceeded)"

                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d %s   %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    codeTxt,
                                    addr[0]
                                )
                              )
                        return False

                    elif icmpType == 3:                         # Destination Unreachable

                        codeTxt = self.helper.getIcmpCode(icmpCode)   # let the helper get the icmp code txt

                        if not codeTxt:
                            codeTxt = "other Icmp code"

                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d %s   %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      f"({codeTxt})",
                                      addr[0]
                                  )
                              )
                        return False

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self, tracerouteBool)
                        return True     # Echo reply is the end and therefore should return

                    else:
                        print("error")
                        return False
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
                return False
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()


    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # variables that identify whether each value that can be obtained from the class is valid
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

            # variables that identify whether each value that can be obtained from the class is valid
            self._icmpSequenceNumber_isValid = False
            self._icmpIdentifier_isValid = False
            self._icmpData_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse
        
        def getIcmpSequenceNumber_isValid(self):
            return self._icmpSequenceNumber_isValid
        
        def getIcmpIdentifier_isValid(self):
            return self._icmpIdentifier_isValid
        
        def getIcmpData_isValid(self):
            return self._icmpData_isValid

        def getTTL(self):
            return self.__unpackByFormatAndPosition("B", 8)

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpSequenceNumber_isValid(self, boolean):
            self._icmpSequenceNumber_isValid = boolean

        def setIcmpIdentifier_isValid(self, boolean):
            self._icmpIdentifier_isValid = boolean

        def setIcmpData_isValid(self, boolean):
            self._icmpData_isValid = boolean

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, sentPacket, traceroutBool=False):
            """
                Print individual echo request reply packet information and store the information for later statistics: 
                    - packet info
                    - packet validity
                    - display error response code
            """
            line = ""
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            rtt = round((timeReceived - timeSent) * 1000, 1)

            # add ping info
            if not traceroutBool:
                line += f"    Recieved data from {addr[0]}: ICMP_Seq={self.getIcmpSequenceNumber()} TTL={self.getTTL()} RTT={rtt} ms"
            
            # add traceroute info
            else:
                line += f"    TTL={ttl}    RTT={rtt} ms    Type={self.getIcmpType()}    Code={self.getIcmpCode()}   {addr[0]}"
            
            # add validity errors
            if self.isValidResponse():                                  # is valid reply or not
                line += " (echo reply is valid)"
            else:
                line += " (echo reply is not valid:"
                if not self.getIcmpSequenceNumber_isValid():                    # sequence number validity
                    line += f" invalid sequence number: Expected: {sentPacket.getIcmpSequenceNumber()} Actual: {self.getIcmpSequenceNumber()}"
                if not self.getIcmpIdentifier_isValid():                        # identifier validity
                    line += f" invalid packet identifier: Expecetd: {sentPacket.getIcmpPacketIdentifier()} Actual: {self.getIcmpIdentifier()}"
                if not self.getIcmpData_isValid():                              # raw data validity
                    line += f" invalid packet Data: Expected: {sentPacket.getDataRaw()} Actual: {self.getIcmpData()}"
                line += ")"

            print(line)

            # collect stats
            sentPacket.helper.collectRTTStats(rtt)         

            
            

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    icmpCodes = { 0:"Net Unreachable", 1:"Host Unreachable" , 2:"Protocol Unreachable", 3:"Port Unreachable", 4:"Fragmentation Needed and Don't Fragment was Set", 5:"Source Route Failed", 6:"Destination Network Unknown", 7:"Destination Host Unknown", 8:"Source Host Isolated", 9:"Comm with Dest Net is admin prohibited", 10:"Comm with Dest Host is admin prohibited", 11:"Dest Net Unreachable for Type of service", 12:"Dest Host Unreachable for Type of service", 13:"Commm Admin Prohibited", 14:"Host Precedence Violation", 15:"Precedence cutoff in effect"}
    targetHost = ""
    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output
    
    # data for ping statistics
    __packetsSent = 0
    __minRTT = 1_000_000_000
    __maxRTT = 0
    __RTTs = []

    def __init__(self):
        signal.signal(signal.SIGINT, self.__signalHandler) # register the signal handler 
        # signal register source: stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
    
    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host, ttl=False):
        """"
            actions depend on traceroute bool.
        """
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # print the initial ping line
        if not ttl:
            destAddr = ""
            try:
                destAddr = gethostbyname(host.strip())
            except:
                exit("could not resolve hostname")
            print(f"PINGING {host} ({destAddr})")

        loops = 4
        if ttl:
            loops = 1 
        for i in range(loops):

            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket(self)

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            # if this is trace route set the ttl
            if ttl:
                icmpPacket.setTtl(ttl)

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            reachedDestination = icmpPacket.sendEchoRequest(bool(ttl))                # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        if not ttl:
            print(f"- - - {host} PING statistics - - -")
            self.__printStatistics()

        return reachedDestination
            

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        
        reachedDest = False
        ttl = 0

        # continue sending packets with increasing TTL untill the destination is reached or user send SIGINT
        while not reachedDest:        
            ttl += 1
            reachedDest = self.__sendIcmpEchoRequest(host, ttl)

        # show stats
        destAddr = ""
        try:
            destAddr = gethostbyname(host.strip())
        except:
            exit("could not resolve hostname")
            print(f"PINGING {host} ({destAddr})")
        print(f"- - - {host} ({destAddr}) Traceroute statistics - - -")
        self.__printStatistics()

    def __printStatistics(self):
        rtts = self.getRTTs()
        sent, recieved = self.getPacketsSent(), len(self.getRTTs())
        ratio = (sent-recieved) / sent
        avg = round(sum(rtts) / recieved, 1)
        print(f"{sent} packets transmitted, {recieved} received, {ratio:.2%} packet loss\nMin RTT: {self.getMinRTT()}, Max RTT: {self.getMaxRTT()} Avg RTT: {avg}")     

    def __signalHandler(self, sig, frame):  
        print(f"- - - {self.targetHost} statistics - - -")
        self.__printStatistics()

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        self.__sendIcmpEchoRequest(targetHost)
        self.targetHost = targetHost

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.targetHost = targetHost
        self.__sendIcmpTraceRoute(targetHost)

    # getters

    def getPacketsSent(self):
        return self.__packetsSent

    def getMinRTT(self):
        return self.__minRTT
        
    def getMaxRTT(self):
        return self.__maxRTT
        
    def getRTTs(self):
        return self.__RTTs
    
    def getIcmpCode(self, code):
        try:
            return self.icmpCodes[code]
        except KeyError:
            return False
    
    # setters

    def incPacketsSent(self):
        self.__packetsSent += 1
        
    def setMinRTT(self, rtt):
        self.__minRTT = rtt
        
    def setMaxRTT(self, rtt):
        self.__maxRTT = rtt
        
    def addToRTTs(self, rtt):
        self.__RTTs.append(rtt)

    def collectRTTStats(self, rtt):
        if self.getMinRTT() > rtt:         
            self.setMinRTT(rtt)
        if self.getMaxRTT() < rtt:
            self.setMaxRTT(rtt)
        self.addToRTTs(rtt)

# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")


if __name__ == "__main__":
    main()
