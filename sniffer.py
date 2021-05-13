import re
from datetime import datetime
import scapy.all as scapy

f = open('snifferActive.txt', 'w')


class MySniffer():
    def __init__(self):
        self.count = 0

    def sniff(self, interface: str) -> None:
        scapy.sniff(iface=interface, store=False, prn=self.process_sniffed_packet)

    def process_sniffed_packet(self, packet):
        str_packet = str(packet)
        project, result, time = self.RegularPacketTest_1(str_packet)
        if (project != "" and result != ""):
            # print(project, result, time)
            self.count += 1
            # string = str(self.count) + ") " + str(str_packet) + "\n\n"
            string = str(self.count) + ") " + str(project) + " " + str(result) + str(time) + "\n\n"
            # print(string)
            self.WriteDataToTXT(string)

    def WriteDataToTXT(self, text) -> None:
        f.write(str(text))

    def RegularPacketTest_1(self, packet) -> tuple:
        # packet = "4234tart MLDR100 0x7F 0x5F 0x7F 0x3F 0x1F end43342"
        print(packet)
        project = ""
        result = ""
        if re.findall(r'^.*start\s(MLDR\w+)', packet):
            project = re.findall(r'^.*start\s(MLDR\w+)', packet)[0]
        # print(type(project))
        if re.findall(r'^.*start\sMLDR\w+\s(.*?)end', packet):
            result = re.findall(r'^.*start\sMLDR\w+\s(.*?)end', packet)[0]
        time = datetime.now()
        # print(project, result, time)
        # project = result = time = ""
        return project, result, time


mySniff = MySniffer()
for i in range(100):
    mySniff.sniff("Ethernet")
    # mySniff.sniff("Беспроводная сеть")
f.close()

# f = open('text.txt', 'w')
# for i in range(100):
#     f.write("1\n")
# f.close()
