import scapy.all as scapy

f = open('text.txt', 'w')
class MySniffer():
    def __init__(self):

        self.count = 0

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_sniffed_packet)

    def process_sniffed_packet(self, packet):
        print(packet)
        self.count += 1
        # f.write(self.count and str(packet) and "\n")
        self.string = str(self.count) + ") " + str(packet) + "\n\n"
        self.WriteDataToTXT(self.string)

    def WriteDataToTXT(self, text):
        f.write(str(text))


mySniff = MySniffer()
for i in range(100):
    mySniff.sniff("Ethernet")
f.close()

# f = open('text.txt', 'w')
# for i in range(100):
#     f.write("1\n")
# f.close()
