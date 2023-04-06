import random
from random import randint

macList = []
macList.append('cc:cc:cc:cc:cc:cc')
mac = ""
genMAC = ""


#FUNCTIONS
def checkUniqueMAC(macAddr):
    global macList
    for mac in macList:
        if mac == macAddr:
            return True
    return False

with open('maclist.txt', 'w') as f:
    for i in range(2,700000):
    # print(i)
        mac = [ random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
        genMAC = ':'.join(map(lambda x: "%02x" % x, mac))
        while checkUniqueMAC(genMAC):
            mac = [ random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
            genMAC = ':'.join(map(lambda x: "%02x" % x, mac))

        macList.append(genMAC)
        f.writelines(genMAC + '\n')






# mac = [ 0x94, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
# genMAC = ':'.join(map(lambda x: "%02x" % x, mac))
# while checkUniqueMAC(genMAC):
#     mac = [ 0x94, 0x16, 0x3e, random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
#     genMAC = ':'.join(map(lambda x: "%02x" % x, mac))
