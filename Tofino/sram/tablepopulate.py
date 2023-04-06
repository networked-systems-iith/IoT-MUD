import random
from random import randint

from netaddr import IPAddress



p4 = bfrt.devops.pipe.Ingress

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
# def clear_all(verbose=True, batching=True):
#     global p4
#     global bfrt
#
#     # The order is important. We do want to clear from the top, i.e.
#     # delete objects that use other objects, e.g. table entries use
#     # selector groups and selector groups use action profile members
#
#     for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],
#                         ['SELECTOR'],
#                         ['ACTION_PROFILE']):
#         for table in p4.info(return_info=True, print_info=False):
#             if table['type'] in table_types:
#                 if verbose:
#                     print("Clearing table {:<40} ... ".
#                           format(table['full_name']), end='', flush=True)
#                 table['node'].clear(batch=batching)
#                 if verbose:
#                     print('Done')

#clear_all(verbose=True)

#GLOBAL VARS
macList = []
macList.append('cc:cc:cc:cc:cc:cc')
mac = ""
genMAC = ""

#Table Sizes
mac = 700000
typE = 28
typD = 12
proto = 87
portE = 132
portD = 37
ipE = 432
ipD = 1


file1 = open('/home/tofinoswitch/iotmud/sram/maclist.txt', 'r')
Lines = file1.readlines()
p4.clear()
count = 1

#FILL MAC ADDRESS TABLE
smac = p4.sMAC_exact
smac.clear()
for line in Lines:
    count = count + 1
    var = line.strip()
    # print(i)
    smac.add_with_ns_exact(var, next_state=count)
    if count >= mac:
        break

smac.add_with_ns_exact('cc:cc:cc:cc:cc:cc', next_state=1)

typeth_exact = p4.typEth_exact
typeth_exact.clear()
for i in range(2,28):
    typeth_exact.add_with_ns_exact(i,'0x0800', next_state=i)
typeth_exact.add_with_ns_exact(1,'0x0800', next_state=1)

typeth_default = p4.typEth_default
typeth_default.clear()
for i in range(2,12):
    typeth_default.add_with_ns_default(i, next_state=i)
typeth_default.add_with_ns_default(1, next_state=1)

proto = p4.protocol_exact
proto.clear()
for i in range(2,87):
    proto.add_with_ns_exact(i, 17, next_state=i)
proto.add_with_ns_exact(1, 6, next_state=1)

dport_exact = p4.dPort_exact
dport_exact.clear()
for i in range(2,132):
    dport_exact.add_with_ns_exact(i, 55, next_state=i)
dport_exact.add_with_ns_exact(1, 7676, next_state=1)

dport_default = p4.dPort_default
dport_default.clear()
for i in range(2,37):
    dport_default.add_with_ns_default(i, next_state=i)
dport_default.add_with_ns_default(1, next_state=1)

ip_exact = p4.dstIP_exact
ip_exact.clear()
for i in range(2,432):
    ip_exact.add_with_ns_exact_last(i,IPAddress('10.11.12.33'),164)
ip_exact.add_with_ns_exact_last(1,IPAddress('10.11.12.13'),164)

ip_default = p4.dstIP_default
ip_default.clear()
for i in range(2,1):
    ip_default.add_with_ns_default_last(i, 164)
ip_default.add_with_ns_default_last(1, 164)



# ipv4_lpm =  p4.Ingress.ipv4_lpm
# ipv4_lpm.add_with_send(
#     dst_addr=IPAddress('192.168.1.0'), dst_addr_p_length=24, port=1)
# ipv4_lpm.add_with_drop(
#     dst_addr=IPAddress('192.168.0.0'), dst_addr_p_length=16)
# ipv4_lpm.add_with_send(
#     dst_addr=IPAddress('0.0.0.0'),     dst_addr_p_length=0,  port=64)

bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table sMAC_exact:")
# smac.dump(table=True)

print ("Table typEth_exact:")
typeth_exact.dump(table=True)
print ("Table typEth_default:")
typeth_default.dump(table=True)

print ("Table protocol_exact:")
proto.dump(table=True)

print ("Table dport_exact:")
dport_exact.dump(table=True)
print ("Table dport_default:")
dport_default.dump(table=True)

print ("Table ip_exact:")
ip_exact.dump(table=True)
print ("Table ip_default:")
ip_default.dump(table=True)
