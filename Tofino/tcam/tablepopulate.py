import random
from random import randint

from netaddr import IPAddress



p4 = bfrt.tcam.pipe.Ingress.aclrules

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
count = 0

file1 = open('/home/tofinoswitch/iotmud/tcam/maclist.txt', 'r')
Lines = file1.readlines()
p4.clear()

for line in Lines:
    count = count + 1
    var = line.strip()
    # print(type(var))
    p4.add_with_send('0x0800','0xffff', 6,'0xff', var,'0xffffffffffff', var,'0xffffffffffff', 6767, '0xffff', 7676, '0xffff', '10.11.12.13', '0xffffffff', '13.12.11.10', '0xffffffff')
    if count == 22480:
        break

p4.add_with_send('0x0800','0xffff', 6,'0xff', 'ab:cd:ab:cd:ab:cd','0xffffffffffff', 'ba:dc:ba:dc:ba:dc','0xffffffffffff', 6767, '0xffff', 7676, '0xffff', '10.11.12.13', '0xffffffff', '13.12.11.10', '0xffffffff')





# ipv4_lpm =  p4.Ingress.ipv4_lpm
# ipv4_lpm.add_with_send(
#     dst_addr=IPAddress('192.168.1.0'), dst_addr_p_length=24, port=1)
# ipv4_lpm.add_with_drop(
#     dst_addr=IPAddress('192.168.0.0'), dst_addr_p_length=16)
# ipv4_lpm.add_with_send(
#     dst_addr=IPAddress('0.0.0.0'),     dst_addr_p_length=0,  port=64)

# bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table ip_default:")
p4.dump(table=True)
