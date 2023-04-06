from netaddr import IPAddress

p4ingress = bfrt.tcam.pipe.Ingress
p4egress = bfrt.tcam.pipe.Egress

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

# Final programming
print("""
******************* REGISTER RESULTS *****************
""")


print ("Ingress TS:")
p4ingress.tst_ing.dump(from_hw=True)
p4ingress.tst_ingg.dump(from_hw=True)

print ("Egress TS:")
p4egress.tst_ing.dump(from_hw=True)
p4egress.tst_ingg.dump(from_hw=True)
