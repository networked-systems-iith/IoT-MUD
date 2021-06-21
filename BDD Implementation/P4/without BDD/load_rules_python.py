import argparse
from subprocess import Popen
from p4utils.utils.topology import Topology
import time
import math

parser = argparse.ArgumentParser()
parser.add_argument('--duration', nargs='?', type=int, default=40, help='Duration of traffic')


args = parser.parse_args()
duration= args.duration

start_time= time.time()
pid_list = []

prev_list_normal=[]
current_list_normal=[]

iteration_number=0

g=0
window_count= -1
for i in range(0,1):
	window_count= window_count + 1
	time.sleep(5)
	p1=(Popen("simple_switch_CLI --thrift-port 9090 < commands.txt >out_without_bdd.txt",shell=True))
	p1.wait()

	myfile1=open("out11.txt","r")
	count1=0
	line1 = myfile1.readlines()
	#print(line1)
	line_to_read1= line1[1]
	required_array1= line_to_read1[21:-1]
	temp1= required_array1.split(" ")
	my_reg1=[]
	for val in temp1:
		my_reg1.append(val)
	
	myfile1.close()


	

#	for i in range(0,len(my_reg1)):
#		my_reg1[i]= int(my_reg1[i])





	