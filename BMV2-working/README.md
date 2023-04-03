**Components and technologies used:**

-   **MUD File server**

    Microweb Python framework **Flask** is used to create a private MUD
    file server that advertises the MUD files and their
    corresponding signatures. It is an HTTPS server that uses port 443.

    ![image](https://user-images.githubusercontent.com/42608920/165620963-e8ee1715-834d-4298-907e-e6bf1a103f9a.png)

-   **MUD Files**

    We utilize MUD profiles for 28 consumer IoT devices generated by [UNSW
    Sydney](https://iotanalytics.unsw.edu.au/mudprofiles).

-   **Signature Files**

    Signature files are needed to verify that the device is responsible
    for the MUD file. MUD file signature is generated as a SHA1 message
    digest using OpenSSL RSA private key.

-   **Router/Switch**

    BMv2 switch is chosen as a tool for testing and debugging code
    written on control planes and data planes.

-   **IoT Devices**

    Mininet-IoT is used to emulate a network of IoT devices via nodes
    and links.
    
____

**Flow of messages**

![image](https://user-images.githubusercontent.com/42608920/172326109-fbe5edd6-541b-4b56-a41f-ee6f00b7f887.png)

Once the Mininet environment is set up, the host sends DHCP packets
to the switch using **generatepackets.py**. To generate DHCP
packets, we import sendp() from scapy with source IP set to 0.0.0.0.

The switch is configured to forward DHCP packets to the controller
via virtual port 510. When the controller receives packet-in
messages, it extracts the URL from the packet payload, requests the
MUD file from the server, verifies the signature file using the
public key, and subsequently, the MUD file is sent to
**processMUD.py**.

At **processMUD.py**, the MUD file is converted from a simple
flattened JSON file into a Pandas DataFrame, which is next directed
to **resolve.py**. The domain names are resolved to IP addresses
using the **gethostbyname()** function. Subsequently, the resolved
ACL rules are sent to decisiontree.py

The **decisiontree.py** has two tasks: converting resolved ACL rules
to a decision tree and adding corresponding table rules to
the switch.

A decision tree is a k-ary search tree to store rules while avoiding
repetitions and optimizing time. A decision tree starts with the
root and travels through 8 levels before deciding to forward or drop
the packet. Any two nodes are siblings if they have the same parent,
and **isPresent** is a Boolean variable that indicates whether the
node is already in the tree or not. Another variable,
**levelCounter,** keeps track of the number of sets of siblings at a
particular level. An ACL rule is defined as a list of 8 elements –
corresponding to the eight tuple format.

Three parameters uniquely identify each node:

1.  **state** – that depends on the previous node values,

2.  **levelheader** determines the current column name – e.g., sMAC,
    destIP, etc.

3.  value at that node.

To insert a new ACL rule in a decision tree, the following rules are to
be observed:

1.  In case of new insertion of a path:

-   At the first level, if **isPresent** is false, **levelCounters** is
    incremented by 1.

-   If the current node has at least one child, the state of the new
    node will be the same as that of the first child of the
    current node.

-   If the current node has no child, **levelCounters** is incremented
    by 1.

2.  If the node is already present, iterate to the next header field of
    the rule.

3.  If the node is not present, define the new node using the three
    parameters, add it to the tree and iterate to the next header field
    of the rule.

    Once the rule is added to the tree, it is converted to table rules which
are installed in the switch.


___

**Instructions to run the code and testing correctness** :

1. Download and extract the zipped folder.  
2. Execute **installations.sh**
3. change the absolute location of MUD files in switch.py, (around lines 29, 115 and 138) and processMUD.py(line 32).
4. To start MUD server, go to **MUDserver/webapp**, open in terminal and run **sudo python3 mudserver.py**
5. Go to ScaleIoT folder, and run **make** in terminal. The mininet environment will be setup.
6. Open new terminal in the ScaleIoT folder and type **./controller.py**.
7. **IMPORTANT** - Ensure that in generatePackets.py, send_DHCP(iface) (around line 272) is uncommented and  correctness_openFile(iface) is commented, when you want to send DHCP packets from the source h1. 
8. In the mininet environment, type **xterm h1**, and in node h1, type **python3 generatePackets.py**. This will generate and send  a DHCP packet from host h1(which is the IoT device) to the switch s1, and start the aforementioned circuit. Now, according to the MUD URL specified in the DHCP packet, the MUD file will be downloaded and processed to flow rules which will be installed on the switch.
9.  **IMPORTANT** - Once DHCP packets are sent, open **template.csv** and update the header fields according to the traffic that you would like to generate from the IoT device h1. Once changes are done, comment out **send_DHCP(iface)**, and uncomment correctness_openFile(iface) in the **generatePackets.py**.
10.  To test the correctness of p4 logic, open two terminals, and type **sudo & wireshark** in both. Choose **s1-eth1** and **s2-eth2**. 
11.  Now, in the mininet environment, type **xterm h1**, and in node h1, type **python3 generatePackets.py**. This will generate a stream of packets from host h1(which is the IoT device) to the switch s1, and based on the table rules, the switch will either forward it to h2, or drop it.

**The packet that gets through the switch will be displayed in both the wireshark traces, while the one that gets dropped will be displayed only in s1-eth1 trace but not in s1-eth2.**

For instance, here are the wireshark traces after testing for Amazon Echo: 

![image](https://user-images.githubusercontent.com/42608920/172308787-8b9cb8ee-5f0c-4f7b-8007-d6d60900ddb4.png)

___