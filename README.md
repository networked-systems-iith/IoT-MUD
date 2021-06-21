# IoT-MUD

Step 1: Go To Flow Rules Folder.

Step 2: Unzip the JSON folder to get the Json files of each IOT Devices

Step 3: Run the Flowrules.ipynb file and the obtained rules are stored in "project_data_final.csv"

Step 4: Go to the Folder BDD Implementation

Step 5: Run the BDD_Implementation.ipynb file

Step 6: Convert BDD tables into Sub-tables using BDD_tables_to_switch_commands.ipynb file

Step 7 : Go to the Folder BDD Implementation/P4/without BDD

Step 8: Compile the MUD.p4 code

Step 9: Load the rules into switch using load_rules_python.py file

Step 10: Verify the out_without_bdd.txt to make sure all the rules got loaded in the switch

Step 11: Go to the Folder BDD Implementation/P4/with BDD

Step 12: Compile the BDD1.p4 code

Step 13: Load the rules into switch using load_rules_python.py file

Step 14: Verify the outbdd.txt to make sure all the rules got loaded in the switch
