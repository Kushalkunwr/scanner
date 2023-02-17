#!/usr/bin/python3
import scanner


#introduction
msg = scanner.Message()
msg.welcomeMsg()# description
scan= scanner.Network() #inititiating the scanner
runApp = True
while runApp == True: #for running the program until the user exits.
    #try:
        print ("\nEnter a specific number to perform the task")
        print ("1) To scan the whole network to find IP in use ")
        print ("2) To scan a specific host for open ports ")
        print ("3) To find specific vulnerabilities")
        print ("4) To exit")
        task = int(input("Type your input here  \n>>" ))
        if task == 1:
            scan.hostScan()
        elif task == 2:
            scan.portScan()
        elif task == 3:
            scan.vulnScan()
        elif task == 4:
            print("Are you sure?")
            exitProg = input("Enter 1 for YES.\nAny other key for NO>>")
            if exitProg == "1" :
                runApp = False

        else:
            print("Invalid input. Please check your input")


   # except: #In case of any invalid input
        print("Please check the input provided. \nThank you ")


