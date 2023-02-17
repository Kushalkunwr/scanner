#!/usr/bin/python3
import os ;
import nmap;
import pandas as pd;
import glob;


nm= nmap.PortScanner() #calling the port scanner

class Message():
    @staticmethod
    def welcomeMsg():
        print("|        | |--------- |         |--------- |---------| |\      /| |---------")
        print("|        | |          |         |          |         | | \    / | |")
        print("|        | |          |         |          |         | |  \  /  | |")
        print("|   /\   | |------    |         |          |         | |   \/   | |------")
        print("|  /  \  | |          |         |          |         | |        | |")
        print("| /    \ | |          |         |          |         | |        | |")
        print("|/      \| |--------- |-------- |--------- |---------| |        | |---------")
        print("\n\n\t\t\t The Reconnainsance tool")
        print("\t\t\tCreated by: Kushal Kunwar")
        print("\t\t\t  Version 1.0.0\n\n")

    def otherMessages():
        print("Description")

    def displayCsv(path):
        print ("List of the csv files")
        path = path
        extension = 'csv'
        os.chdir(path)
        result = glob.glob('*.{}'.format(extension))

        print("\n", result, "\n")
        os.chdir('../')



class Error():
    @staticmethod
    def errorMessage():
        print("\nThe input that you have provided is invalid.Please re-eneter the value\n")
        

errorMsg = Error() # declaring a variable for the class


class Network():#initiating the network
    @staticmethod
    #host scan
    def hostScan() :
        runHostScan = True # initiating a variable
        while runHostScan == True: # looping the program up until the user exits
            #Description
            print("\nEnter a specific number to perform the task")
            print("1) To continue Network Scanning.")
            print("2) To go to the port Scanner")
            print("3) To manually find exploits")
            print("4) To go to the main menu")
            scanHost = input("Type your answer.\n>>")
            scanHost = scanHost.strip() # stripping all the spaces

            #checking the input of the user
            if scanHost == "1": #if the user wants to continue the host scan 
                ipAddr="incorrect" #initiating the varible
                count = 0 #for counting hosts alive
                while ipAddr == "incorrect":# running the loop until the user exits out
                    print("Enter the IP address of the network. E.g 192.168.1.1") 
                    netIP = input(">>")#taking the IP address of the network as an input

                    if len(netIP) != 0: #checking if the input is empty

                        addrPrefix= "incorrect"#initiating the variable

                        while addrPrefix == "incorrect" : # looping the program up until the user exits
                            print("Enter the network prefix. E.g 24") 
                            netPrefix = input(">>") #entering the prefix/ CIDR notation of the net
                            
                            if len(netPrefix) != 0: # checking if the prefix is empty or not
                                netAddr= (netIP+'/'+netPrefix) #creating a network with prefix
                                print("The value you have inserted is: ")
                                print ("Network IP address/CIDR = "+netAddr ) #display the network
                                print ("\nIs the information correct?")
                                print ("1)Yes \n2)No \nEnter 1 or 2")
                                check = input (">>") #taking input for checking if the value is correct
                                check = check.strip() #removing spaces if any
                                
                                if check == "1": #if the entered value is correct
                                    print("\nDiscovering open ports. This might take a few moments.")
                                    nm.scan(hosts=netAddr, arguments='-n -sP -PE -PA21,23,80,3389 -T3') #to find the number of hosts alive
                                    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()] #to create list of all the hosts
                                    print("\nThe hosts in the ip are: ")
                                    
                                    for host in nm.all_hosts():
                                        print ('HOST : %s \tSTATE : %s' % (host, nm[host] ['status']['state'])) # to list all the host ip and state
                                        count = count + 1
                                    ipAddr = "correct"  # to exit the inside loop
                                    addrPrefix = "correct"  # to exit the outside loop
                                    print("The total hosts alive = ",count)
                                    
                                    if count != 0: #if any host is discovered

                                        print("\nDo you want to save the csv output?")
                                        print("Enter 1 to save and any value to not save") 
                                        saveFile = input(">>")
                                        save_path = './hostCsv'  
                                        saveFile = saveFile.strip()
                                        if saveFile == "1":
                                            insertFile = True
                                            while insertFile ==True:
                                                print("Enter the file name to be saved as: ")
                                                fileName = input(">>")
                                                if len(fileName)!= 0:
                                                    fileName = os.path.join(save_path, fileName+".csv")
                                                    print (nm.all_hosts(),file=open(fileName,'w'))
                                                    print("Your output has been saved in the "+ fileName + "file")
                                                    insertFile = False
                                                else:                     
                                                    print("Please enter a valid name") 

                                        print("\n1) Continue to port scanner")
                                        print("2) Enter any value to go back")
                                        goToPort = input(">>") #to either go to portScanner or go back
                                        goToPort = goToPort.strip() #to remove spaces if any
                                        if goToPort == "1":
                                            Network.portScan()#go to port scanner

                                    else: 
                                        print("Sorry no alive host discovered.") #if there is no host the following message is displayed
                                elif check == "2" :
                                    addrPrefix = "correct" # For going bak the loop to re-enter the value
                                else:
                                    errorMsg.errorMessage() # displaying error message

                            else:
                                print("Invalid network prefix") 
                                errorMsg.errorMessage() # displaying error message
                    
                    else:
                        print("Please recheck the network Ip address.\n")
                        errorMsg.errorMessage() #displaying error message
                
                


            elif scanHost == "2":
                Network.portScan() #got o port scanner

            elif scanHost == "3":
                Network.vulnScan() #go to exploit searching

            elif scanHost == "4":
                runHostScan = False #exiting the scanner / going to the main menu

            else:
                errorMsg.errorMessage() #for invalid input


    @staticmethod
    #port Scan
    def portScan() :
        count = 0
        runPortScan = True # initiating a variable
        while runPortScan == True:
            print("1) Enter 1 to continue to Port Scanning.")
            print("2) To manually find exploits")
            print("3) Enter 3 to go to back to the Network Scanner")
            print("4) Enter 4 to go to the main menu")
            scanPort = input("Type your answer.\n>>")
            scanPort = scanPort.strip() # stripping all the spaces

		    #checking the input of the user
            if scanPort == "1":
                runScan= True
                while runScan == True: #for running the program until the user exits the program

                    #these run after the creation of the file.
                    showResultLoop = True

                    while showResultLoop == True:
                        print("Do you want to show the results from the hostScan?")
                        print("1)Yes \n2)No \nEnter 1 or 2")
                        showResult= input(">>")
                        showResult = showResult.strip()
                        if showResult == "1":
                            Message.displayCsv('./hostCsv')
                            displayFile = True
                            while displayFile == True :
                                try:
                                    fileName= input("Enter the name of the file you want to input\nEnter filename with the extension Example: filename.csv:\n>>")
                                    if len(fileName)!=0:
                                        fileName = os.path.join("./hostCsv/",fileName)
                                        '''print(fileName)
                                        df = pd.read_csv( fileName )'''
                                        host_file = open(fileName, "r")
                                        lines = host_file.read().split(',')
                                        print("The alive host from the previous scan are")
                                        for each in lines:
                                            print (each)
                                        host_file.close()
                                        
                                        displayFile = False
                                        

                                    else:
                                        print("Empty field, Please recheck the input.")

                                    showResultLoop = False

                                
                                except:
                                    print("Error:\n Either the file doesn't exist\nor the file is empty\nPlease recheck and enter the value again")
                                    print("Do you want to exit this process?")
                                    contin = input("1) Yes\n2) N0\n>>")
                                    contin = contin.strip()
                                    if contin == 1:
                                        displayFile = False
                                
                            else:
                                print("The folder is empty")
                                showResultLoop = False
                        elif showResult == "2":
                            print("---------------------------------------------")
                        else:
                            errorMsg.errorMessage()

                    print("Enter the Ip address of the host that you would like to scan")
                    hostAddr= input(">>")   #taking IP address to be scanned as an input                             

                    if len(hostAddr) != 0:
                        print ("The ip you have entered is : ", hostAddr)
                        print ("\nIs the information correct?")
                        print ("1)Yes \n2)No \nEnter 1 or 2")
                        check = input (">>") #taking input for checking if the value is correct
                        check = check.strip() #removing spaces if any

                        if check == "1": 
                            print("\nDiscovering open ports. This might take a few moments.")
                            nm.scan(hostAddr ) #to find the number of hosts alive
                            print("\nThe hosts in the ip are:") #message
                            
                        
                            for host in nm.all_hosts(): #to get all the host's information
                                print('Host : %s (%s)' % (host, nm[host].hostname())) #to show the IP of the host
                                print('State : %s' % nm[host].state()) # to show the state of host
                                for proto in nm[host].all_protocols(): # for all the port informations
                                    print('----------')
                                    print('Protocol : %s' % proto) #displays the protocol used by the host
                                    lport = nm[host][proto].keys()
                                    sorted(lport)
                                    for port in lport: #for every port
                                        print ('PORT : %s\tSTATE : %s\tSERVICE : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name'])) #to display the port number, Ip and state
                                        count = count + 1 #number of the ports and services found

                                    print("The number of ports open are: ", count)
                                
                            runScan= False
                            if count == 0: #if no ports found
                                print("No open ports found. Please enable ping on your host computer.") #message displayed
                            
                            else:    
                                print("\nDo you want to save the csv output?")
                                print("Enter 1 to save and any value to not save") 
                                saveFile = input(">>")
                                saveFile = saveFile.strip()
                                if saveFile == "1":
                                    insertFile = True
                                    while insertFile ==True:
                                        print("Enter the file name to be saved as: ")
                                        fileName = input(">>")
                                        if len(fileName)!= 0:
                                            fileName = fileName+".csv"
                                            fileName = os.path.join('./portCsv', fileName)
                                            print (nm.csv(),file=open(fileName,'w'))
                                            print("Your output has been saved in the "+ fileName + "file")
                                            insertFile = False
                                        else:
                                            print("Please enter a valid name")

                        elif check == "2":
                            print("You can re-enter the value: ") #to re-enter the value if incorrect

                        else :
                            errorMsg.errorMessage() # incase of any invalid input

                    else:
                        print("Please check and re-enter the value") # in case of any inva;id input in hostAddr
            
                print("\n1) Continue to vulnerability scanner") 
                print("2) Enter any value to go back")
                goToPort = input(">>") # to either continue to vulnerability scanner or go back
                goToPort = goToPort.strip() #removing all the spaces
                if goToPort == "1": #checking if to continue or not
                    Network.vulnScan()

            elif scanPort == "2": #if hostscan option is choosen
                Network.vulnScan()

            elif scanPort == "3": #if port scan opiton is choosen
                Network.hostScan()   

            elif scanPort == "4": #if exit scan option is choosen
                runPortScan = False

            else:
                errorMsg.errorMessage() #to show error

        
    #searching in exploit database
    @staticmethod
    def vulnScan() :
        
        runVulnScan = True # initiating a variable
        while runVulnScan == True: # looping the program up until the user exits

            print("\n1) Use the output from the portScan/ In progress")
            print("2) Manually search for a vulnerability")
            print("3) Go to Network Scanner")
            print("4) Go to port Scanner")
            print("5) Go to the beginning\n")
            scanVuln = input(">>")
            scanVuln = scanVuln.strip() # stripping all the spaces

            if scanVuln == "1":
                #left to check the output of the portScan.
                #if output of portscan is not empty 
                vuln = "file from portscan"
                if len(vuln) != 0:
                    print("\nScanning process\n")
                    #exploitName = from the text file
                    Message.displayCsv('./portCsv')
                    displayFile = True
                    while displayFile == True :
                        try:
                            fileName= input("\nEnter the name of the file you want to input\nEnter filename with the extension Example: filename.csv:\n>>")
                            if len(fileName)!=0:
                                columns = ["name"]
                                fileName = os.path.join("./portCsv", fileName)
                                df = pd.read_csv( fileName , sep=";", usecols= columns)
                                exploitArray = {}

                                for each in df.index:
                                    exploitArray[each]=(df['name'][each])

                                    
                                for each in exploitArray:
                                    print(exploitArray[each])
                            displayFile = False
                        
                        except:
                            print("\nThe file doesn't exist please re-enter the name of the file.")
                    exploitName ="openssh 1.2"
                    #take out each exploit and its version for the access 
                    print("\nDo you want to save the csv output?")
                    print("Enter 1 to save and any value to not save") 
                    saveFile = input(">>")
                    saveFile = saveFile.strip()
                    if saveFile == "1":
                        insertFile = True
                        while insertFile ==True:
                            print("Enter the file name to be saved as: ")
                            fileName = input(">>")
                            if len(fileName)!= 0:
                                fileName = fileName+".txt"
                                fileName = os.path.join('./vulnDoc', fileName)
                                print("Your output has been saved in the "+ fileName + "file")
                                insertFile = False
                            else:
                                print("Please enter a valid name")
                    os.system("searchsploit "+ exploitName +" | tee"+ fileName) #running command to search through searchexploit
                else:
                    print("\nThe folder is empty please choose manual search for vulnerability\n") #if the port file is empty

                

            elif scanVuln == "2":
                runScan= True

                while runScan == True :
                    print("\nEnter the name of the exploit that you want to search")
                    exploitName = input(">>") #to take the name of the exploit
                    if len(exploitName) != 0:
                        print("\nEnter the version of the exploit. \nPS:You can leave this field empty.")
                        version = input(">>") #to take the version of the exploit
                        exploitName = exploitName+" "+version #exploitNmame version
                        print ("\nThe value you have entered is: ", exploitName)
                        print("Is it correct?\n1)Yes\nNo\nEnter 1 or 2")
                        valueCheck = input(">>")
                        valueCheck = valueCheck.strip()
                        if valueCheck == "1" :#checking if the entered value is correct
                            #take out each exploit and its version for the access 
                            os.system("searchsploit "+exploitName+" | tee .exploit.txt")#texecuting the searchsploit command
                            runScan = False #ending the loop by changing the value
                        
                        elif valueCheck == "2":
                            print("\nPlease re-enter the value")

                        else:
                            errorMsg.errorMessage() #error messege incase of wrong input

                        print("\nScan Completed")

                    else:
                        errorMsg.errorMessage() #error message for invalid input


            elif scanVuln == "3":
                Network.hostScan()  #to skip to host scan 

            elif scanVuln == "4":
                Network.portScan() # to skip to port scan
            
            elif scanVuln == "5":
                runVulnScan = False #to go to main menu

            else:
                errorMsg.errorMessage() #to display error message incase of invalid input.

#Network.portScan()