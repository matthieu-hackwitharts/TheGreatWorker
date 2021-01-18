import multiprocessing
from multiprocessing import Process, Queue
import subprocess
import os
import argparse
import requests







class bcolors:

   yellow = '\033[93m'
   blue = '\033[34m'
   red = '\033[31m'
   magenta = '\033[35m'
   end = '\33[0m'
   green = '\33[32m'
   bold = '\033[1m'

   
   



def verify_defenses():
   grsec_yes = b'Yes'
   grsec_no = b'Not found grsecurity'


   grsec=False

   print(bcolors.bold +bcolors.red + "LOOKING FOR DEFENSES...\n" + bcolors.end)
   

   os.system('echo "((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")" > /tmp/commande.sh')
   
   
   verif_grsecurity= subprocess.run(['/bin/bash', '/tmp/commande.sh'], stdout=subprocess.PIPE)
   os.system("rm /tmp/commande.sh")
   
 

  

  
   if(grsec_yes in verif_grsecurity.stdout):


      grsec=True
      print(bcolors.yellow + "grsec is present" + bcolors.end)
      

   elif(grsec_no in verif_grsecurity.stdout):


      grsec=False
      print(bcolors.blue + "grsec is not present !" + bcolors.end)
   
   
   
   
      

   
   pax_yes = b"Yes"
   pax_no = b"Not found PaX"

   pax_sec = False
   os.system('echo "(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")" > /tmp/commande2.sh')

   verif_pax = subprocess.run(['/bin/bash', '/tmp/commande2.sh'], stdout=subprocess.PIPE)

   os.system("rm /tmp/commande2.sh")

   if(pax_yes in verif_pax.stdout):

      pax_sec = True
      print(bcolors.yellow + "pax_yes is present" + bcolors.end)


   elif(pax_no in verif_pax.stdout):
      
      pax_sec=False
      print(bcolors.blue + "pax_yes not present" +bcolors.end)
   

   
   exec_no = b"Not found Execshield"



   exec_sec = False
   os.system('echo "(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")" > /tmp/commande3.sh')

   verif_exec = subprocess.run(['/bin/bash', '/tmp/commande3.sh'], stdout=subprocess.PIPE)

   os.system('rm /tmp/commande3.sh')

   if(exec_no in verif_exec.stdout):

      exec_sec = False
      print(bcolors.blue +"execshield not present" + bcolors.end)


   else:
      exec_sec = True
      print(bcolors.yellow + "execshield is present" + bcolors.end)


   
   selinux_no = b"Not found sestatus"

   selinux_sec = False

   os.system('echo  "(sestatus 2>/dev/null || echo "Not found sestatus")" > /tmp/commande4.sh')

   verif_selinux = subprocess.run(['/bin/bash', '/tmp/commande4.sh'], stdout=subprocess.PIPE)

   os.system("rm /tmp/commande4.sh")

   if(selinux_no in verif_selinux.stdout):

      selinux_sec = False
      print(bcolors.blue + "selinux not present"+ bcolors.end)

   
   else:
      selinux_sec = True
      print(bcolors.yellow + "selinux is present" + bcolors.end)


   
   aslr_no = b"0"

   aslr_sec = False

   os.system('echo "cat /proc/sys/kernel/randomize_va_space 2>/dev/null" > /tmp/commande5.sh ')

   verif_aslr = subprocess.run(['/bin/bash', '/tmp/commande5.sh'], stdout=subprocess.PIPE)

   os.system("rm /tmp/commande5.sh")

   if(aslr_no in verif_aslr.stdout):
      aslr_sec = False
      print(bcolors.blue + "asl not present\n"+ bcolors.blue)


   else:

      aslr_sec = True
      print(bcolors.yellow + "aslr is present\n" + bcolors.end)

   return True



def useful_software():

   soft_notpresent = b"not found"

   print("################################################################\n")

  

   software_list = ['nmap', 'aws', 'nc', 'netcat', 'nc.traditionnal', 'wget', 'curl', 'ping', 'gcc', 'g++', 'make', 'gdb', 'base64', 'socat', 'python', 'python2', 'python3', 'python2.7', 'python2.6', 'python3.6', 'python3.7', 'perl', 'ruby', 'xterm', 'doas', 'sudo', 'fetch', 'docker', 'lxc', 'ctr', 'run', 'rkt', 'kubectl']

   for x in software_list:

      verify = subprocess.call(['which', x])
      






      if verify ==0:



         
         print(bcolors.green + "Tool {} is installed\n" .format(x) + bcolors.end)


      else:

         print(bcolors.red + "Tool {} is not installed\n" .format(x) + bcolors.end)

   print("################################################################\n")

   return True




def process():



   verif_process = os.system('echo "ps -aux | grep root" > /tmp/commande_pr.sh')

   print(bcolors.bold +bcolors.red + "Checking for interesting (root obviously) process...\n"+ bcolors.end)

   process_check = subprocess.call(['/bin/bash', '/tmp/commande_pr.sh'])
   os.system("rm /tmp/commande_pr.sh")



def path():

   print("\n")
   print("\n")

   print(bcolors.bold +bcolors.blue +"Is there any vuln in the PATH maybe ?\n"+ bcolors.end)



   os.system('echo "$PATH" > /tmp/path.sh')
   print("*************************************************************")

   subprocess.call(['cat', '/tmp/path.sh'])

   print("*************************************************************")
   os.system("rm /tmp/path.sh")
   return True







def get_suid(file):

   


   print("\n")
   print("\n")

   print(bcolors.bold +bcolors.magenta+"Looking for great suid binaries !\n"+bcolors.end)
   print(bcolors.bold +bcolors.yellow +"***************************************************************"+bcolors.end)


   with open(file,"r") as file:
      file_output = file.read()

   liste_suid = []
   for i in file_output.split('\n'):
      splitted_path = i.split("/")
      binary = splitted_path[-1]
      liste_suid.append(binary)
   return liste_suid


def start_suid():
   os.system('find / -perm -u=s -type f 2>/dev/null > /tmp/suid_list.txt')
   for suid in get_suid("/tmp/suid_list.txt"):
      response = requests.get(f"https://gtfobins.github.io/gtfobins/{suid}/") 
      if response.status_code != 404:    
         print("[+] Matched")

         response2 = requests.get(f"https://gtfobins.github.io/gtfobins/{suid}/#suid")
         if response2.status_code != 404:
            print(f"Url For SUID Exploit : https://gtfobins.github.io/gtfobins/{suid}/#suid")
   





def writable_directories():

   os.system('echo "find / -type d -writable 2> /dev/null" > /tmp/check_dir.sh')

   print("\n")
   print("\n")

   print(bcolors.bold+bcolors.blue+"Any interesting writable directory ?....\n"+bcolors.end)

   print("*********************************************************************************")


   subprocess.call(['bash', '/tmp/check_dir.sh'])

   print("***********************************************************************************")

   os.system("rm /tmp/check_dir.sh")
   return True



def authorized_exec():


   os.system('echo "find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 6 -exec ls -ld {} \; 2>/dev/null" > /tmp/check_exec.sh')

   print(bcolors.bold + bcolors.green +"Any interesting script to execute ?\n"+ bcolors.end)

   print("#################################################################################")

   subprocess.call(['bash', '/tmp/check_exec.sh'])

   print("#################################################################################")
   os.system("rm /tmp/check_exec.sh")
   return True

   
      

def crontab():

   os.system('echo "cat /etc/crontab" > /tmp/cron.sh')

   print("\n")

   print(bcolors.bold +bcolors.green+"Any crontab ?...\n"+bcolors.end)

   print("################################")

   subprocess.call(['bash', '/tmp/cron.sh'])

   print("################################")

   os.system("rm /tmp/cron.sh")
   return True



def sudol(password_g):


   print("\n")
   print("\n")

   print(bcolors.bold+bcolors.red+"CHECKING FOR SUDO PERMISSIONS..."+bcolors.end)

   

   password = password_g
   os.system(f'echo {password_g} | sudo -S -l | sudo tee /tmp/test.txt > /dev/null')
   
   with open("/tmp/test.txt", "r") as sudo_file:

      output = sudo_file.readlines()
   
   print(bcolors.red+"Parsing sudo return..."+bcolors.end)
   print("\n")
      

   
   for suid in output:

       
      response = requests.get(f"https://gtfobins.github.io/gtfobins/{suid}/") 
      if response.status_code != 404:    
         print(bcolors.bold+bcolors.yellow+"[+] Way founded !"+bcolors.end)

         response2 = requests.get(f"https://gtfobins.github.io/gtfobins/{suid}/#suid")
         if response2.status_code != 404:
            print(bcolors.green+f"Url For Sudo Exploit : https://gtfobins.github.io/gtfobins/{suid}/#suid"+bcolors.end)
         else:
            print(bcolors.blue+"Nothing"+bcolors.end)
      else:
         print(bcolors.blue+"Nothing"+bcolors.end)

   return output
     
      



def enum_users():



   os.system('echo "cut -d: -f1 /etc/passwd" > /tmp/cond.sh')
   print("\n")


   print(bcolors.bold + bcolors.magenta+ "Current list of users....\n"+ bcolors.end)


   subprocess.call(['bash', '/tmp/cond.sh'])
   print("***************************************************************************")
   os.system("rm /tmp/cond.sh")
   return True



def network_interface():
   print("\n")


   os.system('echo "cat /etc/networks" > /tmp/c1.sh')
   os.system('echo "ip a" > /tmp/c2.sh')

   print(bcolors.bold + bcolors.blue +"Pivoting is always the solution.\n"+ bcolors.end)

   subprocess.call(['bash', '/tmp/c1.sh'])
   subprocess.call(['bash', '/tmp/c2.sh'])

   print('\n')

   os.system("rm /tmp/c1.sh")
   os.system("rm /tmp/c2.sh")

   return True



def check_write():

   print("\n")
   print("\n")

   print(bcolors.bold+bcolors.magenta+"Do you have RIGHTS ?"+bcolors.end)



   path1 = os.access("/etc/sudoers", os.W_OK)
   print(path)

   path2 = os.access("/etc/ld.so.conf.d", os.W_OK)

   path3 = os.access("/etc/shadow", os.W_OK)

   path4 = os.access("/etc/passwd", os.W_OK )

   
   


   if path1 is True:


      print(bcolors.yellow +"/etc/sudoers is writable"+ bcolors.end)

   else:

      print(bcolors.red +"etc/sudoers is not writable"+ bcolors.end)


   if path2 is True:

      print(bcolors.yellow +"/etc/ld.so.conf.d is writable"+bcolors.end)

   else:

      print(bcolors.red+"/etc/ld.so.conf.d is not writable"+bcolors.end)

   if path3 is True:

      print(bcolors.yellow+"/etc/shadow is writable"+bcolors.end)

   else:
      print(bcolors.red+"etc/shadow is not writable"+bcolors.end)

   
   if path4 is True:

      print(bcolors.yellow + "/etc/passwd is writable"+bcolors.end)

   else:
      print(bcolors.red + "/etc/passwd is not writable" + bcolors.red)
   
   return True
 



def search_files():

   print("\n")

   print(bcolors.bold + bcolors.green+"Looking for interesting passwd files...\n"+bcolors.end)

   print("#####################################################################")



   os.system('grep --color=auto -rnw "/" -ie "PASSWORD" --color=always 2> /dev/null')
   print("#######################################################################")

   print('\n')
   print("\n")

   



   
   print(bcolors.bold + bcolors.green+"Looking for usernames files....\n"+bcolors.end)

   print("########################################################################")
   os.system('grep --color=auto -rnw "/" -ie "USERNAME" --color=always 2> /dev/null')

   print("#########################################################################")


   print("\n")
   print("\n")

  
   print("Looking for interesting log files...\n")

   print("************************************************************************")

   os.system('grep --color=auto  -r -i --include=\*.log "PASSWORD" / --color=always')

   print("************************************************************************")

   print("\n")
   print("\n")


   print("Search for db, ini, in, int.d and many others files...\n ")

   print("*************************************************************************")

   os.system('grep --color=auto  -r -i --include=\*.db "PASSWORD" / --color=always 2> /dev/null')

   os.system('grep --color=auto  -r -i --include=\*.db "USERNAME" / --color=always 2> /dev/null')

   os.system('find / |grep --color=auto  -e "\.ini$" --color=always 2> /dev/null')

   os.system('find / |grep --color=auto  -e "\.in$" --color=always 2> /dev/null')

   os.system('find / |grep --color=auto  -e "\.int.d$" --color=always 2> /dev/null ')

   print("**********************************************************************")
   return True






def main_f():



   queue=Queue()





   proc10= multiprocessing.Process(target=verify_defenses)
   proc2 = multiprocessing.Process(target=useful_software)
   proc3 = multiprocessing.Process(target=process)
   proc4 = multiprocessing.Process(target=start_suid)
   
   proc6 =multiprocessing.Process(target=path)
   proc7 =multiprocessing.Process(target=writable_directories)
   proc8 =multiprocessing.Process(target=authorized_exec)
   proc9 =multiprocessing.Process(target=crontab)
   proc1 =multiprocessing.Process(target=enum_users)
   proc11 = multiprocessing.Process(target=network_interface)
   proc12 =multiprocessing.Process(target=check_write)
   proc13 = multiprocessing.Process(target=search_files)
      
   
   

   proc6.start()
   proc6.join()

   proc9.start()
   proc9.join()

   proc11.start()
   proc11.join()

   proc3.start()
   proc3.join()

   proc10.start()
   proc10.join()
   

   proc4.start()

   proc4.join()

   
   proc2.start()
   proc2.join()

   proc1.start()

   proc1.join()

   proc12.start()
   proc12.join()

   proc8.start()
   proc8.join()

   proc7.start()
   proc7.join()

   proc13.start()
   proc13.join()



   





if __name__=="__main__":



  




   print(r"""

   /        |/  |                 /      \                                 /  |    
   $$$$$$$$/ $$ |____    ______  /$$$$$$  |  ______    ______    ______   _$$ |_   
      $$ |   $$      \  /      \ $$ | _$$/  /      \  /      \  /      \ / $$   |  
      $$ |   $$$$$$$  |/$$$$$$  |$$ |/    |/$$$$$$  |/$$$$$$  | $$$$$$  |$$$$$$/   
      $$ |   $$ |  $$ |$$    $$ |$$ |$$$$ |$$ |  $$/ $$    $$ | /    $$ |  $$ | __ 
      $$ |   $$ |  $$ |$$$$$$$$/ $$ \__$$ |$$ |      $$$$$$$$/ /$$$$$$$ |  $$ |/  |
      $$ |   $$ |  $$ |$$       |$$    $$/ $$ |      $$       |$$    $$ |  $$  $$/ 
      $$/    $$/   $$/  $$$$$$$/  $$$$$$/  $$/        $$$$$$$/  $$$$$$$/    $$$$/  
                                                                                 
                                                                                 
                                                                                 
   __       __   ______             __                                            
   /  |  _  /  | /      \           /  |                                           
   $$ | / \ $$ |/$$$$$$  |  ______  $$ |   __   ______    ______                   
   $$ |/$  \$$ |$$ |  $$ | /      \ $$ |  /  | /      \  /      \                  
   $$ /$$$  $$ |$$ |  $$ |/$$$$$$  |$$ |_/$$/ /$$$$$$  |/$$$$$$  |                 
   $$ $$/$$ $$ |$$ |  $$ |$$ |  $$/ $$   $$<  $$    $$ |$$ |  $$/                  
   $$$$/  $$$$ |$$ \__$$ |$$ |      $$$$$$  \ $$$$$$$$/ $$ |                       
   $$$/    $$$ |$$    $$/ $$ |      $$ | $$  |$$       |$$ |                       
   $$/      $$/  $$$$$$/  $$/       $$/   $$/  $$$$$$$/ $$/                        
                                                               """)




   parser = argparse.ArgumentParser()
   parser.add_argument("-o", "--output", type=str, action='store',help="Save report to an output file : highly recommended because of screen size")
   parser.add_argument("-p", "--password", type=str, action='store', help="Specify a known user password to run sudo permissions")
   args = parser.parse_args()

   if args.output:


      object = input(bcolors.blue+"Do you have a password for sudo permissions ? Y or N"+bcolors.end)
      if object=="Y":

         password = input(bcolors.blue+"Enter the pass !"+bcolors.end)
         sudol(password)
         os.system("cp /tmp/test.txt /tmp/sudolist.txt")
         os.system("rm /tmp/test.txt")
      
         print(bcolors.blue+"GENERATING REPORT, PLEASE WAITING !....."+bcolors.end)
         print(str(args))
         myfile = __file__
         print(str(myfile))
         os.system(f"python3 {str(myfile)} > {args.output}")

         print(bcolors.yellow+"Finished ! Check at :", args.output+bcolors.end)
         print(bcolors.green+"Check sudo permissions at /tmp/sudolist.txt"+bcolors.end)
      elif object=="N":


         print(bcolors.blue+"GENERATING REPORT, PLEASE WAITING !....."+bcolors.end)
         print(str(args))
         myfile = __file__
         print(str(myfile))
         os.system(f"python3 {str(myfile)} > {args.output}")

         print(bcolors.yellow+"Finished ! Check at :", args.output+bcolors.end)


   
   elif args.password:

      sudol(args.password)
      main_f()
      print("\n")
      print(bcolors.bold+bcolors.yellow+"Finished !"+bcolors.end)
      print(bcolors.blue+"*******************************************************************".bcolors.end)

   else:
      main_f()
      print(bcolors.bold+bcolors.yellow+"Finished !"+bcolors.end)
      print(bcolors.blue+"*******************************************************************".bcolors.end)


         
      
      







      

























      






      






   



 






