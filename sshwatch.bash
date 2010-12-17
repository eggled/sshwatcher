#!/usr/local/bin/bash

kill `cat /var/run/sshwatch.pid`
echo $$ > /var/run/sshwatch.pid

while [ 1 ]
do
	## get an exclusive copy of sshauth.log
	cd /var/log
	mv sshauth.log sshauth-old.log
	umask 0077
	touch sshauth.log
	kill -HUP `cat /var/run/syslog.pid`
	## done getting exclusive copy
	
	IFS=$'\n'
	for line in `cat sshauth-old.log`
	do
		if [ -n "$(echo "$line" | egrep -i 'none of user.s groups are listed in AllowGroups')" ]
		then
			addr=$(echo "$line" | perl -p -e 's/.*User [^ ]+ from ([^ ]+) not allowed.*/$1/i')
			echo $line >> ssh-offending.log
			echo $addr for groups >> ssh-blocked.log
		elif [ -n "$(echo "$line" | egrep -i 'Invalid user [^ ]+ from [^ ]+')" ]
		then
			addr=$(echo "$line" | perl -p -e 's/.*Invalid user [^ ]+ from ([^ ]+).*/$1/i')
			echo $line >> ssh-offending.log
			echo $addr for user >> ssh-blocked.log
		else
			echo $line >> ssh-OK.log
		fi
		if [ -z "$(echo $addr | perl -n -e 'print if m/^\d+\.\d+\.\d+\.\d+$/')" ]
		then
			addr=$(host $addr 2>/dev/null| awk '{print $NF}' | perl -n -e 'print if m/^\d+\.\d+\.\d+\.\d+$/' | head -1)
		fi
		if [ -n "$addr" ]
		then
			cp -p /root/create_firewall /root/create_firewall_new
			echo -n > /root/create_firewall_new
			for cmdline in `cat /root/create_firewall`
			do
				if [ $cmdline == "\$cmd 00100 deny all from $addr to any" ]
				then
					rm /root/create_firewall_new
					break
				fi
				if [ $cmdline == "##########~~~~~~~~~~ NEWRULE" ]
				then
					echo "\$cmd 00100 deny all from $addr to any" >> /root/create_firewall_new
					echo "\$cmd 00100 deny all from $addr to any" 
					ipfw -q add 00100 deny all from $addr to any
					logger -p auth.info "sshwatch.bash: Blocked address $addr"
				fi
				echo $cmdline >> /root/create_firewall_new
			done
			mv /root/create_firewall_new /root/create_firewall 2>/dev/null
		fi
	done
	rm sshauth-old.log

        sleep 10
done
