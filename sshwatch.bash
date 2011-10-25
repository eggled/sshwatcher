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
			egrep -q "^$addr\$" /etc/sshblacklist && continue
			echo "$addr" >> /etc/sshblacklist
			ipfw -q add 00050 drop all from $addr to any
			ipfw -q add 00050 drop all from any to $addr
			logger -p auth.info "sshwatch.bash: Blocked address $addr"
		fi
	done
	rm sshauth-old.log

        sleep 10
done
