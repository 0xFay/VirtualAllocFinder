using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections;

namespace VirtualAllocFinder
{
    class Priviledge
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

        private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static uint TOKEN_DUPLICATE = 0x0002;
        private static uint TOKEN_IMPERSONATE = 0x0004;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_QUERY_SOURCE = 0x0010;
        private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static uint TOKEN_ADJUST_GROUPS = 0x0040;
        private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        private static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
            out LUID lpLuid);
        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";

        public const string SE_AUDIT_NAME = "SeAuditPrivilege";

        public const string SE_BACKUP_NAME = "SeBackupPrivilege";

        public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";

        public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";

        public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";

        public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";

        public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";

        public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";

        public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";

        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";

        public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";

        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";

        public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";

        public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";

        public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";

        public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";

        public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";

        public const string SE_RELABEL_NAME = "SeRelabelPrivilege";

        public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";

        public const string SE_RESTORE_NAME = "SeRestorePrivilege";

        public const string SE_SECURITY_NAME = "SeSecurityPrivilege";

        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

        public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";

        public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";

        public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";

        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";

        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        public const string SE_TCB_NAME = "SeTcbPrivilege";

        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";

        public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";

        public const string SE_UNDOCK_NAME = "SeUndockPrivilege";

        public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        // Use this signature if you do not want the previous state
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 Zero,
           IntPtr Null1,
           IntPtr Null2);

        public static int EnableDebugPri()
        {
            IntPtr hToken;
            LUID luidSEDebugNameValue;
            TOKEN_PRIVILEGES tkpPrivileges;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                Console.WriteLine("OpenProcessToken() failed, error = {0} . SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
                return -8;
            }
            else
            {
                Console.WriteLine("OpenProcessToken() successfully");
            }

            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luidSEDebugNameValue))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
                CloseHandle(hToken);
                return -7;
            }
            else
            {
                Console.WriteLine("LookupPrivilegeValue() successfully");
            }

            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Luid = luidSEDebugNameValue;
            tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine("SeDebugPrivilege is now available");
            }
            CloseHandle(hToken);
            //Console.ReadLine();
            return 1;
        }
    }
    class Program
    {
        public static int PAGE_EXECUTE = 0x10;
        public static int PAGE_EXECUTE_READ = 0x20;
        public static int PAGE_EXECUTE_READWRITE = 0x40;
        public static int PAGE_EXECUTE_WRITECOPY = 0x80;
        public static int PAGE_NOACCESS = 0x01;
        public static int PAGE_READONLY = 0x02;
        public static int PAGE_READWRITE = 0x04;
        public static int PAGE_WRITECOPY = 0x08;
        public static int PAGE_TARGETS_INVALID = 0x40000000;
        public static int PAGE_TARGETS_NO_UPDATE = 0x40000000;
        public static int PAGE_GUARD = 0x100;
        public static int PAGE_NOCACHE = 0x200;
        public static int PAGE_WRITECOMBINE = 0x400;

        public static int MEM_COMMIT = 0x1000;
        public static int MEM_FREE = 0x10000;
        public static int MEM_RESERVE = 0x2000;

        public static int MEM_IMAGE = 0x1000000;
        public static int MEM_MAPPED = 0x40000;
        public static int MEM_PRIVATE = 0x20000;


        public struct MEMORY_BASIC_INFORMATION
        {
            public uint BaseAddress;
            public uint AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_INFO
        {
            internal uint dwOemId;
            internal uint dwPageSize;
            internal UIntPtr lpMinimumApplicationAddress;
            internal UIntPtr lpMaximumApplicationAddress;
            internal UIntPtr dwActiveProcessorMask;
            internal uint dwNumberOfProcessors;
            internal uint dwProcessorType;
            internal uint dwAllocationGranularity;
            internal ushort wProcessorLevel;
            internal ushort wProcessorRevision;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        [DllImportAttribute("kernel32.dll", EntryPoint = "ReadProcessMemory")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, IntPtr lpNumberOfBytesRead);

        //从指定内存中写入字节集数据
        [DllImportAttribute("kernel32.dll", EntryPoint = "WriteProcessMemory")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, int[] lpBuffer, int nSize, IntPtr lpNumberOfBytesWritten);

        //打开一个已存在的进程对象，并返回进程的句柄
        [DllImportAttribute("kernel32.dll", EntryPoint = "OpenProcess")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        //关闭一个内核对象。其中包括文件、文件映射、进程、线程、安全和同步对象等。
        [DllImport("kernel32.dll")]
        public static extern void CloseHandle(IntPtr hObject);

        public static int GetPidByProcessName(string processName)
        {
            Process[] arrayProcess = Process.GetProcessesByName(processName);
            foreach (Process p in arrayProcess)
            {
                return p.Id;
            }
            return 0;
        }

        //主扫描函数
        public static void GetVirtualMemory(string processName)
        {
            IntPtr hProcess = OpenProcess(0x1F0FFF, false, GetPidByProcessName(processName));
            SYSTEM_INFO sysinfo = new SYSTEM_INFO();
            GetSystemInfo(ref sysinfo);
            //Console.WriteLine(sysinfo.lpMinimumApplicationAddress);
            //Console.WriteLine(sysinfo.dwAllocationGranularity);
            //Console.WriteLine(sysinfo.lpMaximumApplicationAddress);
            long minaddress = (long)sysinfo.lpMinimumApplicationAddress;
            long maxaddress = (long)sysinfo.lpMaximumApplicationAddress;
            MEMORY_BASIC_INFORMATION MemoryInfo = new MEMORY_BASIC_INFORMATION();


            while (minaddress < maxaddress)
            {

                Console.WriteLine(minaddress);
                Console.WriteLine(maxaddress);

                if (MemoryInfo.RegionSize == 0) {
                    Console.WriteLine(" [+] Failed to load process memory ");
                    Console.WriteLine(" [+] Process Name is {0} , Pid is {1}",processName,GetPidByProcessName(processName));
                    break;
                }

                int size_check = VirtualQueryEx(hProcess, (UIntPtr)minaddress, out MemoryInfo, (uint)Marshal.SizeOf(MemoryInfo));
                //if (size_check != (uint)Marshal.SizeOf(MemoryInfo)) {
                //    Console.WriteLine("something wrong with the struct MEMORY_BASIC_INFORMATION");
                //    Console.WriteLine(size_check);
                //    Console.WriteLine((uint)Marshal.SizeOf(MemoryInfo));
                //    break;
                //}

                //显示内存区域属性
                //Console.WriteLine("---------------------------");
                //Console.Write("AllocationProtect is:");
                //Console.Write(MemoryInfo.AllocationProtect);
                //Console.WriteLine("     " + MemoryInfo.AllocationProtect.ToString("x8") + "\n");
                //Console.Write("BaseAddress is:");
                //Console.Write(MemoryInfo.BaseAddress);
                //Console.WriteLine("     " + MemoryInfo.BaseAddress.ToString("x8") + "\n");
                //Console.Write("AllocationBase is:");
                //Console.Write(MemoryInfo.AllocationBase);
                //Console.WriteLine("     " + MemoryInfo.AllocationBase.ToString("x8") + "\n");
                //Console.Write("State is:");
                //Console.Write(MemoryInfo.State);
                //Console.WriteLine("     " + MemoryInfo.State.ToString("x8") + "\n");
                //Console.Write("Type is:");
                //Console.Write(MemoryInfo.Type);
                //Console.WriteLine("     " + MemoryInfo.Type.ToString("x8") + "\n");
                //Console.Write("RegionSize is:");
                //Console.Write(MemoryInfo.RegionSize);
                //Console.WriteLine("     "+ MemoryInfo.RegionSize.ToString("x8") + "\n");
                //Console.WriteLine("---------------------------");
                if (MemoryInfo.Type != MEM_IMAGE)
                {
                    if (MemoryInfo.AllocationProtect == PAGE_EXECUTE ||
                        MemoryInfo.AllocationProtect == PAGE_EXECUTE_READ ||
                        MemoryInfo.AllocationProtect == PAGE_EXECUTE_READWRITE ||
                        MemoryInfo.AllocationProtect == PAGE_EXECUTE_WRITECOPY)
                    {
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        Console.WriteLine(" [!] Detect a memory region which seems to be executed by VirtualAlloc ShellCode");
                        Console.WriteLine(" [!] The Process Name is {0}", processName);
                        Console.WriteLine(" [!] The Process Pid is {0}", GetPidByProcessName(processName));


                        ReadMemoryValue((IntPtr)minaddress, processName);
                        Console.WriteLine("--------------------------------------------------------------------------------");
                    }
                }

                Console.WriteLine(MemoryInfo.RegionSize);
                Console.WriteLine("\n");
                minaddress = minaddress + MemoryInfo.RegionSize;

            };
            Console.WriteLine(" [-] {0} scan complete\n", processName);
        }


        //辅助判断区域特征
        public static int ReadMemoryValue(IntPtr baseAddress, string processName)
        {
            try
            {
                byte[] buffer = new byte[4];
                IntPtr byteAddress = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
                //打开一个已存在的进程对象  0x1F0FFF 最高权限
                IntPtr hProcess = OpenProcess(0x1F0FFF, false, GetPidByProcessName(processName));
                //将制定内存中的值读入缓冲区
                ReadProcessMemory(hProcess, baseAddress, byteAddress, Marshal.SizeOf(byteAddress), IntPtr.Zero);
                if (byteAddress == (IntPtr)0x4d5a9000)
                {
                    Console.WriteLine(" [!] Detect excutable PE File in process memory");
                }
                else if (byteAddress == (IntPtr)0xfce88200)
                {
                    Console.WriteLine(" [!] Detect MetaSploit ShellCode feature in process memory");
                }
                //关闭操作
                CloseHandle(hProcess);

                //从非托管内存中读取一个 32 位带符号整数。
                return Marshal.ReadInt32(byteAddress);
            }
            catch(Exception e)
            {

                Console.WriteLine(" [!] Error Occer");
                Console.WriteLine(e);
                return 0;
            }
        }


        public static string processname = "shellcode_virtualalloc_msf";
        //寻找固定进程
        public static IntPtr getBaseAddress()
        {
            Process[] ps = Process.GetProcesses();
            foreach (Process p in ps)
            {
                //Console.WriteLine(p.ProcessName);
                if (p.ProcessName == processname)
                {
                    for (int i = 0; i < p.Modules.Count; i++)
                    {
                        //Console.WriteLine(p.Modules[i].ModuleName);
                        //Console.WriteLine(p.Modules[i].EntryPointAddress.ToString("x8"));
                        if (p.Modules[i].ModuleName == processname + ".exe")
                        {
                            Console.WriteLine(p.Modules[i].ModuleName);
                            //要找基址就用p.Modules[i].EntryPointAddress
                            Console.WriteLine(p.Modules[i].EntryPointAddress.ToString("x8"));
                            IntPtr testbaseaddress = p.Modules[i].EntryPointAddress;

                            return testbaseaddress;
                        }

                    }
                }
            }
            Console.WriteLine("process not found");
            return IntPtr.Zero;
        }

        public static void ScanAllProcess()
        {
            Process[] ps = Process.GetProcesses();
            foreach (Process p in ps)
            {
                Console.WriteLine(" [+] {0} scan start", p.ProcessName);
                GetVirtualMemory(p.ProcessName);
            }
        }
        public static void Finder()
        {
            Console.WriteLine("start trace");
            var stackTrace = new StackTrace(true);
            Console.WriteLine(stackTrace.ToString());
            Console.WriteLine(stackTrace.GetFrames());
            Console.WriteLine("===========================");
            var traceevent = new TraceEventCache();
            Console.WriteLine(traceevent.Callstack);
        }
        static void Main(string[] args)
        {
            Priviledge.EnableDebugPri();
            //Finder();
            //IntPtr baseaddress = getBaseAddress();
            //int memoryint = ReadMemoryValue(baseaddress,processname);
            //Console.WriteLine(memoryint);

            //Console.WriteLine("here is the virtual memory in your comouter:");
            //getVirtualMemory(processname);
            //Console.WriteLine("StackTrace: '{0}'", Environment.StackTrace);

            Console.WriteLine(" [+] Start all process scan\n");

            ScanAllProcess();

            Console.WriteLine(" [+] Finish all process scan");

            Console.ReadLine();
        }
    }
}
