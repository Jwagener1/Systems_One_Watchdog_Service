using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Systems_One_Watchdog_Service
{
    [SupportedOSPlatform("windows")]
    public static class ProcessExtensions
    {
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [Flags]
        public enum CREATE_PROCESS_FLAGS : uint
        {
            NONE = 0x00000000,
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
        private const uint TOKEN_QUERY = 0x08;

        public static class Kernel32
        {
            [DllImport("kernel32.dll", EntryPoint = "WTSGetActiveConsoleSessionId")]
            public static extern uint WTSGetActiveConsoleSessionId();

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();
        }

        public static class WtsApi32
        {
            [DllImport("Wtsapi32.dll", EntryPoint = "WTSQueryUserToken", SetLastError = true)]
            public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);
        }

        public static class AdvApi32
        {
            public const uint MAXIMUM_ALLOWED = 0x02000000;

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool DuplicateTokenEx(
                IntPtr hExistingToken,
                uint dwDesiredAccess,
                SECURITY_ATTRIBUTES? lpTokenAttributes,
                SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                TOKEN_TYPE TokenType,
                out IntPtr phNewToken);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CreateProcessAsUser(
                IntPtr hToken,
                string? lpApplicationName,
                string? lpCommandLine,
                SECURITY_ATTRIBUTES? lpProcessAttributes,
                SECURITY_ATTRIBUTES? lpThreadAttributes,
                bool bInheritHandles,
                CREATE_PROCESS_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                string? lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint Zero, IntPtr Null1, IntPtr Null2);
        }

        private static void EnablePrivilege(string privilege)
        {
            if (!AdvApi32.OpenProcessToken(Kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var hToken))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                if (!AdvApi32.LookupPrivilegeValue(null, privilege, out var luid))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    }
                };

                if (!AdvApi32.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                    Kernel32.CloseHandle(hToken);
            }
        }

        public static void StartAsActiveUser(this Process process)
        {
            // If running interactively (e.g., debugging), fall back to a normal start under the current user
            if (Environment.UserInteractive)
            {
                if (!process.Start())
                    throw new InvalidOperationException("Process failed to start in interactive mode.");
                return;
            }

            if (process.StartInfo == null)
                throw new InvalidOperationException("The StartInfo property must be defined");
            if (string.IsNullOrWhiteSpace(process.StartInfo.FileName))
                throw new InvalidOperationException("The StartInfo.FileName property must be defined");

            // Ensure required privileges when running as a service (LocalSystem)
            try
            {
                EnablePrivilege("SeIncreaseQuotaPrivilege");
                EnablePrivilege("SeAssignPrimaryTokenPrivilege");
                EnablePrivilege("SeImpersonatePrivilege");
            }
            catch (Win32Exception)
            {
                // If privilege enabling fails, we'll still attempt; CreateProcessAsUser will error if insufficient
            }

            uint sessionId = Kernel32.WTSGetActiveConsoleSessionId();

            if (!WtsApi32.WTSQueryUserToken(sessionId, out var userTokenPtr))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            IntPtr duplicateUserTokenPtr = IntPtr.Zero;
            IntPtr environmentPtr = IntPtr.Zero;

            try
            {
                if (!AdvApi32.DuplicateTokenEx(userTokenPtr, AdvApi32.MAXIMUM_ALLOWED, null,
                        SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out duplicateUserTokenPtr))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                if (!UserEnv.CreateEnvironmentBlock(out environmentPtr, duplicateUserTokenPtr, false))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    lpDesktop = "winsta0\\default"
                };

                var processFlags = CREATE_PROCESS_FLAGS.NORMAL_PRIORITY_CLASS |
                                   CREATE_PROCESS_FLAGS.CREATE_UNICODE_ENVIRONMENT |
                                   CREATE_PROCESS_FLAGS.CREATE_NEW_CONSOLE;

                string? currentDirectory = string.IsNullOrWhiteSpace(process.StartInfo.WorkingDirectory)
                    ? null
                    : process.StartInfo.WorkingDirectory;

                if (!AdvApi32.CreateProcessAsUser(
                        duplicateUserTokenPtr,
                        process.StartInfo.FileName,
                        string.IsNullOrWhiteSpace(process.StartInfo.Arguments) ? null : process.StartInfo.Arguments,
                        null,
                        null,
                        false,
                        processFlags,
                        environmentPtr,
                        currentDirectory,
                        ref startupInfo,
                        out var processInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Close handles created by CreateProcessAsUser
                if (processInfo.hProcess != IntPtr.Zero)
                    Kernel32.CloseHandle(processInfo.hProcess);
                if (processInfo.hThread != IntPtr.Zero)
                    Kernel32.CloseHandle(processInfo.hThread);
            }
            finally
            {
                if (environmentPtr != IntPtr.Zero)
                    UserEnv.DestroyEnvironmentBlock(environmentPtr);
                if (duplicateUserTokenPtr != IntPtr.Zero)
                    Kernel32.CloseHandle(duplicateUserTokenPtr);
                if (userTokenPtr != IntPtr.Zero)
                    Kernel32.CloseHandle(userTokenPtr);
            }
        }

        public static class UserEnv
        {
            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

            [DllImport("userenv.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        }
    }
}
