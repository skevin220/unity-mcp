using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using NUnit.Framework;
using Newtonsoft.Json.Linq;
using MCPForUnity.Editor.Helpers;
using MCPForUnity.Editor.Services.Transport.Transports;

namespace MCPForUnityTests.Editor.Services
{
    /// <summary>
    /// Token-gate tests for the local stdio bridge (harden/security, R4/R5).
    ///
    /// These exercise the C# server side of the auth handshake against a live
    /// StdioBridgeHost: the host sends FRAMING=1, then requires the client's first
    /// framed message to be {"auth_token": "..."} matching BridgeAuth.GetToken().
    /// A connection that cannot authenticate is closed before any command runs and,
    /// critically, before the stale-client cleanup — so it can never displace the
    /// live authenticated session. Every case asserts the rejection (negative)
    /// direction; the positive case proves a valid token still reaches command exec.
    /// </summary>
    [TestFixture]
    public class BridgeAuthGateTests
    {
        private const int ConnectTimeoutMs = 5000;
        private const int ReadTimeoutMs = 10000;

        private bool _startedHost;
        private int _port;
        private string _validToken;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            // Only manage a host we actually started, so running these in a live
            // Editor (where the bridge auto-starts) doesn't tear down the real one.
            _startedHost = !StdioBridgeHost.IsRunning;
            if (_startedHost)
            {
                StdioBridgeHost.Start();
            }

            Assert.IsTrue(StdioBridgeHost.IsRunning,
                "StdioBridgeHost failed to start; cannot exercise the token gate.");

            _port = StdioBridgeHost.GetCurrentPort();
            // Same resolver the host uses to validate, so the positive case matches.
            _validToken = BridgeAuth.GetToken();
            Assert.IsFalse(string.IsNullOrEmpty(_validToken), "BridgeAuth produced no token.");
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            if (_startedHost)
            {
                StdioBridgeHost.Stop();
            }
        }

        // --- positive -------------------------------------------------------------

        [Test]
        public void ValidToken_IsAccepted_AndCommandExecutes()
        {
            using var client = Connect();
            var stream = client.GetStream();
            ReadHandshakeLine(stream);

            JObject ack = SendAuth(stream, _validToken);
            Assert.AreEqual("success", (string)ack["status"],
                "Valid token should be accepted by the bridge.");

            // A command must now execute on the authenticated session.
            SendFrame(stream, Encoding.UTF8.GetBytes("ping"));
            JObject pong = ReadFrameJson(stream);
            Assert.AreEqual("success", (string)pong["status"]);
            Assert.AreEqual("pong", (string)pong["result"]?["message"],
                "Authenticated session should execute commands.");
        }

        // --- negative: no token ---------------------------------------------------

        [Test]
        public void NoToken_IsRejected_AndNoCommandExecutes()
        {
            using var client = Connect();
            var stream = client.GetStream();
            ReadHandshakeLine(stream);

            // First framed message carries no auth_token → must be rejected.
            JObject ack = SendFrameJson(stream, new JObject { ["type"] = "ping" });
            Assert.AreEqual("error", (string)ack["status"], "Missing token must be rejected.");
            StringAssert.Contains("unauthorized", ((string)ack["error"]) ?? "",
                "Expected an unauthorized rejection.");

            // The connection must be closed with no command executed: a follow-up
            // command frame must not yield a pong.
            Assert.IsFalse(TryExecutePing(stream),
                "A connection rejected for a missing token must not execute commands.");
        }

        // --- negative: wrong token ------------------------------------------------

        [Test]
        public void WrongToken_IsRejected_AndNoCommandExecutes()
        {
            using var client = Connect();
            var stream = client.GetStream();
            ReadHandshakeLine(stream);

            JObject ack = SendAuth(stream, _validToken + "-tampered");
            Assert.AreEqual("error", (string)ack["status"], "Wrong token must be rejected.");
            StringAssert.Contains("unauthorized", ((string)ack["error"]) ?? "");

            Assert.IsFalse(TryExecutePing(stream),
                "A connection rejected for a wrong token must not execute commands.");
        }

        // --- negative: hijack (the specific R4 fix) -------------------------------

        [Test]
        public void UnauthenticatedSecondClient_DoesNotDisplaceLiveSession()
        {
            // Live, authenticated session.
            using var live = Connect();
            var liveStream = live.GetStream();
            ReadHandshakeLine(liveStream);
            Assert.AreEqual("success", (string)SendAuth(liveStream, _validToken)["status"]);
            SendFrame(liveStream, Encoding.UTF8.GetBytes("ping"));
            Assert.AreEqual("pong", (string)ReadFrameJson(liveStream)["result"]?["message"],
                "Live session should be working before the hijack attempt.");

            // Second connection that fails auth must be closed WITHOUT closing the
            // live session (auth runs before the stale-client cleanup).
            using (var attacker = Connect())
            {
                var attackerStream = attacker.GetStream();
                ReadHandshakeLine(attackerStream);
                JObject ack = SendAuth(attackerStream, "totally-wrong-token");
                Assert.AreEqual("error", (string)ack["status"],
                    "Unauthenticated hijack attempt must be rejected.");
            }

            // The live session must still execute commands — it was never displaced.
            Assert.IsTrue(TryExecutePing(liveStream),
                "The authenticated session must survive an unauthenticated connection attempt.");
        }

        // --- helpers --------------------------------------------------------------

        private TcpClient Connect()
        {
            var client = new TcpClient();
            Assert.IsTrue(client.ConnectAsync("127.0.0.1", _port).Wait(ConnectTimeoutMs),
                "Connect to StdioBridgeHost timed out.");
            client.ReceiveTimeout = ReadTimeoutMs;
            client.NoDelay = true;
            return client;
        }

        private static JObject SendAuth(NetworkStream stream, string token)
        {
            return SendFrameJson(stream, new JObject { ["auth_token"] = token });
        }

        private static JObject SendFrameJson(NetworkStream stream, JObject payload)
        {
            SendFrame(stream, Encoding.UTF8.GetBytes(payload.ToString(Newtonsoft.Json.Formatting.None)));
            return ReadFrameJson(stream);
        }

        /// <summary>
        /// Attempts one ping/pong. Returns true only if a pong came back; returns
        /// false if the bridge closed the connection (the expected outcome after a
        /// rejected auth). Used to assert "no command executed".
        /// </summary>
        private static bool TryExecutePing(NetworkStream stream)
        {
            try
            {
                SendFrame(stream, Encoding.UTF8.GetBytes("ping"));
                JObject resp = ReadFrameJson(stream, 2000);
                return string.Equals((string)resp["result"]?["message"], "pong", StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        private static JObject ReadFrameJson(NetworkStream stream, int timeoutMs = ReadTimeoutMs)
        {
            byte[] payload = ReadFrame(stream, timeoutMs);
            return JObject.Parse(Encoding.UTF8.GetString(payload));
        }

        private static string ReadHandshakeLine(NetworkStream stream)
        {
            var sb = new StringBuilder();
            stream.ReadTimeout = ReadTimeoutMs;
            var deadline = DateTime.UtcNow.AddMilliseconds(ReadTimeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                int b = stream.ReadByte();
                if (b < 0)
                    throw new IOException("Connection closed while reading handshake");
                if (b == '\n')
                {
                    string line = sb.ToString();
                    Assert.That(line, Does.Contain("FRAMING=1"), "Expected the FRAMING handshake.");
                    return line;
                }
                sb.Append((char)b);
            }
            throw new TimeoutException("Timed out reading handshake line");
        }

        private static void SendFrame(NetworkStream stream, byte[] payload)
        {
            byte[] header = new byte[8];
            ulong len = (ulong)payload.LongLength;
            for (int i = 0; i < 8; i++)
                header[i] = (byte)(len >> (56 - 8 * i));
            stream.Write(header, 0, 8);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        }

        private static byte[] ReadFrame(NetworkStream stream, int timeoutMs)
        {
            byte[] header = ReadExact(stream, 8, timeoutMs);
            ulong len = 0;
            for (int i = 0; i < 8; i++)
                len = (len << 8) | header[i];
            if (len == 0 || len > 16UL * 1024 * 1024)
                throw new IOException($"Invalid frame length: {len}");
            return ReadExact(stream, (int)len, timeoutMs);
        }

        private static byte[] ReadExact(NetworkStream stream, int count, int timeoutMs)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            stream.ReadTimeout = timeoutMs;
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (offset < count)
            {
                if (DateTime.UtcNow > deadline)
                    throw new TimeoutException($"Timed out reading {count} bytes (got {offset})");
                int read = stream.Read(buffer, offset, count - offset);
                if (read == 0)
                    throw new IOException("Connection closed before reading expected bytes");
                offset += read;
            }
            return buffer;
        }
    }
}
