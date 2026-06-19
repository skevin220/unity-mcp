using System.Threading;
using NUnit.Framework;
using Newtonsoft.Json.Linq;
using MCPForUnity.Editor.Services;
using MCPForUnity.Editor.Services.Transport;

namespace MCPForUnityTests.Editor.Services
{
    /// <summary>
    /// Dispatch-boundary tests for the tool enable/disable gate (harden/security, R9).
    ///
    /// The Python advertiser only *hides* non-core tools; the real enforcement is in
    /// TransportCommandDispatcher, which refuses a registered-but-disabled tool even
    /// when a client speaks straight to the Unity socket. These drive the dispatcher
    /// directly (the same entry point the bridge uses) and assert that a disabled
    /// non-core tool is refused (negative) while a core tool still dispatches (positive).
    /// </summary>
    [TestFixture]
    public class DispatchEnablementBoundaryTests
    {
        // A non-core tool (group "scripting_ext", AutoRegister=false) that is disabled
        // by default and must never be reachable straight off the socket.
        private const string DisabledNonCoreTool = "execute_code";
        // A built-in core tool that dispatches normally.
        private const string CoreTool = "manage_editor";
        private const string DisabledMarker = "is disabled in the Unity Editor";

        private bool _hadDisabledPref;
        private bool _prevDisabledValue;
        private bool _hadCorePref;
        private bool _prevCoreValue;

        [SetUp]
        public void SetUp()
        {
            var td = MCPServiceLocator.ToolDiscovery;
            // Snapshot so we don't pollute the developer's tool prefs.
            _hadDisabledPref = td.GetToolMetadata(DisabledNonCoreTool) != null
                && UnityEditor.EditorPrefs.HasKey(ToolKey(DisabledNonCoreTool));
            _prevDisabledValue = td.IsToolEnabled(DisabledNonCoreTool);
            _hadCorePref = UnityEditor.EditorPrefs.HasKey(ToolKey(CoreTool));
            _prevCoreValue = td.IsToolEnabled(CoreTool);

            // Force a deterministic starting state for the boundary.
            td.SetToolEnabled(DisabledNonCoreTool, false);
            td.SetToolEnabled(CoreTool, true);
        }

        [TearDown]
        public void TearDown()
        {
            var td = MCPServiceLocator.ToolDiscovery;
            if (_hadDisabledPref) td.SetToolEnabled(DisabledNonCoreTool, _prevDisabledValue);
            else UnityEditor.EditorPrefs.DeleteKey(ToolKey(DisabledNonCoreTool));
            if (_hadCorePref) td.SetToolEnabled(CoreTool, _prevCoreValue);
            else UnityEditor.EditorPrefs.DeleteKey(ToolKey(CoreTool));
        }

        // --- negative: disabled non-core tool refused at the dispatch boundary -----

        [Test]
        public void DisabledNonCoreTool_IsRefusedAtDispatch()
        {
            // Sanity: the tool is registered (so this isn't an "unknown tool" pass)
            // but disabled.
            Assert.IsNotNull(MCPServiceLocator.ToolDiscovery.GetToolMetadata(DisabledNonCoreTool),
                $"'{DisabledNonCoreTool}' should be a registered tool.");
            Assert.IsFalse(MCPServiceLocator.ToolDiscovery.IsToolEnabled(DisabledNonCoreTool),
                $"'{DisabledNonCoreTool}' should be disabled for this test.");

            JObject resp = Dispatch(new JObject
            {
                ["type"] = DisabledNonCoreTool,
                ["params"] = new JObject { ["code"] = "return 1 + 1;" }
            });

            Assert.AreEqual("error", (string)resp["status"],
                "A disabled tool must be refused, not executed.");
            StringAssert.Contains(DisabledMarker, (string)resp["error"],
                "Refusal must come from the enablement boundary.");
        }

        // --- positive: core tool dispatches normally ------------------------------

        [Test]
        public void CoreTool_DispatchesNormally()
        {
            // Use an unknown action so the tool reaches its handler and reports back
            // without mutating editor state — proving it passed the enablement gate.
            JObject resp = Dispatch(new JObject
            {
                ["type"] = CoreTool,
                ["params"] = new JObject { ["action"] = "__enablement_probe__" }
            });

            StringAssert.DoesNotContain(DisabledMarker, resp.ToString(),
                "A core tool must not be blocked by the enablement boundary.");
            Assert.AreEqual("success", (string)resp["status"],
                "A core tool should dispatch to its handler.");
        }

        // --- helpers --------------------------------------------------------------

        private static JObject Dispatch(JObject command)
        {
            string json = command.ToString(Newtonsoft.Json.Formatting.None);
            var task = TransportCommandDispatcher.ExecuteCommandJsonAsync(json, CancellationToken.None);
            Assert.IsTrue(task.Wait(5000), "Dispatch did not complete in time.");
            return JObject.Parse(task.Result);
        }

        private static string ToolKey(string toolName) =>
            MCPForUnity.Editor.Constants.EditorPrefKeys.ToolEnabledPrefix + toolName;
    }
}
