using NUnit.Framework;
using Newtonsoft.Json.Linq;
using MCPForUnity.Editor.Tools;
using MCPForUnity.Editor.Constants;
using UnityEditor;

namespace MCPForUnityTests.Editor.Tools
{
    /// <summary>
    /// Play-mode gate tests for manage_editor action=play (harden/security, R6).
    ///
    /// Entering play mode runs project/game code — including scripts the AI just
    /// authored — so it is opt-in behind the AllowPlayMode pref (default false).
    ///
    /// The negative case is exercised end-to-end: with the pref false, the play
    /// action is blocked and no transition occurs. The positive case asserts the
    /// gate *decision* (ManageEditor.PlayModeAllowed) flips to true — deliberately
    /// NOT performing the real transition, since actually entering play mode inside
    /// an EditMode run corrupts the test framework's scene restore. The handler's
    /// block depends solely on this predicate, so the two together prove both
    /// directions without the destructive side effect.
    /// </summary>
    [TestFixture]
    public class PlayModeGateTests
    {
        private static JObject ToJO(object o) => JObject.FromObject(o);

        private bool _hadPref;
        private bool _prevPref;

        [SetUp]
        public void SetUp()
        {
            _hadPref = EditorPrefs.HasKey(EditorPrefKeys.AllowPlayMode);
            _prevPref = EditorPrefs.GetBool(EditorPrefKeys.AllowPlayMode, false);
        }

        [TearDown]
        public void TearDown()
        {
            if (_hadPref) EditorPrefs.SetBool(EditorPrefKeys.AllowPlayMode, _prevPref);
            else EditorPrefs.DeleteKey(EditorPrefKeys.AllowPlayMode);
        }

        // --- negative: default-off blocks play, with no transition ----------------

        [Test]
        public void Play_Blocked_WhenAllowPlayModeFalse()
        {
            EditorPrefs.SetBool(EditorPrefKeys.AllowPlayMode, false);

            Assert.IsFalse(ManageEditor.PlayModeAllowed(),
                "Gate must be closed when AllowPlayMode is false (the default).");

            var res = ManageEditor.HandleCommand(new JObject { ["action"] = "play" });
            var jo = ToJO(res);

            Assert.IsFalse((bool)jo["success"], "Play must be blocked when AllowPlayMode is false.");
            StringAssert.Contains("disabled by default", (string)jo["error"],
                "Expected the hardened play-mode block message.");
            Assert.IsFalse(EditorApplication.isPlaying,
                "A blocked play request must not have entered play mode.");
        }

        // --- positive: pref-on opens the gate -------------------------------------

        [Test]
        public void Gate_Opens_WhenAllowPlayModeTrue()
        {
            EditorPrefs.SetBool(EditorPrefKeys.AllowPlayMode, true);

            // The handler's block branch is `if (!PlayModeAllowed()) return block;`,
            // so a true predicate is exactly what lets the play request through.
            // We assert the decision rather than triggering the real transition,
            // which would break the EditMode run's scene teardown.
            Assert.IsTrue(ManageEditor.PlayModeAllowed(),
                "Gate must open when AllowPlayMode is true.");
            Assert.IsFalse(EditorApplication.isPlaying,
                "Asserting the gate must not have entered play mode.");
        }
    }
}
