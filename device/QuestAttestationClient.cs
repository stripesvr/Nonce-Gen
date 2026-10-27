// QuestAttestationClient.cs — Assets/Scripts/
// Meta XR Platform SDK v55+, Meta Horizon OS v55+.
// One paste: the pairing code from the desktop window. One press: Send.
// The desktop verifies, shows the token, and tells you the verdict.

using System;
using System.Collections;
using System.Text;
using Oculus.Platform;
using Oculus.Platform.Models;
using UnityEngine;
using UnityEngine.Networking;

public sealed class QuestAttestationClient : MonoBehaviour
{
    [Header("Pairing")]
    [Tooltip("Paste the pairing code shown in the desktop window.")]
    [SerializeField] private string pairingCode = "";

    [Header("Runtime")]
    [SerializeField] private bool autoSendOnStart = false;

    [Serializable]
    private sealed class Pair
    {
        public string u; // endpoint
        public string s; // secret
        public string n; // nonce
        public string p; // package
    }

    [Serializable]
    private sealed class Envelope
    {
        public string code;
        public string token;
    }

    private bool _busy;

    /// <summary>Pull the pairing code off the system clipboard (Quest shares it with the browser).</summary>
    public void PasteFromClipboard()
    {
        string clip = GUIUtility.systemCopyBuffer;
        if (string.IsNullOrWhiteSpace(clip))
        {
            Debug.LogWarning("[attest] clipboard is empty");
            return;
        }
        pairingCode = clip.Trim();
        Debug.Log("[attest] pairing code pasted (" + pairingCode.Length + " chars)");
    }

    private void Start()
    {
        if (autoSendOnStart) Send();
    }

    public void Send()
    {
        if (_busy) return;

        Pair pair;
        try
        {
            pair = JSONUtility_FromBase64(pairingCode.Trim());
        }
        catch (Exception exc)
        {
            Debug.LogError("[attest] pairing code unreadable: " + exc.Message);
            return;
        }

        if (string.IsNullOrEmpty(pair.n) || pair.n.Length < 22)
        {
            Debug.LogError("[attest] nonce missing or too short");
            return;
        }

        _busy = true;
        Debug.Log("[attest] asking the headset for a token");

        DeviceApplicationIntegrity
            .GetIntegrityToken(pair.n)
            .OnComplete(msg => OnToken(msg, pair));
    }

    private void OnToken(Message<string> msg, Pair pair)
    {
        if (msg.IsError)
        {
            _busy = false;
            Debug.LogError("[attest] GetIntegrityToken failed: " + msg.GetError().Message);
            return;
        }

        string token = msg.Data;
        if (string.IsNullOrEmpty(token))
        {
            _busy = false;
            Debug.LogError("[attest] empty token");
            return;
        }

        // Local copy so you can eyeball or fall back to "I already have a token".
        GUIUtility.systemCopyBuffer = token;
        Debug.Log("[attest] token received, handing it to the desktop");

        StartCoroutine(Post(pair.u, token, pairingCode.Trim()));
    }

    private IEnumerator Post(string endpoint, string token, string code)
    {
        var envelope = new Envelope { code = code, token = token };
        byte[] raw = Encoding.UTF8.GetBytes(JsonUtility.ToJson(envelope));

        using var req = new UnityWebRequest(endpoint, UnityWebRequest.kHttpVerbPOST);
        req.uploadHandler = new UploadHandlerRaw(raw);
        req.downloadHandler = new DownloadHandlerBuffer();
        req.SetRequestHeader("Content-Type", "application/json");
        req.timeout = 25;

        yield return req.SendWebRequest();

        _busy = false;

        if (req.result != UnityWebRequest.Result.Success)
        {
            Debug.LogError($"[attest] desktop refused: {(long)req.responseCode} {req.downloadHandler.text}");
            yield break;
        }

        Debug.Log("[attest] desktop says: " + req.downloadHandler.text);
    }

    private static Pair JSONUtility_FromBase64(string code)
    {
        string normalised = code.Replace('-', '+').Replace('_', '/');
        int pad = (4 - normalised.Length % 4) % 4;
        normalised = normalised.PadRight(normalised.Length + pad, '=');

        byte[] bytes = Convert.FromBase64String(normalised);
        string json = Encoding.UTF8.GetString(bytes);
        var pair = JsonUtility.FromJson<Pair>(json);
        if (pair == null || string.IsNullOrEmpty(pair.u)) throw new FormatException("no endpoint in code");
        return pair;
    }
}
