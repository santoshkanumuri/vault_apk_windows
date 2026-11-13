using System.Text.Json;
using Org.BouncyCastle.Crypto.Agreement.JPake;
using Org.BouncyCastle.Math;

static JsonElement Read()
{
    var line = Console.ReadLine() ?? throw new InvalidDataException("Pairing ended");
    if (line.Length is < 2 or > 32768) throw new InvalidDataException("Invalid pairing message");
    return JsonDocument.Parse(line).RootElement.Clone();
}

static string Text(JsonElement data, string name)
{
    var value = data.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing pairing field");
    if (value.Length is < 1 or > 8192) throw new InvalidDataException("Invalid pairing field");
    return value;
}

static BigInteger ParseInteger(string? value)
{
    if (value is null || value.Length is < 1 or > 1025 ||
        value.TrimStart('-').Any(c => !Uri.IsHexDigit(c))) throw new InvalidDataException("Invalid pairing integer");
    return new BigInteger(value, 16);
}

static BigInteger Integer(JsonElement data, string name) => ParseInteger(Text(data, name));
static BigInteger[] Proof(JsonElement data, string name)
{
    var values = data.GetProperty(name).EnumerateArray().Select(value => ParseInteger(value.GetString())).ToArray();
    if (values.Length != 2) throw new InvalidDataException("Invalid pairing proof");
    return values;
}

static void Send(object response) => Console.WriteLine(JsonSerializer.Serialize(response));

try
{
    var init = Read();
    if (Text(init, "action") != "init") throw new InvalidDataException("Expected pairing start");
    var secret = Text(init, "secret").ToCharArray();
    var participant = new JPakeParticipant(Text(init, "id"), secret);
    Array.Clear(secret);
    Send(new { ready = true });

    var first = participant.CreateRound1PayloadToSend();
    Send(new { id = first.ParticipantId, gx1 = first.Gx1.ToString(16), gx2 = first.Gx2.ToString(16),
        p1 = first.KnowledgeProofForX1.Select(value => value.ToString(16)),
        p2 = first.KnowledgeProofForX2.Select(value => value.ToString(16)) });
    var peer1 = Read();
    participant.ValidateRound1PayloadReceived(new JPakeRound1Payload(Text(peer1, "id"), Integer(peer1, "gx1"),
        Integer(peer1, "gx2"), Proof(peer1, "p1"), Proof(peer1, "p2")));

    var second = participant.CreateRound2PayloadToSend();
    Send(new { id = second.ParticipantId, a = second.A.ToString(16),
        proof = second.KnowledgeProofForX2s.Select(value => value.ToString(16)) });
    var peer2 = Read();
    participant.ValidateRound2PayloadReceived(new JPakeRound2Payload(Text(peer2, "id"), Integer(peer2, "a"), Proof(peer2, "proof")));

    var material = participant.CalculateKeyingMaterial();
    var third = participant.CreateRound3PayloadToSend(material);
    Send(new { id = third.ParticipantId, mac = third.MacTag.ToString(16) });
    var peer3 = Read();
    participant.ValidateRound3PayloadReceived(new JPakeRound3Payload(Text(peer3, "id"), Integer(peer3, "mac")), material);
    Send(new { material = Convert.ToBase64String(material.ToByteArray()) });
}
catch
{
    Send(new { error = "Pairing handshake failed" });
    return 1;
}
return 0;
