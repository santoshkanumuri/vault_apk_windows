import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** Runs the Android J-PAKE library against the Windows helper process. */
public final class InteropTest {
    private static JsonArray proof(BigInteger[] values) {
        JsonArray result = new JsonArray();
        for (BigInteger value : values) result.add(value.toString(16));
        return result;
    }

    private static BigInteger[] readProof(JsonObject value, String name) {
        JsonArray values = value.getAsJsonArray(name);
        return new BigInteger[] { new BigInteger(values.get(0).getAsString(), 16),
            new BigInteger(values.get(1).getAsString(), 16) };
    }

    private static JsonObject receive(BufferedReader input) throws Exception {
        JsonObject result = JsonParser.parseString(input.readLine()).getAsJsonObject();
        if (result.has("error")) throw new AssertionError(result.get("error").getAsString());
        return result;
    }

    private static void send(OutputStreamWriter output, JsonObject value) throws Exception {
        output.write(value.toString() + "\n");
        output.flush();
    }

    public static void main(String[] args) throws Exception {
        Process helper = new ProcessBuilder("dotnet", args[0]).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        try (BufferedReader input = new BufferedReader(new InputStreamReader(helper.getInputStream(), StandardCharsets.UTF_8));
             OutputStreamWriter output = new OutputStreamWriter(helper.getOutputStream(), StandardCharsets.UTF_8)) {
            String secret = "123456789012345678901234";
            JPAKEParticipant android = new JPAKEParticipant("android", secret.toCharArray());
            JsonObject init = new JsonObject();
            init.addProperty("action", "init"); init.addProperty("id", "windows"); init.addProperty("secret", secret);
            send(output, init);
            if (!receive(input).get("ready").getAsBoolean()) throw new AssertionError("Helper not ready");

            JsonObject peer1 = receive(input);
            JPAKERound1Payload first = android.createRound1PayloadToSend();
            JsonObject outbound1 = new JsonObject();
            outbound1.addProperty("id", first.getParticipantId());
            outbound1.addProperty("gx1", first.getGx1().toString(16));
            outbound1.addProperty("gx2", first.getGx2().toString(16));
            outbound1.add("p1", proof(first.getKnowledgeProofForX1()));
            outbound1.add("p2", proof(first.getKnowledgeProofForX2()));
            android.validateRound1PayloadReceived(new JPAKERound1Payload(peer1.get("id").getAsString(),
                new BigInteger(peer1.get("gx1").getAsString(), 16), new BigInteger(peer1.get("gx2").getAsString(), 16),
                readProof(peer1, "p1"), readProof(peer1, "p2")));
            send(output, outbound1);

            JsonObject peer2 = receive(input);
            JPAKERound2Payload second = android.createRound2PayloadToSend();
            JsonObject outbound2 = new JsonObject();
            outbound2.addProperty("id", second.getParticipantId());
            outbound2.addProperty("a", second.getA().toString(16));
            outbound2.add("proof", proof(second.getKnowledgeProofForX2s()));
            android.validateRound2PayloadReceived(new JPAKERound2Payload(peer2.get("id").getAsString(),
                new BigInteger(peer2.get("a").getAsString(), 16), readProof(peer2, "proof")));
            send(output, outbound2);

            JsonObject peer3 = receive(input);
            BigInteger material = android.calculateKeyingMaterial();
            JPAKERound3Payload third = android.createRound3PayloadToSend(material);
            JsonObject outbound3 = new JsonObject();
            outbound3.addProperty("id", third.getParticipantId());
            outbound3.addProperty("mac", third.getMacTag().toString(16));
            android.validateRound3PayloadReceived(new JPAKERound3Payload(peer3.get("id").getAsString(),
                new BigInteger(peer3.get("mac").getAsString(), 16)), material);
            send(output, outbound3);

            byte[] windowsMaterial = Base64.getDecoder().decode(receive(input).get("material").getAsString());
            if (!Arrays.equals(windowsMaterial, material.toByteArray())) throw new AssertionError("Keying material differs");
            if (helper.waitFor() != 0) throw new AssertionError("Helper failed");
            System.out.println("Android and Windows J-PAKE keying material matches");
        } finally {
            helper.destroyForcibly();
        }
    }
}
