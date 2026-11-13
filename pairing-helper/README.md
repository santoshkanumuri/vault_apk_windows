# Pairing helper

Android uses Bouncy Castle J-PAKE. This small .NET process uses the same library's C# implementation. The Rust pairing code starts it with redirected stdin and stdout for the three J-PAKE rounds. The helper returns keying material only after it verifies the peer's final proof. Rust then derives the session key using Android's pairing transcript.

Build with `dotnet build pairing-helper/Nuvori.PairingHelper.csproj`. The project targets .NET 8 and restores the official `BouncyCastle.Cryptography` package from NuGet. Run `npm run package:windows` from the Windows app root to publish the helper as a self-contained win-x64 executable and include it in the Tauri installer. Pairing is still disabled until Windows can commit Android's enrollment snapshot and preserve existing Windows items.

`InteropTest.java` exercises the helper against Android's `JPAKEParticipant` from `bcprov-jdk18on`. Compile it with the Bouncy Castle and Gson jars on the classpath, then pass the built helper DLL as its first argument. It completes all three rounds and compares the raw keying material. The Rust `pairing::tests::rust_wire_and_bouncy_castle_helper_complete_both_pairing_roles` test checks the framed Rust handshake with two helper processes; set `NUVORI_PAIRING_HELPER` to the DLL or executable and run that ignored test explicitly.
