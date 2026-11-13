import { useEffect, useRef, useState, type FormEvent } from "react";
import type { IScannerControls } from "@zxing/browser";
import { QRCodeSVG } from "qrcode.react";
import { Camera, CameraOff, Check, ImageUp, QrCode, ScanLine, X } from "lucide-react";
import { Button } from "../../components/Button";
import { PasswordField, Segmented } from "../../components/Field";
import { ProgressBar, Spinner } from "../../components/Spinner";
import { StatusBanner } from "../../components/Status";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type PairingStatus } from "../../lib/api";
import { humanError } from "../../lib/errors";
import { cx } from "../../lib/format";

const idle: PairingStatus = { stage: "", confirmation: "", message: "", invitation: "" };

export function usePairingStatus(enabled: boolean) {
  const { setSnapshot } = useVault();
  const toast = useToast();
  const [pairing, setPairing] = useState<PairingStatus>(idle);
  const [error, setError] = useState("");
  const lastStage = useRef("");

  useEffect(() => {
    if (!enabled) return;
    let active = true;
    let first = true;
    const refresh = async () => {
      try {
        const status = await api.pairingStatus();
        if (!active) return;
        setPairing(status);
        setError("");
        if (first) {
          // The first reading may describe an older attempt; don't announce it.
          first = false;
          lastStage.current = status.stage;
          if (status.stage === "paired") setSnapshot(await api.snapshot());
        } else if (status.stage !== lastStage.current) {
          if (status.stage === "paired") {
            toast.success("Paired with your phone");
            setSnapshot(await api.snapshot());
          } else if (status.stage === "failed") {
            toast.error(status.message || "Pairing didn't finish.");
          } else if (status.stage === "confirm") {
            toast.info("Compare the code on both devices");
          }
          lastStage.current = status.stage;
        }
      } catch (failure) {
        if (active) setError(humanError(failure, "Pairing status is unavailable."));
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 500);
    return () => { active = false; window.clearInterval(timer); };
  }, [enabled, setSnapshot, toast]);

  return { pairing, error, reset: () => setPairing(idle) };
}

function stepFor(stage: string): number {
  if (stage === "confirm") return 2;
  if (stage === "transferring" || stage === "canceling") return 3;
  if (stage === "paired") return 4;
  return 1;
}

function Stepper({ step }: { step: number }) {
  const steps = ["Connect", "Confirm code", "Import vault"];
  return (
    <ol className="stepper" aria-label="Pairing steps">
      {steps.map((label, index) => {
        const number = index + 1;
        const state = number < step ? "done" : number === step ? "active" : "todo";
        return (
          <li key={label} className={cx("step", `is-${state}`)} aria-current={state === "active" ? "step" : undefined}>
            <span className="step-dot" aria-hidden="true">{state === "done" ? <Check /> : number}</span>
            <span className="step-label">{label}</span>
          </li>
        );
      })}
    </ol>
  );
}

export function PairingCard() {
  const toast = useToast();
  const { pairing, error: statusError } = usePairingStatus(true);
  const [mode, setMode] = useState<"scan" | "show">("scan");
  const [setupLink, setSetupLink] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanNotice, setScanNotice] = useState("");
  const camera = useRef<HTMLVideoElement>(null);
  const scanner = useRef<IScannerControls | null>(null);
  const qrImageInput = useRef<HTMLInputElement>(null);
  const passwordInput = useRef<HTMLInputElement>(null);
  const stage = pairing.stage;
  const step = stepFor(stage);

  const acceptQr = (link: string): boolean => {
    if (!link.startsWith("nuvori-pair://v3/") || link.length > 2048) {
      setScanNotice("");
      setError("This QR isn't a Nuvori pairing invitation.");
      return false;
    }
    setError("");
    setSetupLink(link);
    setScanNotice("QR read. Enter your phone's master password to continue.");
    setScanning(false);
    toast.success("Pairing QR read");
    window.setTimeout(() => passwordInput.current?.focus(), 0);
    return true;
  };

  const readQrImage = async (file?: File) => {
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) {
      setError("Choose a QR image smaller than 20 MB.");
      if (qrImageInput.current) qrImageInput.current.value = "";
      return;
    }
    setScanning(false);
    setError("");
    setScanNotice("Reading QR image…");
    try {
      const url = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
      });
      const { BrowserQRCodeReader } = await import("@zxing/browser");
      acceptQr((await new BrowserQRCodeReader().decodeFromImageUrl(url)).getText());
    } catch {
      setScanNotice("");
      setError("Couldn't read a QR from this image. Paste the setup link instead.");
    } finally {
      if (qrImageInput.current) qrImageInput.current.value = "";
    }
  };

  useEffect(() => {
    if (!scanning) return;
    let closed = false;
    let completed = false;
    setError("");
    setScanNotice("Opening camera…");
    import("@zxing/browser").then(async ({ BrowserQRCodeReader }) => {
      if (!camera.current) return;
      const reader = new BrowserQRCodeReader();
      const controls = await reader.decodeFromVideoDevice(undefined, camera.current, (result, _error, liveControls) => {
        if (closed || !result) return;
        if (!acceptQr(result.getText())) return;
        completed = true;
        liveControls.stop();
      });
      if (closed || completed) controls.stop();
      else { scanner.current = controls; setScanNotice("Point the camera at the QR on your phone."); }
    }).catch((failure: unknown) => {
      if (closed) return;
      const name = failure instanceof Error ? failure.name : "";
      const reason = name === "NotAllowedError" ? "Camera access was denied."
        : name === "NotFoundError" ? "No camera was found."
        : name === "NotReadableError" ? "The camera is busy or unavailable."
        : "The camera couldn't start.";
      setError(`${reason} Paste the setup link from your phone instead.`);
      setScanNotice("");
      setScanning(false);
    });
    return () => { closed = true; scanner.current?.stop(); scanner.current = null; };
  }, [scanning]); // eslint-disable-line react-hooks/exhaustive-deps

  const start = async (event: FormEvent) => {
    event.preventDefault();
    if (!setupLink.trim()) { setError("Scan the QR or paste the setup link from your phone."); return; }
    if (masterPassword.length < 12) { setError("Enter your phone vault's master password."); passwordInput.current?.focus(); return; }
    setScanning(false);
    setBusy(true);
    setError("");
    try {
      await api.startPairing(setupLink.trim(), masterPassword);
      toast.info("Connecting to your phone…");
      setSetupLink("");
      setMasterPassword("");
    } catch (failure) {
      setError(humanError(failure, "Pairing couldn't start."));
    } finally {
      setBusy(false);
    }
  };

  const startReverse = async (event: FormEvent) => {
    event.preventDefault();
    if (masterPassword.length < 12) {
      setError("Enter your phone vault's master password first.");
      passwordInput.current?.focus();
      return;
    }
    setScanning(false);
    setBusy(true);
    setError("");
    try {
      await api.startReversePairing(masterPassword);
      toast.info("Scan the QR with your phone");
      setMasterPassword("");
      setSetupLink("");
    } catch (failure) {
      setError(humanError(failure, "Couldn't create a pairing QR."));
    } finally {
      setBusy(false);
    }
  };

  const action = async (command: "approve" | "cancel") => {
    try {
      setError("");
      if (command === "approve") { await api.approvePairing(); toast.info("Code confirmed. Waiting for your phone…"); }
      else { await api.cancelPairing(); toast.info("Pairing canceled"); }
    } catch (failure) {
      toast.error(failure);
    }
  };

  return (
    <section className="card card-padded pairing" aria-labelledby="pairing-title">
      <header className="card-header compact">
        <div className="card-heading">
          <h2 id="pairing-title">Pair with your phone</h2>
          <p>Both devices confirm the same code before this PC receives a copy of your vault.</p>
        </div>
      </header>
      <Stepper step={step} />

      {statusError && <StatusBanner kind="warning">{statusError}</StatusBanner>}
      {stage === "failed" && <StatusBanner kind="error" title="Pairing didn't finish">{pairing.message || "Start again from your phone."}</StatusBanner>}
      {error && <StatusBanner kind="error">{error}</StatusBanner>}

      {stage === "confirm" ? (
        <div className="pairing-confirm">
          <p>{pairing.message || "Compare this code with the one on your phone. Confirm on both devices."}</p>
          <output className="pairing-code" aria-label={`Pairing code ${pairing.confirmation.split("").join(" ")}`}>{pairing.confirmation}</output>
          <div className="button-row">
            <Button variant="primary" size="lg" icon={Check} onClick={() => void action("approve")}>Codes match</Button>
            <Button size="lg" onClick={() => void action("cancel")}>They don't match</Button>
          </div>
        </div>
      ) : stage === "offering" ? (
        <div className="pairing-offer">
          <div className="qr-frame"><QRCodeSVG value={pairing.invitation} size={240} marginSize={2} role="img" aria-label="Pairing QR for your phone to scan" /></div>
          <div className="pairing-offer-text">
            <p><strong>On your phone:</strong> open Devices, tap <em>Scan Windows QR</em>, and point it at this code.</p>
            <p className="muted small">{pairing.message}</p>
            <Button onClick={() => void action("cancel")} icon={X}>Cancel</Button>
          </div>
        </div>
      ) : stage === "connecting" || stage === "transferring" || stage === "canceling" ? (
        <div className="pairing-progress">
          <div className="pairing-progress-row"><Spinner /><span>{pairing.message || (stage === "transferring" ? "Receiving the encrypted vault copy…" : "Connecting…")}</span></div>
          <ProgressBar label="Pairing progress" indeterminate />
          <Button disabled={stage === "canceling"} onClick={() => void action("cancel")} icon={X}>Cancel</Button>
        </div>
      ) : stage === "paired" ? (
        <StatusBanner kind="success" title="Paired">{pairing.message || "This PC and your phone now keep their own copies in sync."}</StatusBanner>
      ) : (
        <>
          <Segmented label="Pairing method" value={mode} onChange={(value) => { setMode(value); setError(""); setScanning(false); }}
            options={[{ value: "scan", label: "Scan phone's QR", icon: ScanLine }, { value: "show", label: "Show QR to phone", icon: QrCode }]} />
          {mode === "scan" ? (
            <form className="form-stack" onSubmit={(event) => void start(event)} noValidate>
              <p className="muted small">On your phone, open <strong>Devices</strong> and choose <strong>Create QR</strong>. Scan it with this PC's camera, or copy the link and paste it below.</p>
              <div className="button-row">
                <Button icon={scanning ? CameraOff : Camera} onClick={() => { setScanNotice(""); setScanning((value) => !value); }}>{scanning ? "Stop camera" : "Use camera"}</Button>
                <Button icon={ImageUp} onClick={() => qrImageInput.current?.click()}>Read QR image</Button>
                <input ref={qrImageInput} type="file" accept="image/*" className="sr-only" tabIndex={-1} aria-label="Choose pairing QR image" onChange={(event) => void readQrImage(event.target.files?.[0])} />
              </div>
              {scanning && <video ref={camera} className="pairing-camera" autoPlay muted playsInline aria-label="Camera preview for the phone's pairing QR" />}
              {scanNotice && <p className="muted small" role="status">{scanNotice}</p>}
              <PasswordField label="Setup link" value={setupLink} onValue={setSetupLink} autoComplete="off" hint="Starts with nuvori-pair://v3/. It contains a one-time secret." />
              <PasswordField ref={passwordInput} label="Phone's master password" value={masterPassword} onValue={setMasterPassword} autoComplete="current-password" capsLockWarning />
              <div className="form-actions start">
                <Button variant="primary" type="submit" busy={busy}>Continue</Button>
              </div>
            </form>
          ) : (
            <form className="form-stack" onSubmit={(event) => void startReverse(event)} noValidate>
              <p className="muted small">Use this if your phone can't reach this PC. This PC shows a QR; your phone scans it with <strong>Scan Windows QR</strong>.</p>
              <PasswordField ref={passwordInput} label="Phone's master password" value={masterPassword} onValue={setMasterPassword} autoComplete="current-password" capsLockWarning />
              <div className="form-actions start">
                <Button variant="primary" type="submit" icon={QrCode} busy={busy}>Show QR</Button>
              </div>
            </form>
          )}
        </>
      )}
    </section>
  );
}
