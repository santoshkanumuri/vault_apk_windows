import { useEffect, useRef, useState, type FormEvent } from "react";
import type { IScannerControls } from "@zxing/browser";
import { Camera, CameraOff, Clock3, FileText, ImageUp } from "lucide-react";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { SettingsRow } from "../components/Display";
import { PasswordField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api } from "../lib/api";
import { alreadyRead, importResult, isOneAuthExport, MAX_EXPORT_BYTES, reviewHeading, reviewLabel,
  type AuthenticatorReview, type AuthenticatorSource } from "../lib/authenticatorImport";
import { authenticatorImportText as text, strings } from "../strings";

const message = (failure: unknown, fallback: string) =>
  typeof failure === "string" ? failure : failure instanceof Error && failure.message ? failure.message : fallback;

/** Settings > Your data > Import authenticator codes. */
export function AuthenticatorImportRow() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <SettingsRow icon={Clock3} title={text.title} description={text.row} onClick={() => setOpen(true)} />
      <AuthenticatorImportDialog open={open} onClose={() => setOpen(false)} />
    </>
  );
}

/**
 * Import authenticator codes as on Android: read Google Authenticator transfer QRs (camera or a
 * saved image), a standard setup QR, a text file of otpauth links or a Zoho OneAuth export; review
 * every account against the saved codes; then save the new ones. What was read stays in this
 * dialog's memory only and is dropped when it closes.
 */
export function AuthenticatorImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const { refresh } = useVault();
  const [sources, setSources] = useState<AuthenticatorSource[]>([]);
  const [review, setReview] = useState<AuthenticatorReview | null>(null);
  const [oneAuth, setOneAuth] = useState<string | null>(null);
  const [oneAuthPassword, setOneAuthPassword] = useState("");
  const [scanning, setScanning] = useState(false);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<"" | "read" | "import">("");
  const [error, setError] = useState("");
  const camera = useRef<HTMLVideoElement>(null);
  const scanner = useRef<IScannerControls | null>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const latest = useRef(sources);
  latest.current = sources;

  const clear = () => { setSources([]); setReview(null); setError(""); };
  const reset = () => { setScanning(false); clear(); setOneAuth(null); setOneAuthPassword(""); setNotice(""); };
  const close = () => {
    if (busy === "import") return;
    reset();
    onClose();
  };

  /** Adds one page and reviews them all; a page that can't join this batch leaves it as it was. */
  const add = async (source: AuthenticatorSource) => {
    const current = latest.current;
    if (alreadyRead(current, source)) { setNotice(""); return; }
    setBusy("read"); setError("");
    try {
      const next = [...current, source];
      setReview(await api.authenticatorsPreview(next));
      setSources(next);
      setNotice("");
    } catch (failure) {
      setNotice("");
      setError(message(failure, text.fileUnreadable));
    } finally {
      setBusy("");
    }
  };

  const readImage = async (file?: File) => {
    if (imageInput.current) imageInput.current.value = "";
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) { setError(text.imageTooLarge); return; }
    setScanning(false); setError("");
    try {
      const url = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
      });
      const { BrowserQRCodeReader } = await import("@zxing/browser");
      await add({ kind: "qr", text: (await new BrowserQRCodeReader().decodeFromImageUrl(url)).getText() });
    } catch {
      setError(text.imageUnreadable);
    }
  };

  const readFile = async (file?: File) => {
    if (fileInput.current) fileInput.current.value = "";
    if (!file) return;
    setScanning(false); setError("");
    try {
      if (file.size > MAX_EXPORT_BYTES) throw new Error("too large");
      const content = await file.text();
      if (isOneAuthExport(content)) { setOneAuth(content); setOneAuthPassword(""); return; }
      await add({ kind: "text", text: content });
    } catch {
      setError(text.fileUnreadable);
    }
  };

  const unlockOneAuth = async (event: FormEvent) => {
    event.preventDefault();
    if (!oneAuth || !oneAuthPassword) return;
    const source: AuthenticatorSource = { kind: "oneAuth", text: oneAuth, password: oneAuthPassword };
    setOneAuth(null); setOneAuthPassword("");
    await add(source);
  };

  const importCodes = async () => {
    setBusy("import"); setError("");
    try {
      const result = importResult(await api.authenticatorsImport(latest.current));
      if (result.tone === "success") toast.success(result.message);
      else if (result.tone === "warning") toast.warning(result.message);
      else toast.info(result.message);
      await refresh();
      setBusy("");
      reset();
      onClose();
    } catch (failure) {
      setError(message(failure, text.failed));
      setBusy("");
    }
  };

  // The camera reads one QR, then stops, as on Android; choose Use camera again for the next page.
  useEffect(() => {
    if (!scanning) return;
    let closed = false;
    let completed = false;
    setNotice(text.openingCamera);
    import("@zxing/browser").then(async ({ BrowserQRCodeReader }) => {
      if (!camera.current) return;
      const controls = await new BrowserQRCodeReader().decodeFromVideoDevice(undefined, camera.current, (result, _error, liveControls) => {
        if (closed || completed || !result) return;
        completed = true;
        liveControls.stop();
        setScanning(false);
        void add({ kind: "qr", text: result.getText() });
      });
      if (closed || completed) controls.stop();
      else { scanner.current = controls; setNotice(text.pointCamera); }
    }).catch((failure: unknown) => {
      if (closed) return;
      const name = failure instanceof Error ? failure.name : "";
      setError(name === "NotAllowedError" ? "Camera access was denied."
        : name === "NotFoundError" ? "No camera was found."
        : name === "NotReadableError" ? "The camera is busy or unavailable."
        : "The camera couldn't start.");
      setNotice("");
      setScanning(false);
    });
    return () => { closed = true; scanner.current?.stop(); scanner.current = null; };
  }, [scanning]); // eslint-disable-line react-hooks/exhaustive-deps

  const complete = review !== null && review.pages === review.expected;

  return (
    <Dialog open={open} onClose={close} title={text.title} size="md" locked={busy === "import"}
      footer={<>
        {review && <Button variant="ghost" onClick={clear} disabled={busy !== ""}>{text.clear}</Button>}
        <Button variant="ghost" onClick={close} disabled={busy === "import"}>{strings.cancel}</Button>
        <Button variant="primary" onClick={() => void importCodes()} busy={busy === "import"} disabled={!complete || busy !== ""}>{text.importCodes}</Button>
      </>}>
      <div className="form-stack">
        <p className="muted small">{text.howTo}</p>
        <div className="button-row">
          <Button icon={scanning ? CameraOff : Camera} onClick={() => { setError(""); setNotice(""); setScanning((value) => !value); }} disabled={busy !== ""}>
            {scanning ? text.stopCamera : text.useCamera}
          </Button>
          <Button icon={ImageUp} onClick={() => imageInput.current?.click()} disabled={busy !== ""}>{text.chooseQrImage}</Button>
          <Button icon={FileText} onClick={() => fileInput.current?.click()} disabled={busy !== ""}>{text.chooseFile}</Button>
          <input ref={imageInput} type="file" accept="image/*" className="sr-only" tabIndex={-1} aria-label={text.chooseQrImage} onChange={(event) => void readImage(event.target.files?.[0])} />
          <input ref={fileInput} type="file" accept=".json,.txt,application/json,text/plain" className="sr-only" tabIndex={-1} aria-label={text.chooseFile} onChange={(event) => void readFile(event.target.files?.[0])} />
        </div>
        {scanning && <video ref={camera} className="pairing-camera" autoPlay muted playsInline aria-label={text.cameraPreview} />}
        {notice && <p className="muted small" role="status">{notice}</p>}
        <p className="muted small">{text.alsoSupported}</p>
        <StatusBanner kind="warning">{text.plaintextWarning}</StatusBanner>
        {oneAuth !== null && (
          <form className="form-stack" onSubmit={(event) => void unlockOneAuth(event)} aria-label={text.unlockOneAuth}>
            <PasswordField label={text.exportPassword} value={oneAuthPassword} onValue={setOneAuthPassword} autoComplete="off" autoFocus />
            <div className="button-row">
              <Button variant="primary" type="submit" disabled={!oneAuthPassword || busy !== ""}>{text.unlock}</Button>
              <Button variant="ghost" onClick={() => { setOneAuth(null); setOneAuthPassword(""); }}>{strings.cancel}</Button>
            </div>
          </form>
        )}
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        {review && (
          <section className="form-stack" aria-label={reviewHeading(review)}>
            <p className="authenticator-import-heading">{reviewHeading(review)}</p>
            <ul className="keepass-counts">
              {review.items.map((item, index) => <li key={index}>{reviewLabel(item)}</li>)}
            </ul>
            {!complete && <StatusBanner kind="info">{text.scanRemaining}</StatusBanner>}
            <p className="muted small">{text.reviewNote}</p>
          </section>
        )}
      </div>
    </Dialog>
  );
}
