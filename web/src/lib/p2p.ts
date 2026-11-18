/**
 * Direct browser-to-browser links over WebRTC data channels.
 *
 * The relay server only carries the signalling (SDP + ICE candidates). Once a link is open,
 * envelopes flow peer-to-peer and never touch the server. Links are an optimisation: the
 * envelopes are already end-to-end encrypted by the Double Ratchet, so a link that can't be
 * established (or an attacker on the signalling path) just means we fall back to the relay.
 *
 * Offer collisions (both sides dialling at once) are resolved with the "polite / impolite peer"
 * scheme: the polite side rolls back its own offer, the impolite side ignores the incoming one.
 */

export type LinkState = "connecting" | "open";

export type Signal =
  | { kind: "description"; description: RTCSessionDescriptionInit }
  | { kind: "candidate"; candidate: RTCIceCandidateInit }
  | { kind: "bye" };

export interface LinkFrame {
  t: "env";
  envelope: unknown;
  transient?: boolean;
}

interface Link {
  pc: RTCPeerConnection;
  channel: RTCDataChannel;
  polite: boolean;
  makingOffer: boolean;
  ignoreOffer: boolean;
  state: LinkState;
  timeout: ReturnType<typeof setTimeout>;
}

export interface PeerLinkOptions {
  selfId: string;
  iceServers(): RTCIceServer[];
  sendSignal(peerId: string, signal: Signal): void;
  onFrame(peerId: string, frame: LinkFrame): void;
  onState(peerId: string, state: LinkState | null): void;
}

const CONNECT_TIMEOUT_MS = 15_000;
const RETRY_COOLDOWN_MS = 60_000;
const MAX_FRAME_BYTES = 64 * 1024;

export class PeerLinks {
  private readonly options: PeerLinkOptions;
  private readonly links = new Map<string, Link>();
  private readonly cooldown = new Map<string, number>();

  constructor(options: PeerLinkOptions) {
    this.options = options;
  }

  static supported(): boolean {
    return typeof RTCPeerConnection !== "undefined";
  }

  isOpen(peerId: string): boolean {
    return this.links.get(peerId)?.state === "open";
  }

  /** Dial a peer (no-op if a link exists or a recent attempt failed). */
  connect(peerId: string): void {
    if (!PeerLinks.supported() || this.links.has(peerId)) return;
    if ((this.cooldown.get(peerId) ?? 0) > Date.now()) return;
    this.create(peerId);
  }

  send(peerId: string, frame: LinkFrame): boolean {
    const link = this.links.get(peerId);
    if (link?.state !== "open" || link.channel.readyState !== "open") return false;
    const data = JSON.stringify(frame);
    if (data.length > MAX_FRAME_BYTES) return false;
    try {
      link.channel.send(data);
      return true;
    } catch {
      return false;
    }
  }

  async handleSignal(peerId: string, signal: Signal): Promise<void> {
    if (signal.kind === "bye") return this.close(peerId, false);
    let link = this.links.get(peerId);
    if (!link) {
      // Only an incoming offer may create a link; stray candidates/answers are ignored.
      if (signal.kind !== "description" || signal.description.type !== "offer") return;
      link = this.create(peerId);
    }
    const { pc } = link;
    try {
      if (signal.kind === "description") {
        const description = signal.description;
        const collision = description.type === "offer" && (link.makingOffer || pc.signalingState !== "stable");
        link.ignoreOffer = !link.polite && collision;
        if (link.ignoreOffer) return;
        await pc.setRemoteDescription(description);
        if (description.type === "offer") {
          await pc.setLocalDescription();
          this.options.sendSignal(peerId, { kind: "description", description: pc.localDescription!.toJSON() });
        }
      } else if (signal.kind === "candidate") {
        try {
          await pc.addIceCandidate(signal.candidate);
        } catch (err) {
          if (!link.ignoreOffer) throw err;
        }
      }
    } catch {
      this.fail(peerId);
    }
  }

  close(peerId: string, notifyPeer = true): void {
    const link = this.links.get(peerId);
    if (!link) return;
    this.links.delete(peerId);
    clearTimeout(link.timeout);
    link.channel.onclose = null;
    link.pc.onconnectionstatechange = null;
    link.channel.close();
    link.pc.close();
    if (notifyPeer) this.options.sendSignal(peerId, { kind: "bye" });
    this.options.onState(peerId, null);
  }

  closeAll(): void {
    for (const peerId of [...this.links.keys()]) this.close(peerId);
  }

  // ------------------------------------------------------------------

  private create(peerId: string): Link {
    const pc = new RTCPeerConnection({ iceServers: this.options.iceServers() });
    // Pre-negotiated channel id: both sides create it, so there is no "who opens it" asymmetry.
    const channel = pc.createDataChannel("parley", { negotiated: true, id: 0, ordered: true });
    const link: Link = {
      pc,
      channel,
      polite: this.options.selfId > peerId,
      makingOffer: false,
      ignoreOffer: false,
      state: "connecting",
      timeout: setTimeout(() => this.fail(peerId), CONNECT_TIMEOUT_MS),
    };
    this.links.set(peerId, link);
    this.options.onState(peerId, "connecting");

    pc.onnegotiationneeded = async () => {
      try {
        link.makingOffer = true;
        await pc.setLocalDescription();
        this.options.sendSignal(peerId, { kind: "description", description: pc.localDescription!.toJSON() });
      } catch {
        this.fail(peerId);
      } finally {
        link.makingOffer = false;
      }
    };
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) this.options.sendSignal(peerId, { kind: "candidate", candidate: candidate.toJSON() });
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "failed" || pc.connectionState === "closed") this.fail(peerId);
    };
    channel.onopen = () => {
      clearTimeout(link.timeout);
      link.state = "open";
      this.cooldown.delete(peerId);
      this.options.onState(peerId, "open");
    };
    channel.onclose = () => this.close(peerId, false);
    channel.onmessage = (event) => {
      if (typeof event.data !== "string" || event.data.length > MAX_FRAME_BYTES) return;
      try {
        const frame = JSON.parse(event.data) as LinkFrame;
        if (frame?.t === "env") this.options.onFrame(peerId, frame);
      } catch {
        /* ignore malformed frames */
      }
    };
    return link;
  }

  private fail(peerId: string): void {
    if (!this.links.has(peerId)) return;
    this.cooldown.set(peerId, Date.now() + RETRY_COOLDOWN_MS);
    this.close(peerId);
  }
}
