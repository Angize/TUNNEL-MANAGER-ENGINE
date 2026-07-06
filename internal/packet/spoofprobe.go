package packet

// SpoofProbe reports whether this host can run IP spoofing for the raw bip transport.
// It is a LOCAL capability check only (the raw sockets can be opened); it does NOT
// prove the upstream network will actually forward a forged source — a datacenter may
// still drop spoofed egress (anti-spoofing / BCP38), which only shows up once a real
// tunnel fails to establish.
type SpoofProbe struct {
	OK        bool   `json:"ok"`          // CapNetRaw && AFPacket
	CapNetRaw bool   `json:"cap_net_raw"` // can open an IP_HDRINCL raw socket (forge headers)
	AFPacket  bool   `json:"af_packet"`   // can open an AF_PACKET socket (receive decoy dst)
	Reason    string `json:"reason"`      // why OK is false (empty when OK)
}
