package virtualwebauthn

type Transport int

const (
	TransportUSB Transport = iota
	TransportNFC
	TransportBLE
	TransportSmartCard
	TransportHybrid
	TransportInternal
)

var transportNames = map[Transport]string{
	TransportUSB:       "usb",
	TransportNFC:       "nfc",
	TransportBLE:       "ble",
	TransportSmartCard: "smart-card",
	TransportHybrid:    "hybrid",
	TransportInternal:  "internal",
}
