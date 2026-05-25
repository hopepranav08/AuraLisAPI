This skill calculates memory offsets for TLS interception.

Tools:
nm
objdump
readelf

Targets:
SSL_read
SSL_write
crypto/tls.(*Conn).Read
crypto/tls.(*Conn).Write

Usage:
When an agent needs to hook encrypted traffic, run the Python script to calculate offsets.