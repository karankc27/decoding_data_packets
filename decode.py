import struct


class DecodedData:
    def __init__(self, short1, char12, byte1, char8, short2, char15, long1):
        self.short1 = short1
        self.char12 = char12
        self.byte1 = byte1
        self.char8 = char8
        self.short2 = short2
        self.char15 = char15
        self.long1 = long1


def decode_packet(packet):
    format_string = ">h12sb8sh15sl"
    unpacked_data = struct.unpack(format_string, packet)
    char_decoder = lambda char_bytes: char_bytes.decode('utf-8').rstrip('\x00')
    decoded_data = DecodedData(*unpacked_data)
    decoded_data.char12 = char_decoder(decoded_data.char12)
    decoded_data.char8 = char_decoder(decoded_data.char8)
    decoded_data.char15 = char_decoder(decoded_data.char15)
    return decoded_data


# Sample packet
packet = b"\x04\xD2\x6B\x65\x65\x70\x64\x65\x63\x6F\x64\x69\x6E\x67\x38\x64\x6F\x6E\x74\x73\x74\x6F\x70\x03\x15\x63\x6F\x6E\x67\x72\x61\x74\x75\x6C\x61\x74\x69\x6F\x6E\x73\x07\x5B\xCD\x15"

decoded = decode_packet(packet)
print(
    f"Decoded struct: {{{decoded.short1}, \"{decoded.char12}\", {decoded.byte1}, \"{decoded.char8}\", {decoded.short2}, \"{decoded.char15}\", , {decoded.long1}}}")
