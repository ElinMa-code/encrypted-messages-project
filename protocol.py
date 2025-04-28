from enum import Enum

def compose_packet(packet_type, data):
    return f"{packet_type.value}:{data}"

class PacketType(Enum):
    REGISTRATION = "REG"
    MESSAGE = "MSG"
    CONFIRMATION = "CNF"
