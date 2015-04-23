import xdrlib

class XDREnum(object):
    __slots__ = ['name', 'value']

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __int__(self):
        return self.value

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __cmp__(x, y):
        return cmp(int(x), int(y))

    def __hash__(self):
        return hash(int(self))

    @classmethod
    def unpack_from(cls, reader):
        value = reader.unpack_int()
        return cls.members[value]

    @classmethod
    def pack_into(cls, packer, value):
        packer.pack_int(value)

class XDRStruct(object):
    __slots__ = []

    def pack(self):
        packer = xdrlib.Packer()
        self.pack_into(packer, self)
        return packer.get_buffer()

    @classmethod
    def unpack(cls, data):
        return cls.unpack_from(xdrlib.Unpacker(data))

    def __str__(self):
        return repr(self)

    def __ne__(self, other):
        return not self == other

class XDRUnion(object):
    @classmethod
    def unpack(cls, data):
        return cls.unpack_from(xdrlib.Unpacker(data))

    @classmethod
    def pack_into(cls, packer, obj):
        type(obj).pack_into(packer, obj)

class XDRUnionMember(object):
    __slots__ = ["value"]

    def __init__(self, value=None):
        self.value = value

    def pack(self):
        packer = xdrlib.Packer()
        self.pack_into(packer, self)
        return packer.get_buffer()

    def __repr__(self):
        return type(self).__name__ + '(' + repr(self.value) + ')'

    def __str__(self):
        return repr(self)

    def __eq__(self, other):
        return type(self) == type(other) and self.value == other.value

    def __ne__(self, other):
        return not self == other

class XDRTypedef(object):
    __slots__ = []

    @classmethod
    def unpack(cls, data):
        return cls.unpack_from(xdrlib.Unpacker(data))

class l2_key(XDRStruct):
    __slots__ = ['vlan', 'mac_hi', 'mac_lo']

    def __init__(self, vlan=None, mac_hi=None, mac_lo=None):
        self.vlan = vlan
        self.mac_hi = mac_hi
        self.mac_lo = mac_lo

    @classmethod
    def pack_into(self, packer, obj):
        packer.pack_uint(obj.vlan)
        packer.pack_uint(obj.mac_hi)
        packer.pack_uint(obj.mac_lo)

    @classmethod
    def unpack_from(cls, unpacker):
        obj = l2_key()
        obj.vlan = unpacker.unpack_uint()
        obj.mac_hi = unpacker.unpack_uint()
        obj.mac_lo = unpacker.unpack_uint()
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.vlan != other.vlan:
            return False
        if self.mac_hi != other.mac_hi:
            return False
        if self.mac_lo != other.mac_lo:
            return False
        return True

    def __repr__(self):
        parts = []
        parts.append('l2_key(')
        parts.append('vlan=')
        parts.append(repr(self.vlan))
        parts.append(", ")
        parts.append('mac_hi=')
        parts.append(repr(self.mac_hi))
        parts.append(", ")
        parts.append('mac_lo=')
        parts.append(repr(self.mac_lo))
        parts.append(')')
        return ''.join(parts)

class l2_value(XDRStruct):
    __slots__ = ['port']

    def __init__(self, port=None):
        self.port = port

    @classmethod
    def pack_into(self, packer, obj):
        packer.pack_uint(obj.port)

    @classmethod
    def unpack_from(cls, unpacker):
        obj = l2_value()
        obj.port = unpacker.unpack_uint()
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.port != other.port:
            return False
        return True

    def __repr__(self):
        parts = []
        parts.append('l2_value(')
        parts.append('port=')
        parts.append(repr(self.port))
        parts.append(')')
        return ''.join(parts)

class vlan_key(XDRStruct):
    __slots__ = ['vlan']

    def __init__(self, vlan=None):
        self.vlan = vlan

    @classmethod
    def pack_into(self, packer, obj):
        packer.pack_uint(obj.vlan)

    @classmethod
    def unpack_from(cls, unpacker):
        obj = vlan_key()
        obj.vlan = unpacker.unpack_uint()
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.vlan != other.vlan:
            return False
        return True

    def __repr__(self):
        parts = []
        parts.append('vlan_key(')
        parts.append('vlan=')
        parts.append(repr(self.vlan))
        parts.append(')')
        return ''.join(parts)

class vlan_value(XDRStruct):
    __slots__ = ['port_bitmap']

    def __init__(self, port_bitmap=None):
        self.port_bitmap = port_bitmap

    @classmethod
    def pack_into(self, packer, obj):
        packer.pack_uint(obj.port_bitmap)

    @classmethod
    def unpack_from(cls, unpacker):
        obj = vlan_value()
        obj.port_bitmap = unpacker.unpack_uint()
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.port_bitmap != other.port_bitmap:
            return False
        return True

    def __repr__(self):
        parts = []
        parts.append('vlan_value(')
        parts.append('port_bitmap=')
        parts.append(repr(self.port_bitmap))
        parts.append(')')
        return ''.join(parts)

__all__ = ['l2_key', 'l2_value', 'vlan_key', 'vlan_value']