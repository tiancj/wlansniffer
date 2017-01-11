# -*- coding: utf-8 -*-
"""Radiotap"""

import dpkt
import socket
from . import ieee80211
from .decorators import deprecated
import struct

# Ref: http://www.radiotap.org
# Fields Ref: http://www.radiotap.org/fields/defined


def BIT(nr):
    return 1 << nr


# Present flags
# TSFT
# Bit Number: 0
# Structure: u64 mactime
# Required Alignment: 8
# Unit: microseconds
# Value in microseconds of the MAC’s 64-bit 802.11 Time Synchronization Function timer
# when the first bit of the MPDU arrived at the MAC. For received frames only.
_TSFT_MASK = BIT(0)

# Flags
# Bit Number: 1
# Structure: u8 flags
# Unit: bitmap
# Properties of transmitted and received frames.
#
# Currently, the following flags are defined:
#
# Mask	Meaning
# 0x01	sent/received during CFP
# 0x02	sent/received with short preamble
# 0x04	sent/received with WEP encryption
# 0x08	sent/received with fragmentation
# 0x10	frame includes FCS
# 0x20	frame has padding between 802.11 header and payload (to 32-bit boundary)
# 0x40	frame failed FCS check
# Currently unspecified but used:
#
# Mask	Meaning
# 0x80	frame used short guard interval (HT)
_FLAGS_MASK = BIT(1)

# Rate
# Bit Number: 2
# Structure: u8
# Unit: 500 Kbps
# TX/RX data rate.
_RATE_MASK = BIT(2)

# Channel
# Bit Number: 3
# Structure: u16 frequency, u16 flags
# Required Alignment: 2
# Units: MHz, bitmap
# Tx/Rx frequency in MHz, followed by flags.
#
# Currently, the following flags are defined:
#
# Mask	Meaning
# 0x0010	Turbo Channel
# 0x0020	CCK channel
# 0x0040	OFDM channel
# 0x0080	2 GHz spectrum channel
# 0x0100	5 GHz spectrum channel
# 0x0200	Only passive scan allowed
# 0x0400	Dynamic CCK-OFDM channel
# 0x0800	GFSK channel (FHSS PHY)
_CHANNEL_MASK = BIT(3)

# FHSS
# Bit Number: 4
# Structure: u8 hop set, u8 hop pattern
# Units: ??
# The hop set and pattern for frequency-hopping radios.
_FHSS_MASK = BIT(4)

# Antenna signal
# Bit Number: 5
# Structure: s8
# Unit: dBm
_ANT_SIG_MASK = BIT(5)

# Antenna noise
# Bit Number: 6
# Structure: s8
# Unit: dBm
_ANT_NOISE_MASK = BIT(6)

# Lock quality
# Bit Number: 7
# Structure: u16
# Required Alignment: 2
# Unit: unitless
# Quality of Barker code lock. Unitless. Monotonically nondecreasing with “better” lock strength.
# Called “Signal Quality” in datasheets. (Is there a standard way to measure this?)
_LOCK_QUAL_MASK = BIT(7)

# TX attenuation
# Bit Number: 8
# Structure: u16
# Required Alignment: 2
# Unit: unitless
# Transmit power expressed as unitless distance from max power set at factory calibration.
# 0 is max power. Monotonically nondecreasing with lower power levels.
_TX_ATTN_MASK = BIT(8)

# dB TX attenuation
# Bit Number: 9
# Structure: u16
# Required Alignment: 2
# Unit: dB
# Transmit power expressed as decibel distance from max power set at factory calibration.
# 0 is max power. Monotonically nondecreasing with lower power levels.
_DB_TX_ATTN_MASK = BIT(9)

# dBm TX power
# Bit Number: 10
# Structure: s8
# Required Alignment: 1
# Unit: dBm
# Transmit power expressed as dBm (decibels from a 1 milliwatt reference).
# This is the absolute power level measured at the antenna port.
_DBM_TX_POWER_MASK = BIT(10)

# Antenna
# Bit Number: 11
# Structure: u8
# Unit: antenna index
_ANTENNA_MASK = BIT(11)

# dB antenna signal
# Bit Number: 12
# Structure: u8
# Unit: dB
# RF signal power at the antenna, decibel difference from an arbitrary, fixed reference.
# This field contains a single unsigned 8-bit value.
_DB_ANT_SIG_MASK = BIT(12)

# dB antenna noise
# Bit Number: 13
# Structure: u8
# Unit: dB
# RF noise power at the antenna, decibel difference from an arbitrary, fixed reference.
# This field contains a single unsigned 8-bit value.
_DB_ANT_NOISE_MASK = BIT(13)

# RX flags
# Bit Number: 14
# Structure: u16
# Required Alignment: 2
# Unit: bitmap
# Properties of received frames.
#
# The following flags are currently defined:
#
# mask	meaning
# 0x0001	reserved (was FCS failed but this is a regular flag)
# 0x0002	PLCP CRC check failed
# 0xfffc	reserved for future expansion
# Notes
# This field originates from NetBSD and is also used like this in Linux.
#
# Use bit 0x40 in the flags field to indicate FCS CRC failed.
_RX_FLAGS_MASK = BIT(14)

# hardware queue
# Bit Number: 15
# Structure: u8 queue
# Required Alignment: 1
# Hardware queue to send the frame on.
#
# Discussion
# Only used in OpenBSD, clashes with ../TX flags_ used by others.
_HARDWARE_QUEUE_MASK = BIT(15)

# RSSI
# Bit Number: 16
# Structure: u8 rssi, u8 max_rssi
# Required Alignment: 1
# This field indicates the received signal strength and the maximum for the hardware.
#
# Discussion
# Used by OpenBSD only. Clashes with ../RTS retries_.
_RSSI_MASK = BIT(16)

# data retries
# Bit Number: 17
# Structure: u8 retries
# Unit: unitless number
# Number of data retries a transmitted frame used.
_DATA_RETRIES_MASK = BIT(17)

# XChannel
# Bit Number: 18
# Structure: u32 flags, u16 freq, u8 channel, u8 maxpower
# Required Alignment: 4
# Unit(s): none, MHz, 802.11 channel number, unknown
# Extended channel information. The flags part of the field contains various flags:
#
# flag	definition
# 0x00000010	Channel Type Turbo
# 0x00000020	Channel Type Complementary Code Keying (CCK) Modulation
# 0x00000040	Channel Type Orthogonal Frequency-Division Multiplexing (OFDM)
# 0x00000080	Channel Type 2 GHz spectrum
# 0x00000100	Channel Type 5 GHz spectrum
# 0x00000200	Channel Type Passive
# 0x00000400	Channel Type Dynamic CCK-OFDM Channel
# 0x00000800	Channel Type Gaussian Frequency Shift Keying (GFSK) Modulation
# 0x00001000	Channel Type GSM
# 0x00002000	Channel Type Status Turbo
# 0x00004000	Channel Type Half Rate
# 0x00008000	Channel Type Quarter Rate
# 0x00010000	Channel Type HT/20
# 0x00020000	Channel Type HT/40+
# 0x00040000	Channel Type HT/40-
# Discussion
# This field is parsed by wireshark, but only partially (it ignores maxpower).
# Origin of the field is unknown. Used by FreeBSD and OS X.
#
# Channel numbers are problematic – using the channel’s center frequency would be much better.
#
# The flags define some things that can be inferred (2 vs. 5 GHz).
#
# Things like the “Channel Type Passive” don’t make sense per packet. As used, this field conflates
# channel properties (which need not be stored per packet but are more or less fixed) with packet
# properties (like the modulation).
_CHANNELPLUS_MASK = BIT(18)

# MCS
# Bit Number: 19
# Structure: u8 known, u8 flags, u8 mcs
# Required Alignment: 1
# The mcs field indicates the MCS rate index as in IEEE_802.11n-2009
#
# The known field indicates which information is known:
#
# flag	definition
# 0x01	bandwidth
# 0x02	MCS index known (in mcs part of the field)
# 0x04	guard interval
# 0x08	HT format
# 0x10	FEC type
# 0x20	STBC known
# 0x40	Ness known (Number of extension spatial streams)
# 0x80	Ness data - bit 1 (MSB) of Number of extension spatial streams
# The flags field is any combination of the following:
#
# flag	definition
# 0x03	bandwidth - 0: 20, 1: 40, 2: 20L, 3: 20U
# 0x04	guard interval - 0: long GI, 1: short GI
# 0x08	HT format - 0: mixed, 1: greenfield
# 0x10	FEC type - 0: BCC, 1: LDPC
# 0x60	Number of STBC streams
# 0x80	Ness - bit 0 (LSB) of Number of extension spatial streams
#
# A-MPDU status
# Bit: Number 20
# Structure: u32 reference number, u16 flags, u8 delimiter CRC value, u8 reserved
# Required Alignment: 4 bytes
_MCS_MASK = BIT(19)

# A-MPDU status
# Bit Number: 20
# Structure: u32 reference number, u16 flags, u8 delimiter CRC value, u8 reserved
# Required Alignment: 4 bytes
# The presence of this field indicates that the frame was received as part of an a-MPDU.
_AMDPU_STAUS_MASK = BIT(20)

# extended flags
# Bit Number: 22 (not assigned yet)
# Structure: u32 flags
# Required Alignment: 4
# Unit(s): n/a
# This field defines decryption flags for frames. The following flags are defined:
#
# value	meaning
# 0x00000001	frame is decrypted (but FC protected bit is set)
# 0x00000002	frame is encrypted (FC protected bit is also set)
# 0x00000004	(ext) IV is still present (reserved if 0x1 isn’t set)
# 0x00000008	MIC is not present (should only be used if FCS is also not present, reserved if 0x1 isn’t set)
# 0xfffffff0	(reserved)
_EXTENDED_FLAGS_MASK = BIT(22)


_EXT_MASK = BIT(31)

_TSFT_SHIFT = 0
_FLAGS_SHIFT = 1
_RATE_SHIFT = 2
_CHANNEL_SHIFT = 3
_FHSS_SHIFT = 4
_ANT_SIG_SHIFT = 5
_ANT_NOISE_SHIFT = 6
_LOCK_QUAL_SHIFT = 7
_TX_ATTN_SHIFT = 8
_DB_TX_ATTN_SHIFT = 9
_DBM_TX_POWER_SHIFT = 10
_ANTENNA_SHIFT = 11
_DB_ANT_SIG_SHIFT = 12
_DB_ANT_NOISE_SHIFT = 13
_RX_FLAGS_SHIFT = 14
_CHANNELPLUS_SHIFT = 18
_EXT_SHIFT = 31

# Flags elements
_CFP_FLAG_SHIFT = 0
_PREAMBLE_SHIFT = 1
_WEP_SHIFT = 2
_FRAG_SHIFT = 3
_DATA_PAD_SHIFT = 5
_BAD_FCS_SHIFT = 6
_SHORT_GI_SHIFT = 7

# Channel type
_CHAN_TYPE_SIZE = 4
_CHANNEL_TYPE_SHIFT = 4
_CCK_SHIFT = 5
_OFDM_SHIFT = 6
_TWO_GHZ_SHIFT = 7
_FIVE_GHZ_SHIFT = 8
_PASSIVE_SHIFT = 9
_DYN_CCK_OFDM_SHIFT = 10
_GFSK_SHIFT = 11
_GSM_SHIFT = 12
_STATIC_TURBO_SHIFT = 13
_HALF_RATE_SHIFT = 14
_QUARTER_RATE_SHIFT = 15

# Flags offsets and masks
_FCS_SHIFT = 4
_FCS_MASK = 0x10


class Radiotap(dpkt.Packet):
    __hdr__ = (
        ('version', 'B', 0),
        ('pad', 'B', 0),
        ('length', 'H', 0),
        ('present_flags', 'I', 0)
    )
    __byte_order__ = '<'    # little endian

    @property
    def tsft_present(self):
        return (self.present_flags & _TSFT_MASK) >> _TSFT_SHIFT

    @tsft_present.setter
    def tsft_present(self, val):
        self.present_flags |= val << _TSFT_SHIFT

    @property
    def flags_present(self):
        return (self.present_flags & _FLAGS_MASK) >> _FLAGS_SHIFT

    @flags_present.setter
    def flags_present(self, val):
        self.present_flags |= val << _FLAGS_SHIFT

    @property
    def rate_present(self):
        return (self.present_flags & _RATE_MASK) >> _RATE_SHIFT

    @rate_present.setter
    def rate_present(self, val):
        self.present_flags |= val << _RATE_SHIFT

    @property
    def channel_present(self):
        return (self.present_flags & _CHANNEL_MASK) >> _CHANNEL_SHIFT

    @channel_present.setter
    def channel_present(self, val):
        self.present_flags |= val << _CHANNEL_SHIFT

    @property
    def fhss_present(self):
        return (self.present_flags & _FHSS_MASK) >> _FHSS_SHIFT

    @fhss_present.setter
    def fhss_present(self, val):
        self.present_flags |= val << _FHSS_SHIFT

    @property
    def ant_sig_present(self):
        return (self.present_flags & _ANT_SIG_MASK) >> _ANT_SIG_SHIFT

    @ant_sig_present.setter
    def ant_sig_present(self, val):
        self.present_flags |= val << _ANT_SIG_SHIFT

    @property
    def ant_noise_present(self):
        return (self.present_flags & _ANT_NOISE_MASK) >> _ANT_NOISE_SHIFT

    @ant_noise_present.setter
    def ant_noise_present(self, val):
        self.present_flags |= val << _ANT_NOISE_SHIFT

    @property
    def lock_qual_present(self):
        return (self.present_flags & _LOCK_QUAL_MASK) >> _LOCK_QUAL_SHIFT

    @lock_qual_present.setter
    def lock_qual_present(self, val):
        self.present_flags |= val << _LOCK_QUAL_SHIFT

    @property
    def tx_attn_present(self):
        return (self.present_flags & _TX_ATTN_MASK) >> _TX_ATTN_SHIFT

    @tx_attn_present.setter
    def tx_attn_present(self, val):
        self.present_flags |= val << _TX_ATTN_SHIFT

    @property
    def db_tx_attn_present(self):
        return (self.present_flags & _DB_TX_ATTN_MASK) >> _DB_TX_ATTN_SHIFT

    @db_tx_attn_present.setter
    def db_tx_attn_present(self, val):
        self.present_flags |= val << _DB_TX_ATTN_SHIFT

    @property
    def dbm_tx_power_present(self):
        return (self.present_flags & _DBM_TX_POWER_MASK) >> _DBM_TX_POWER_SHIFT

    @dbm_tx_power_present.setter
    def dbm_tx_power_present(self, val):
        self.present_flags |= val << _DBM_TX_POWER_SHIFT

    @property
    def ant_present(self):
        return (self.present_flags & _ANTENNA_MASK) >> _ANTENNA_SHIFT

    @ant_present.setter
    def ant_present(self, val):
        self.present_flags |= val << _ANTENNA_SHIFT

    @property
    def db_ant_sig_present(self):
        return (self.present_flags & _DB_ANT_SIG_MASK) >> _DB_ANT_SIG_SHIFT

    @db_ant_sig_present.setter
    def db_ant_sig_present(self, val):
        self.present_flags |= val << _DB_ANT_SIG_SHIFT

    @property
    def db_ant_noise_present(self):
        return (self.present_flags & _DB_ANT_NOISE_MASK) >> _DB_ANT_NOISE_SHIFT

    @db_ant_noise_present.setter
    def db_ant_noise_present(self, val):
        self.present_flags |= val << _DB_ANT_NOISE_SHIFT

    @property
    def rx_flags_present(self):
        return (self.present_flags & _RX_FLAGS_MASK) >> _RX_FLAGS_SHIFT

    @rx_flags_present.setter
    def rx_flags_present(self, val):
        self.present_flags |= val << _RX_FLAGS_SHIFT

    @property
    def chanplus_present(self):
        return (self.present_flags & _CHANNELPLUS_MASK) >> _CHANNELPLUS_SHIFT

    @chanplus_present.setter
    def chanplus_present(self, val):
        self.present_flags |= val << _CHANNELPLUS_SHIFT

    @property
    def ext_present(self):
        return (self.present_flags & _EXT_MASK) >> _EXT_SHIFT

    @ext_present.setter
    def ext_present(self, val):
        self.present_flags |= val << _EXT_SHIFT

    # Deprecated methods, will be removed in the future
    # =================================================
    @deprecated('tsft_present')
    def _get_tsft_present(self):
        return self.tsft_present

    @deprecated('tsft_present')
    def _set_tsft_present(self, val):
        self.tsft_present = val

    @deprecated('flags_present')
    def _get_flags_present(self):
        return self.flags_present

    @deprecated('flags_present')
    def _set_flags_present(self, val):
        self.flags_present = val

    @deprecated('rate_present')
    def _get_rate_present(self):
        return self.rate_present

    @deprecated('rate_present')
    def _set_rate_present(self, val):
        self.rate_present = val

    @deprecated('channel_present')
    def _get_channel_present(self):
        return self.channel_present

    @deprecated('channel_present')
    def _set_channel_present(self, val):
        self.channel_present = val

    @deprecated('fhss_present')
    def _get_fhss_present(self):
        return self.fhss_present

    @deprecated('fhss_present')
    def _set_fhss_present(self, val):
        self.fhss_present = val

    @deprecated('ant_sig_present')
    def _get_ant_sig_present(self):
        return self.ant_sig_present

    @deprecated('ant_sig_present')
    def _set_ant_sig_present(self, val):
        self.ant_sig_present = val

    @deprecated('ant_noise_present')
    def _get_ant_noise_present(self):
        return self.ant_noise_present

    @deprecated('ant_noise_present')
    def _set_ant_noise_present(self, val):
        self.ant_noise_present = val

    @deprecated('lock_qual_present')
    def _get_lock_qual_present(self):
        return self.lock_qual_present

    @deprecated('lock_qual_present')
    def _set_lock_qual_present(self, val):
        self.lock_qual_present = val

    @deprecated('tx_attn_present')
    def _get_tx_attn_present(self):
        return self.tx_attn_present

    @deprecated('tx_attn_present')
    def _set_tx_attn_present(self, val):
        self.tx_attn_present = val

    @deprecated('db_tx_attn_present')
    def _get_db_tx_attn_present(self):
        return self.db_tx_attn_present

    @deprecated('db_tx_attn_present')
    def _set_db_tx_attn_present(self, val):
        self.db_tx_attn_present = val

    @deprecated('dbm_tx_power_present')
    def _get_dbm_power_present(self):
        return self.dbm_tx_power_present

    @deprecated('dbm_tx_power_present')
    def _set_dbm_power_present(self, val):
        self.dbm_tx_power_present = val

    @deprecated('ant_present')
    def _get_ant_present(self):
        return self.ant_present

    @deprecated('ant_present')
    def _set_ant_present(self, val):
        self.ant_present = val

    @deprecated('db_ant_sig_present')
    def _get_db_ant_sig_present(self):
        return self.db_ant_sig_present

    @deprecated('db_ant_sig_present')
    def _set_db_ant_sig_present(self, val):
        self.db_ant_sig_present = val

    @deprecated('db_ant_noise_present')
    def _get_db_ant_noise_present(self):
        return self.db_ant_noise_present

    @deprecated('db_ant_noise_present')
    def _set_db_ant_noise_present(self, val):
        self.db_ant_noise_present = val

    @deprecated('rx_flags_present')
    def _get_rx_flags_present(self):
        return self.rx_flags_present

    @deprecated('rx_flags_present')
    def _set_rx_flags_present(self, val):
        self.rx_flags_present = val

    @deprecated('chanplus_present')
    def _get_chanplus_present(self):
        return self.chanplus_present

    @deprecated('chanplus_present')
    def _set_chanplus_present(self, val):
        self.chanplus_present = val

    @deprecated('ext_present')
    def _get_ext_present(self):
        return self.ext_present

    @deprecated('ext_present')
    def _set_ext_present(self, val):
        self.ext_present = val
    # =================================================

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        it_present = self.present_flags
        n_it_present = 0
        pos = self.__hdr_len__ # pointer to radiotap body
        while it_present & _EXT_MASK:
            n_it_present += 1
            it_present = struct.unpack('<I', buf[pos+(n_it_present-1)*4 : pos+n_it_present*4])[0]
            self.present_flags |= it_present << (n_it_present*8)
        self.data = buf[self.length:]

        self.fields = []
        buf = buf[self.__hdr_len__ + n_it_present*4:]

        # decode each field into self.<name> (eg. self.tsft) as well as append it self.fields list
        field_decoder = [
            ('tsft', self.tsft_present, self.TSFT),
            ('flags', self.flags_present, self.Flags),
            ('rate', self.rate_present, self.Rate),
            ('channel', self.channel_present, self.Channel),
            ('fhss', self.fhss_present, self.FHSS),
            ('ant_sig', self.ant_sig_present, self.AntennaSignal),
            ('ant_noise', self.ant_noise_present, self.AntennaNoise),
            ('lock_qual', self.lock_qual_present, self.LockQuality),
            ('tx_attn', self.tx_attn_present, self.TxAttenuation),
            ('db_tx_attn', self.db_tx_attn_present, self.DbTxAttenuation),
            ('dbm_tx_power', self.dbm_tx_power_present, self.DbmTxPower),
            ('ant', self.ant_present, self.Antenna),
            ('db_ant_sig', self.db_ant_sig_present, self.DbAntennaSignal),
            ('db_ant_noise', self.db_ant_noise_present, self.DbAntennaNoise),
            ('rx_flags', self.rx_flags_present, self.RxFlags)
        ]
        for name, present_bit, parser in field_decoder:
            if present_bit:
                field = parser(buf)
                field.data = ''
                setattr(self, name, field)
                self.fields.append(field)
                buf = buf[len(field):]

        if len(self.data) > 0:
            if self.flags_present and self.flags.fcs:
                self.data = ieee80211.IEEE80211(self.data, fcs=self.flags.fcs)
            else:
                self.data = ieee80211.IEEE80211(self.data)

    class Antenna(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('index', 'B', 0),
        )

    class AntennaNoise(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('db', 'B', 0),
        )

    class AntennaSignal(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('db', 'B', 0),
        )

    class Channel(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('freq', 'H', 0),
            ('flags', 'H', 0),
        )

    class FHSS(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('set', 'B', 0),
            ('pattern', 'B', 0),
        )

    class Flags(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('val', 'B', 0),
        )

        @property
        def fcs(self): return (self.val & _FCS_MASK) >> _FCS_SHIFT

        # TODO statement seems to have no effect
        @fcs.setter
        def fcs(self, v): (v << _FCS_SHIFT) | (self.val & ~_FCS_MASK)

        # Deprecated methods, will be removed in the future
        # =================================================
        @deprecated('fcs')
        def _get_fcs_present(self): return self.fcs

        @deprecated('fcs')
        def _set_fcs_present(self, v): self.fcs = v
        # =================================================

    class LockQuality(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('val', 'H', 0),
        )

    class RxFlags(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('val', 'H', 0),
        )

    class Rate(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('val', 'B', 0),
        )

    class TSFT(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('usecs', 'Q', 0),
        )

    class TxAttenuation(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('val', 'H', 0),
        )

    class DbTxAttenuation(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('db', 'H', 0),
        )

    class DbAntennaNoise(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbAntennaSignal(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbmTxPower(dpkt.Packet):
        __byte_order__ = '<'  # little endian
        __hdr__ = (
            ('dbm', 'B', 0),
        )


def test_Radiotap():
    s = b'\x00\x00\x00\x18\x6e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xa8\x81\x02\x00\x00\x00\x00\x00\x00\x00'
    rad = Radiotap(s)
    assert(rad.version == 0)
    assert(rad.present_flags == 0x0000486e)
    assert(rad.tsft_present == 0)
    assert(rad.flags_present == 1)
    assert(rad.rate_present == 1)
    assert(rad.channel_present == 1)
    assert(rad.fhss_present == 0)
    assert(rad.ant_sig_present == 1)
    assert(rad.ant_noise_present == 1)
    assert(rad.lock_qual_present == 0)
    assert(rad.db_tx_attn_present == 0)
    assert(rad.dbm_tx_power_present == 0)
    assert(rad.ant_present == 1)
    assert(rad.db_ant_sig_present == 0)
    assert(rad.db_ant_noise_present == 0)
    assert(rad.rx_flags_present == 1)
    assert(rad.channel.freq == 0x6c09)
    assert(rad.channel.flags == 0xa000)
    assert(len(rad.fields) == 7)


def test_fcs():
    s = b'\x00\x00\x1a\x00\x2f\x48\x00\x00\x34\x8f\x71\x09\x00\x00\x00\x00\x10\x0c\x85\x09\xc0\x00\xcc\x01\x00\x00'
    rt = Radiotap(s)
    assert(rt.flags_present == 1)
    assert(rt.flags.fcs == 1)


if __name__ == '__main__':
    test_Radiotap()
    test_fcs()
    print('Tests Successful...')