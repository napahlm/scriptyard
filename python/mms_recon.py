#!/usr/bin/env python3
"""mms_recon.py - read-only MMS / IEC 61850 reconnaissance.

A single-file, standard-library-only reconnaissance tool for MMS (ISO 9506)
servers, aimed at IEC 61850 devices. Everything it sends is a well-formed,
read-only request. It sends no malformed PDUs, performs no writes, and issues
no control commands.

WHAT IT ADDS OVER A SERVICE-BITMAP STACK DETECTOR

A detector answers "which stack is this?" from the Initiate response's service
bitmap. That is useful and this tool does it too, but the bitmap is only the
first few hundred bytes of what a server will tell you for free.

  1. Decodes the ENTIRE negotiated parameter set, not just the bitmap: maximum
     PDU size, outstanding-service limits, data-structure nesting level and the
     ParameterSupportOptions feature bits. These are the hard constraints any
     later testing has to work inside, and no detector reports them.
  2. Sends GetCapabilityList. IEC 61850-8-1 never uses this service, so the
     strings it returns are implementation-chosen and often say more about the
     implementation than Identify does. Rarely implemented, so its mere
     presence is a strong discriminator.
  3. Sends GetDomainAttributes for structural information that is not
     reachable any other way.
  4. Reads the IEC 61850 nameplate (LPHD PhyNam, LLN0 NamPlt) for a version
     string taken from the data model rather than from Identify. The Identify
     revision field is set by the application and is frequently stale or
     hand-written; the nameplate is an independent second source.
  5. Hunts non-IEC-61850 objects by enumerating every MMS object class at both
     VMD and domain scope, and ranks what it finds by confidence rather than
     emitting one undifferentiated list.
  6. Probes data-model shape through GetVariableAccessAttributes, so you learn
     whether arrays and deep structures exist before investing in anything
     that depends on them.
  7. Tests both full-OSI and reduced-OSI framing. A server answering both has
     two independent parse paths, and the non-default one usually sees less
     testing.
  8. Writes a machine-readable evidence file, including raw hex for every
     response, so results are reviewable and diffable rather than scrollback.

CORRECTNESS NOTES, because these are the things such tools usually get wrong

  - BER tags are decoded in both low- and high-tag-number form. Every MMS file
    service is numbered above 30 and therefore uses the multi-byte form; a
    parser that assumes one tag byte desynchronises on all of them.
  - The MMS PDU is reached by descending the TPKT, COTP, ISO 8327 session,
    ISO 8823 presentation and ACSE layers. It is not located by scanning for a
    tag byte, which collides with length and content octets.
  - GetNameList's moreFollows is BOOLEAN DEFAULT TRUE, so its ABSENCE means
    more data follows. Treating absence as "done" silently truncates
    enumeration and turns a partial result into an apparent clean negative.
    FileDirectory's moreFollows is DEFAULT FALSE. The two are opposites.
  - MMS FileName is SEQUENCE OF GraphicString (universal 25), not
    VisibleString (universal 26). Scanning for the wrong tag finds no files.
  - Structure nesting depth is computed by recursive descent through the
    TypeDescription, honouring the explicit wrapper that TypeSpecification
    requires. Counting constructed tag bytes over-reports depth badly.

SAFETY

The default mode is read-only and conformant, and needs no confirmation flag.
Two things are nevertheless true of this tool and worth stating.

  - Reads of IEC 61850 control attributes ($SBO, $SBOw, $Oper, $Cancel) are
    refused in every automatic sweep. Reading $SBO performs a SELECT, which
    reserves apparatus control, and doing that across a data model would take
    a bay away from its operator. The refusal lives inside the read helper,
    not at its call sites, so a later change cannot route around it. ctlModel
    is read at FC=CF instead, which is configuration and tells you the same
    thing.
  - Associations are opened one at a time against a budget, and every one is
    closed with a proper Conclude so the server frees the slot rather than
    waiting out an idle timer.

--lab unlocks probes that are different in kind: each either holds a resource
the device needs, or deliberately deviates from the protocol to see how the
implementation reacts. They are selected individually with --probes, never as
a group, so nothing runs because of a typo. --list-probes describes them.

--dry-run prints every request it would send, in hex, and opens no socket.

Usage:
  mms_recon.py 192.0.2.10
  mms_recon.py 192.0.2.10 --deep --json out/recon.json
  mms_recon.py 192.0.2.10 --advisories advisories.json
  mms_recon.py 192.0.2.10 --lab --probes services,ctxid
  mms_recon.py --list-probes
  mms_recon.py 192.0.2.10 --dry-run

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import sys
import time
from pathlib import Path

__version__ = "1.0.0"


# ===========================================================================
#  BER
# ===========================================================================

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

_CLASS_BITS = {UNIVERSAL: 0x00, APPLICATION: 0x40, CONTEXT: 0x80, PRIVATE: 0xC0}


class BerError(Exception):
    pass


class Tlv:
    """One decoded BER TLV."""

    __slots__ = ("cls", "constructed", "num", "value", "start", "end")

    def __init__(self, cls, constructed, num, value, start, end):
        self.cls = cls
        self.constructed = constructed
        self.num = num
        self.value = value
        self.start = start
        self.end = end

    def is_(self, cls, num):
        return self.cls == cls and self.num == num

    def __repr__(self):
        names = {UNIVERSAL: "univ", APPLICATION: "app", CONTEXT: "ctx",
                 PRIVATE: "priv"}
        return (f"<Tlv {names[self.cls]}:{self.num}"
                f"{' cons' if self.constructed else ''} len={len(self.value)}>")


def ber_tlvs(buf, pos=0, end=None, strict=False):
    """Yield Tlv objects from buf[pos:end].

    Handles high-tag-number form (tag & 0x1f == 0x1f), which every MMS service
    numbered above 30 uses. Rejects indefinite length: BER permits it, MMS does
    not use it, and silently mis-parsing it is worse than refusing.

    With strict=False a malformed tail ends iteration quietly, which is what
    you want when walking a response from an implementation you do not trust.
    With strict=True it raises.
    """
    if end is None:
        end = len(buf)
    while pos < end:
        if pos + 2 > end:
            if strict:
                raise BerError(f"truncated tag at {pos}")
            return
        first = buf[pos]
        cls = (first >> 6) & 0x03
        constructed = bool(first & 0x20)
        num = first & 0x1F
        p = pos + 1
        if num == 0x1F:
            num = 0
            while True:
                if p >= end:
                    if strict:
                        raise BerError("truncated high-tag-number form")
                    return
                b = buf[p]
                p += 1
                num = (num << 7) | (b & 0x7F)
                if not b & 0x80:
                    break
                if num > 0xFFFFFF:
                    if strict:
                        raise BerError("implausible tag number")
                    return
        if p >= end:
            if strict:
                raise BerError("truncated length")
            return
        b = buf[p]
        p += 1
        if b == 0x80:
            if strict:
                raise BerError("indefinite length not supported")
            return
        if b & 0x80:
            n = b & 0x7F
            if n > 4 or p + n > end:
                if strict:
                    raise BerError("bad long-form length")
                return
            length = int.from_bytes(buf[p:p + n], "big")
            p += n
        else:
            length = b
        if p + length > end:
            if strict:
                raise BerError(f"length {length} overruns buffer at {p}")
            return
        yield Tlv(cls, constructed, num, buf[p:p + length], pos, p + length)
        pos = p + length


def find_tlv(buf, cls, num):
    """First TLV in buf matching (cls, num), or None."""
    for t in ber_tlvs(buf):
        if t.is_(cls, num):
            return t
    return None


def first_tlv(buf):
    for t in ber_tlvs(buf):
        return t
    return None


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, n >> 8, n & 0xFF])
    return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def ber_tag_bytes(cls, constructed, num):
    first = _CLASS_BITS[cls] | (0x20 if constructed else 0x00)
    if num < 0x1F:
        return bytes([first | num])
    groups = []
    n = num
    while True:
        groups.append(n & 0x7F)
        n >>= 7
        if not n:
            break
    groups.reverse()
    out = bytearray([first | 0x1F])
    for i, g in enumerate(groups):
        out.append(g | (0x80 if i < len(groups) - 1 else 0x00))
    return bytes(out)


def tlv(cls, num, value, constructed=True):
    return ber_tag_bytes(cls, constructed, num) + ber_len(len(value)) + value


def ctx(num, value, constructed=True):
    return tlv(CONTEXT, num, value, constructed)


def univ(num, value, constructed=True):
    return tlv(UNIVERSAL, num, value, constructed)


def vis(s):
    """VisibleString, universal 26."""
    if isinstance(s, str):
        s = s.encode("ascii")
    return univ(26, s, constructed=False)


def uint(n):
    """Minimal-length UNSIGNED content, for implicitly-tagged unsigned fields.

    Do NOT use for a universal INTEGER: see int_content.
    """
    if n == 0:
        return b"\x00"
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    return bytes(reversed(out))


def int_content(n):
    """Minimal two's-complement content for a universal (SIGNED) INTEGER.

    A universal INTEGER is signed, so 128 encoded as the single octet 0x80 is
    -128, not 128. An invokeID of 128 therefore went on the wire as a
    negative integer, which a strict peer may reject and which makes every
    later correlation wrong. Values whose top bit is set need a 0x00 pad.
    """
    if n == 0:
        return b"\x00"
    if n < 0:
        raise ValueError("negative INTEGER content not needed here")
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x00)
    return bytes(reversed(out))


def bitstring_indices(value):
    """BER BIT STRING value -> (set bit indices, total bits).

    value[0] is the count of unused trailing bits.
    """
    if not value:
        return [], 0
    unused = value[0]
    data = value[1:]
    total = max(0, len(data) * 8 - unused)
    return [i for i in range(total) if data[i // 8] & (0x80 >> (i % 8))], total


# ===========================================================================
#  MMS constants
# ===========================================================================

# ISO 9506-2 ServiceSupportOptions. 85 defined flags, indices 0..84. The
# ConfirmedServiceRequest CHOICE uses the same numbering for indices 0..77,
# which is why these double as service tag numbers.
SERVICES = [
    "status", "getNameList", "identify", "rename", "read", "write",
    "getVariableAccessAttributes", "defineNamedVariable",
    "defineScatteredAccess", "getScatteredAccessAttributes",
    "deleteVariableAccess", "defineNamedVariableList",
    "getNamedVariableListAttributes", "deleteNamedVariableList",
    "defineNamedType", "getNamedTypeAttributes", "deleteNamedType",
    "input", "output", "takeControl", "relinquishControl",
    "defineSemaphore", "deleteSemaphore", "reportSemaphoreStatus",
    "reportPoolSemaphoreStatus", "reportSemaphoreEntryStatus",
    "initiateDownloadSequence", "downloadSegment",
    "terminateDownloadSequence", "initiateUploadSequence", "uploadSegment",
    "terminateUploadSequence", "requestDomainDownload",
    "requestDomainUpload", "loadDomainContent", "storeDomainContent",
    "deleteDomain", "getDomainAttributes", "createProgramInvocation",
    "deleteProgramInvocation", "start", "stop", "resume", "reset", "kill",
    "getProgramInvocationAttributes", "obtainFile", "defineEventCondition",
    "deleteEventCondition", "getEventConditionAttributes",
    "reportEventConditionStatus", "alterEventConditionMonitoring",
    "triggerEvent", "defineEventAction", "deleteEventAction",
    "getEventActionAttributes", "reportEventActionStatus",
    "defineEventEnrollment", "deleteEventEnrollment", "alterEventEnrollment",
    "reportEventEnrollmentStatus", "getEventEnrollmentAttributes",
    "acknowledgeEventNotification", "getAlarmSummary",
    "getAlarmEnrollmentSummary", "readJournal", "writeJournal",
    "initializeJournal", "reportJournalStatus", "createJournal",
    "deleteJournal", "getCapabilityList", "fileOpen", "fileRead", "fileClose",
    "fileRename", "fileDelete", "fileDirectory", "unsolicitedStatus",
    "informationReport", "eventNotification", "attachToEventCondition",
    "attachToSemaphore", "conclude", "cancel",
]
SVC = {name: i for i, name in enumerate(SERVICES)}

# ISO 9506-2 ParameterSupportOptions.
#
# Indices 0..8 are well attested. A reserved position is believed to sit at 9,
# placing cei at 10, but that was not confirmed against the standard text, so
# position 9 is labelled explicitly rather than renumbered silently. The two
# flags that matter in practice, valt and vlis, are below the uncertainty.
PARAM_SUPPORT = ["str1", "str2", "vnam", "valt", "vadr", "vsca", "tpy",
                 "vlis", "real", "reserved9?", "cei?"]

PARAM_MEANING = {
    "vnam": "named variables supported",
    "valt": "alternateAccess supported: array and component sub-addressing "
            "is reachable",
    "vadr": "addressed (unnamed) variables supported, unusual on IEC 61850",
    "vsca": "scattered access supported, rare and correspondingly untested",
    "tpy": "named types supported",
    "vlis": "named variable lists (datasets) supported",
    "str1": "nested structure/array support, level 1",
    "str2": "nested structure/array support, level 2",
    "real": "floating-point values supported",
}

OBJECT_CLASSES = {
    0: "namedVariable", 1: "scatteredAccess", 2: "namedVariableList",
    3: "namedType", 4: "semaphore", 5: "eventCondition", 6: "eventAction",
    7: "eventEnrollment", 8: "journal", 9: "domain",
}

# MmsPdu CHOICE
PDU_CONFIRMED_REQUEST = 0
PDU_CONFIRMED_RESPONSE = 1
PDU_CONFIRMED_ERROR = 2
PDU_UNCONFIRMED = 3
PDU_REJECT = 4
PDU_INITIATE_RESPONSE = 9
PDU_INITIATE_ERROR = 10
PDU_CONCLUDE_REQUEST = 11

PDU_NAMES = {
    0: "confirmed-RequestPDU", 1: "confirmed-ResponsePDU",
    2: "confirmed-ErrorPDU", 3: "unconfirmed-PDU", 4: "rejectPDU",
    5: "cancel-RequestPDU", 6: "cancel-ResponsePDU", 7: "cancel-ErrorPDU",
    8: "initiate-RequestPDU", 9: "initiate-ResponsePDU",
    10: "initiate-ErrorPDU", 11: "conclude-RequestPDU",
    12: "conclude-ResponsePDU", 13: "conclude-ErrorPDU",
}

# MMS Data CHOICE. Index 8 is unassigned.
DATA_TYPES = {
    1: "array", 2: "structure", 3: "boolean", 4: "bit-string", 5: "integer",
    6: "unsigned", 7: "floating-point", 9: "octet-string",
    10: "visible-string", 11: "generalized-time", 12: "binary-time",
    13: "bcd", 14: "booleanArray", 15: "objId", 16: "mMSString",
    17: "utc-time",
}

# TypeDescription CHOICE, same numbering space as Data for the shared types.
TYPE_DESC = dict(DATA_TYPES)

DATA_ACCESS_ERROR = {
    0: "object-invalidated", 1: "hardware-fault", 2: "temporarily-unavailable",
    3: "object-access-denied", 4: "object-undefined",
    5: "invalid-address", 6: "type-unsupported", 7: "type-inconsistent",
    8: "object-attribute-inconsistent", 9: "object-access-unsupported",
    10: "object-non-existent", 11: "object-value-invalid",
}

# ISO 9506-2 ServiceError errorClass CHOICE, and the enumeration within each.
# decode_error always prints the numeric code alongside the name, so a label
# this table has wrong still leaves the raw value readable.
SERVICE_ERROR_CLASS = {
    0: ("vmd-state", {0: "other", 1: "vmd-state-conflict",
                      2: "vmd-operational-problem",
                      3: "domain-transfer-problem",
                      4: "state-machine-id-invalid"}),
    1: ("application-reference", {0: "other", 1: "application-unreachable",
                                 2: "connection-lost",
                                 3: "application-reference-invalid",
                                 4: "context-unsupported"}),
    2: ("definition", {0: "other", 1: "object-undefined",
                       2: "invalid-address", 3: "type-unsupported",
                       4: "type-inconsistent", 5: "object-exists",
                       6: "object-attribute-inconsistent"}),
    3: ("resource", {0: "other", 1: "memory-unavailable",
                     2: "processor-resource-unavailable",
                     3: "mass-storage-unavailable",
                     4: "capability-unavailable", 5: "capability-unknown"}),
    4: ("service", {0: "other", 1: "primitives-out-of-sequence",
                    2: "object-state-conflict", 4: "continuation-invalid",
                    5: "object-constraint-conflict"}),
    5: ("service-preempt", {0: "other", 1: "timeout", 2: "deadlock",
                            3: "cancel"}),
    6: ("time-resolution", {0: "other",
                            1: "unsupportable-time-resolution"}),
    7: ("access", {0: "other", 1: "object-access-unsupported",
                   2: "object-non-existent", 3: "object-access-denied",
                   4: "object-invalidated"}),
    8: ("initiate", {0: "other", 1: "version-incompatible",
                     2: "max-segment-insufficient",
                     3: "max-services-outstanding-calling-insufficient",
                     4: "max-services-outstanding-called-insufficient",
                     5: "service-CBB-insufficient",
                     6: "parameter-CBB-insufficient",
                     7: "nesting-level-insufficient"}),
    9: ("conclude", {0: "other", 1: "further-communication-required"}),
    10: ("cancel", {0: "other", 1: "invoke-id-unknown",
                    2: "cancel-not-possible"}),
    11: ("file", {0: "other", 1: "filename-ambiguous", 2: "file-busy",
                  3: "filename-syntax-error", 4: "content-type-invalid",
                  5: "position-invalid", 6: "file-access-denied",
                  7: "file-non-existent", 8: "duplicate-filename",
                  9: "insufficient-space-in-filestore"}),
    12: ("others", {}),
}

# ISO 9506-2 RejectPDU rejectReason CHOICE.
_REQ_REJECT = {0: "other", 1: "unrecognized-service",
               2: "unrecognized-modifier", 3: "invalid-invokeID",
               4: "invalid-argument", 5: "invalid-modifier",
               6: "max-serv-outstanding-exceeded",
               8: "max-recursion-exceeded", 9: "value-out-of-range"}
REJECT_REASON = {
    1: ("confirmed-requestPDU", _REQ_REJECT),
    2: ("confirmed-responsePDU", _REQ_REJECT),
    3: ("confirmed-errorPDU", _REQ_REJECT),
    4: ("unconfirmedPDU", _REQ_REJECT),
    5: ("pdu-error", {0: "unknown-pdu-type", 1: "invalid-pdu",
                      2: "illegal-acse-mapping"}),
    6: ("cancel-requestPDU", _REQ_REJECT),
    7: ("cancel-responsePDU", _REQ_REJECT),
    8: ("cancel-errorPDU", _REQ_REJECT),
    9: ("conclude-requestPDU", _REQ_REJECT),
    10: ("conclude-responsePDU", _REQ_REJECT),
    11: ("conclude-errorPDU", _REQ_REJECT),
}

DOMAIN_STATE = {
    0: "non-existent", 1: "loading", 2: "ready", 3: "in-use",
    4: "complete", 5: "incomplete", 7: "d1", 8: "d2", 9: "d3",
}

# IEC 61850 control attributes. Reading $SBO performs a SELECT, which reserves
# apparatus control on a controllable object. Never read these.
CONTROL_ATTRS = ("$SBO", "$SBOW", "$OPER", "$CANCEL")
# The same leaf names without the separator, for checking alternateAccess
# component selectors. Both sides are upper-cased before comparing.
_CONTROL_LEAVES = frozenset(a.lstrip("$").upper() for a in CONTROL_ATTRS)

# ISO 9506 services by what calling them does, used to keep the service-probe
# sweep away from handlers that delete or actuate. An empty request body is
# usually rejected on argument validation, but "usually" is luck rather than
# design: fileDelete's body is a FileName, a SEQUENCE OF GraphicString, and an
# empty SEQUENCE OF is syntactically VALID. So the sweep is restricted by
# service number, not by trusting the argument parser to save it.
READ_ONLY_SERVICES = frozenset({
    0, 1, 2, 4, 6, 9, 12, 15, 23, 24, 25, 37, 45, 49, 50, 55, 56, 60, 61,
    63, 64, 68, 71, 77,
})
DESTRUCTIVE_SERVICES = frozenset({
    10, 13, 16, 19, 22, 34, 35, 36, 39, 41, 43, 44, 46, 48, 52, 54, 58, 66,
    67, 69, 70, 75, 76,
})
# Everything not in either set creates, writes or transfers; still not probed.


# ===========================================================================
#  IEC 61850 logical node classes
# ===========================================================================
#
# IEC 61850-7-4 plus the -7-410 (hydro), -7-420 (DER) and -90-x extensions.
# Deliberately broad: a missing class produces a false "undocumented object"
# flag for every instance of it, and a device with many GOOSE subscriptions
# will carry one LGOS per subscription. Extend with --ln-classes rather than
# accepting the noise.

LN_CLASSES = set("""
LLN0 LPHD LCCH LGOS LSVS LTIM LTMS LTRK
ANCR ARCO ATCC AVCO ARIS
CALH CCGR CILO CPOW CSWI CSYN CAAL CPDI CPTR
DCRP DRCT DRCS DGEN DPVM DPVA DPVC DSTO DFCL DCTS DSCC DSCH DOPM DPST DTRC
FCNT FCSD FFIL FLIM FPID FRMP FSPT FXOT FXUT FSEQ FCSP FMON FSCH
GAPC GGIO GSAL GLOG GRLY
IARC IHMI ITCI ITMI ITPC
KFAN KFIL KPMP KTNK KVLV KCMP KDLC KHST KRMP
MDIF MHAI MHAN MMTR MMXN MMXU MSQI MSTA MENV MFLK MHYD MMDC MMET MSTA
PDIF PDIR PDIS PDOP PDUP PFRC PHAR PHIZ PIOC PMRI PMSS POPF PPAM PSCH
PSDE PTEF PTOC PTOF PTOV PTRC PTTR PTUC PTUF PTUV PUPF PVOC PVPH PZSU
PDFR PFRQ PRTR PSOF PTHF PVST
QFVR QITR QIUB QVTR QVUB QVVR QAXR QHRM QVOL
RADR RBDR RBRF RDIR RDRE RDRS RFLO RPSB RREC RSYN RMXU RRIG RRPW
SARC SCBR SIMG SIML SOPM SPDC SPTR SSWI STMP SVBR SLTC SPGC SRPM
TANG TAXD TCTR TDST TFLW TFRQ TGSN TLVL TMGF TMVM TPOS TPRS TRTN TSND
TTMP TTNS TVBR TVTR TWPH THUM TRAN
XCBR XSWI XFUS
YEFN YLTC YPSH YPTR
ZAXN ZBAT ZBSH ZCAB ZCAP ZCON ZGEN ZGIL ZINV ZLIN ZMOT ZREA ZRRC ZSAR
ZSMC ZTCF ZTCR ZBTC ZFAN ZRES
""".split())

# IEC 61850 functional constraints, used to recognise a well-formed object
# name even when the logical node class is unfamiliar.
FUNCTIONAL_CONSTRAINTS = {
    "ST", "MX", "CO", "SP", "SG", "SE", "SV", "CF", "DC", "EX", "SR", "OR",
    "BL", "RP", "LG", "GO", "GS", "MS", "US", "BR", "RG",
}


# ===========================================================================
#  Service interest notes
# ===========================================================================
#
# Why a service is worth attention. Deliberately phrased as defect CLASSES
# rather than CVE identifiers: a hardcoded CVE list ages badly and invites
# misattribution across implementations. Check current advisories for whichever
# stack you are actually looking at.

SERVICE_NOTES = {
    "getNameList": (
        "continueAfter is attacker-supplied and is copied on every "
        "continuation round. A classic locus for unbounded copies into "
        "fixed-size buffers.", "well-studied"),
    "read": (
        "alternateAccess array and component addressing. Index and range "
        "arithmetic against the real element count.", "well-studied"),
    "write": (
        "same addressing surface as read, plus values that are stored and "
        "then consumed on a different code path later.", "well-studied"),
    "defineNamedVariableList": (
        "caller-supplied dataset names and member lists, held as server "
        "state across requests.", "well-studied"),
    "fileOpen": (
        "file position and length validation, plus path handling.",
        "moderately studied"),
    "fileRead": (
        "returns buffered content; length handling decides whether stale "
        "buffer contents can leak.", "moderately studied"),
    "fileDirectory": (
        "path and wildcard handling, and directory enumeration exposure.",
        "lightly studied"),
    "fileDelete": (
        "DESTRUCTIVE if exercised. Its presence is itself worth reporting: "
        "network-reachable file deletion on a protection device can destroy "
        "disturbance records, which are the forensic record of a fault.",
        "lightly studied"),
    "obtainFile": (
        "server-initiated transfer and file handle lifecycle; double-free "
        "and use-after-free territory.", "moderately studied"),
    "initiateDownloadSequence": (
        "segment reassembly. The classic overflow locus in MMS, and almost "
        "unexamined in published work.", "largely unexamined"),
    "downloadSegment": ("segment reassembly.", "largely unexamined"),
    "requestDomainDownload": ("segment reassembly.", "largely unexamined"),
    "loadDomainContent": ("content load path, server-side file access.",
                          "largely unexamined"),
    "readJournal": ("journal entry parsing and time-range handling.",
                    "largely unexamined"),
    "getCapabilityList": (
        "implementation-defined capability strings. IEC 61850-8-1 does not "
        "use this service, so it is exercised neither by conformance testing "
        "nor by normal operation.", "largely unexamined"),
    "getDomainAttributes": (
        "also outside normal IEC 61850 use. Returns capability strings and "
        "domain state.", "largely unexamined"),
    "takeControl": ("semaphore state machine and ownership tracking.",
                    "largely unexamined"),
    "informationReport": (
        "CLIENT-side parse of unsolicited data. This attacks the master "
        "station, not the device.", "largely unexamined"),
    "unsolicitedStatus": ("CLIENT-side unsolicited parse.",
                          "largely unexamined"),
    "eventNotification": ("CLIENT-side unsolicited parse.",
                          "largely unexamined"),
}


# ===========================================================================
#  Safety gate
# ===========================================================================

class Refused(Exception):
    pass


def check_target(host):
    """Refuse address kinds that are a category error for this tool.

    This is NOT an authorization control. It exists because multicast,
    broadcast and the unspecified address cannot carry a point-to-point MMS
    association at all, so aiming at one is a mistake rather than a decision.
    Everything else is the operator's call.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return                      # a name; what it resolves to is your call
    if ip.is_multicast:
        raise Refused(f"{host} is multicast; MMS is point-to-point over TCP")
    if ip.is_unspecified:
        raise Refused(f"{host} is the unspecified address")
    if ip.version == 4 and ip == ipaddress.IPv4Address("255.255.255.255"):
        raise Refused(f"{host} is the broadcast address")


class LabGate:
    """Gates probes that may change state, degrade service, or send
    non-conformant data.

    Read-only conformant reconnaissance needs no gate and has none. These
    probes are different in kind: each either holds a resource the device
    needs, or deliberately deviates from the protocol to see what happens.
    They are opt-in individually, never as a group, so a typo cannot run one
    you did not choose.
    """

    def __init__(self, enabled=False, selected=()):
        self.enabled = enabled
        self.selected = set(selected)
        self.log = []

    def allow(self, name, what):
        if not self.enabled:
            self.log.append({"probe": name, "ran": False,
                             "why": "--lab not given"})
            return False
        if name not in self.selected:
            self.log.append({"probe": name, "ran": False,
                             "why": "not in --probes"})
            return False
        self.log.append({"probe": name, "ran": True, "what": what})
        return True


def refuse_control_attr(item):
    """Unconditional. Reading anything under FC=CO can perform a SELECT.

    Checking only the four leaf names is not enough, and that was the hole:
    a Read of the FC=CO PARENT (`CSWI1$CO$Pos`) returns the object's
    components, SBO among them, so the Select happens without `$SBO` ever
    appearing in the name. With a component selector the leaf is not in the
    itemID at all.

    So the rule is the functional constraint, not the leaf: refuse any name
    with a `CO` path component, case-insensitively, after normalising a
    trailing separator. Nothing legitimate is lost, because ctlModel lives at
    FC=CF and every other read this tool performs is at ST, MX, CF, DC or SP.
    """
    norm = item.rstrip("$").upper()
    parts = norm.split("$")
    if "CO" in parts:
        raise Refused(
            f"refusing to read {item!r}: it is under functional constraint "
            f"CO. Reading a control object, including its parent node, can "
            f"perform a SELECT, which reserves apparatus control and denies "
            f"it to the operator. Read ctlModel at FC=CF instead. No "
            f"override exists.")
    for attr in CONTROL_ATTRS:
        if attr in norm:
            raise Refused(
                f"refusing to read {item!r}: {attr.lower()} is an IEC 61850 "
                f"control attribute and reading it performs a control-model "
                f"operation. No override exists.")


def object_names_in(pdu: bytes, depth=0):
    """Every domain-specific ObjectName in a PDU, as (domain, item).

    ObjectName domain-specific is `[1] SEQUENCE { domainID, itemID }`, so any
    constructed context-1 TLV holding exactly two VisibleStrings is one. This
    walks the whole PDU rather than a known path, because the point is to
    catch names the caller built by a route this function does not know about.
    """
    if depth > 24:
        return
    for tlv in ber_tlvs(pdu):
        if tlv.is_(CONTEXT, 1) and tlv.constructed:
            strs = [x for x in ber_tlvs(tlv.value)
                    if x.cls == UNIVERSAL and x.num in (26, 25)]
            if len(strs) == 2:
                yield (strs[0].value.decode("ascii", "replace"),
                       strs[1].value.decode("ascii", "replace"))
                continue
        if tlv.constructed:
            yield from object_names_in(tlv.value, depth + 1)


def component_selectors_in(pdu: bytes, depth=0):
    """Every alternateAccess component selector in a PDU.

    Both schemes are covered: component is [1] at member level and [0] inside
    selectAlternateAccess, and the walk does not know which context it is in,
    so it yields candidates from both and the caller filters by name. Over-
    reporting here is harmless; missing one is not.
    """
    if depth > 24:
        return
    for tlv in ber_tlvs(pdu):
        if tlv.is_(CONTEXT, 5) and tlv.constructed:
            # alternateAccess is [5] in ListOfVariableSeq, which sits several
            # levels inside the service argument, so this must match at ANY
            # depth. Requiring depth 0 meant the guard never fired.
            yield from _selectors(tlv.value, 0)
        if tlv.constructed:
            yield from component_selectors_in(tlv.value, depth + 1)


def _selectors(aa: bytes, depth):
    if depth > 24:
        return
    for mem in ber_tlvs(aa):
        if not mem.constructed and mem.num in (0, 1) and mem.value:
            try:
                yield mem.value.decode("ascii")
            except UnicodeDecodeError:
                pass
        elif mem.constructed:
            yield from _selectors(mem.value, depth + 1)


# Service numbers whose argument carries an ObjectName that gets dereferenced.
_DEREFERENCING_SERVICES = frozenset({4, 5, 6})


def check_pdu_safety(mms_pdu: bytes):
    """Enforce the control-attribute rule at the send primitive.

    The guard used to live only in the read helper, which left
    MmsClient.request and send_raw_mms ungated -- and one probe already sent a
    Read straight through request(). An invariant the documentation claims
    has to be enforced where the bytes leave, not where one convenience
    wrapper happens to call it.
    """
    try:
        outer = first_tlv(mms_pdu)
        if outer is None or not outer.is_(CONTEXT, PDU_CONFIRMED_REQUEST):
            return
        for svc in ber_tlvs(outer.value):
            if svc.cls == UNIVERSAL:
                continue                              # invokeID
            if svc.num not in _DEREFERENCING_SERVICES:
                continue
            for _domain, item in object_names_in(svc.value):
                refuse_control_attr(item)
            # A component selector names the leaf inside the alternateAccess
            # rather than in the itemID, so a selector of "SBO" against an
            # FC=CO parent would reach the control model with a clean-looking
            # name. Check the selectors too, at every nesting level.
            for comp in component_selectors_in(svc.value):
                if comp.upper() in _CONTROL_LEAVES:
                    raise Refused(
                        f"refusing a component selector {comp!r}: it names "
                        f"an IEC 61850 control attribute, and selecting it "
                        f"performs a control-model operation even though the "
                        f"itemID does not mention it.")
    except Refused:
        raise
    except Exception:
        # A malformed PDU is the caller's business; this guard only refuses
        # what it can positively identify as a control-object dereference.
        return


# ===========================================================================
#  Transport: TPKT / COTP / ISO 8327 session / ISO 8823 presentation / ACSE
# ===========================================================================

def tpkt(payload):
    return struct.pack("!BBH", 0x03, 0x00, len(payload) + 4) + payload


TPDU_SIZES = {7: 128, 8: 256, 9: 512, 10: 1024, 11: 2048, 12: 4096,
              13: 8192, 14: 16384, 15: 32768, 16: 65536}


def cotp_cr(src_ref=0x0001, dst_ref=0x0000, tpdu_size=0x0D,
            called_tsap=b"\x00\x01", calling_tsap=b"\x00\x01"):
    """COTP Connection Request, class 0.

    tpdu_size is the log2 code: 0x0a is 1024 octets, 0x0d is 8192. COTP
    negotiates downward only, so the responder may reduce what you propose
    but never raise it. Whatever it settles on governs how large a single
    DT TPDU may be, and therefore when responses get fragmented.
    """
    params = (bytes([0xC0, 0x01, tpdu_size])
              + bytes([0xC2, len(called_tsap)]) + called_tsap
              + bytes([0xC1, len(calling_tsap)]) + calling_tsap)
    body = (bytes([0xE0]) + struct.pack("!HH", dst_ref, src_ref)
            + bytes([0x00]) + params)
    return tpkt(bytes([len(body)]) + body)


COTP_DT = bytes([0x02, 0xF0, 0x80])


def cotp_dt(payload):
    return tpkt(COTP_DT + payload)


def sess_len(n):
    """ISO 8327-1 parameter length. Not BER: 0xff escapes to a 2-octet form."""
    if n < 0xFF:
        return bytes([n])
    return bytes([0xFF]) + struct.pack("!H", n)


def session_connect(user_data, calling_ssel=b"\x00\x01",
                    called_ssel=b"\x00\x01"):
    """SPDU type 13, CONNECT."""
    cn_accept = bytes([0x13, 0x01, 0x00]) + bytes([0x16, 0x01, 0x02])
    body = (bytes([0x05]) + sess_len(len(cn_accept)) + cn_accept
            + bytes([0x14, 0x02, 0x00, 0x02])
            + bytes([0x33]) + sess_len(len(calling_ssel)) + calling_ssel
            + bytes([0x34]) + sess_len(len(called_ssel)) + called_ssel
            + bytes([0xC1]) + sess_len(len(user_data)) + user_data)
    return bytes([0x0D]) + sess_len(len(body)) + body


# GIVE TOKENS then DATA TRANSFER, both SPDU type 1 with zero length.
SESSION_DT = bytes([0x01, 0x00, 0x01, 0x00])

ACSE_OID = bytes([0x52, 0x01, 0x00, 0x01])            # 2.2.1.0.1
MMS_AS_OID = bytes([0x28, 0xCA, 0x22, 0x02, 0x01])    # 1.0.9506.2.1
MMS_AC_OID = bytes([0x28, 0xCA, 0x22, 0x02, 0x03])    # 1.0.9506.2.3
BER_TRANSFER_SYNTAX = univ(6, bytes([0x51, 0x01]), constructed=False)

ACSE_CONTEXT_ID = 1
MMS_CONTEXT_ID = 3


def pres_cp_type(acse_pdu, calling_psel=b"\x00\x00\x00\x01",
                 called_psel=b"\x00\x00\x00\x01"):
    """ISO 8823 CP-type carrying an ACSE AARQ."""
    def context(cid, oid):
        return univ(16, (univ(2, int_content(cid), constructed=False)
                         + univ(6, oid, constructed=False)
                         + univ(16, BER_TRANSFER_SYNTAX)))

    ctx_list = context(ACSE_CONTEXT_ID, ACSE_OID) + context(MMS_CONTEXT_ID,
                                                            MMS_AS_OID)
    user_data = pres_user_data(acse_pdu, ACSE_CONTEXT_ID)
    normal = (ctx(1, calling_psel, constructed=False)
              + ctx(2, called_psel, constructed=False)
              + ctx(4, ctx_list)
              + user_data)
    return univ(17, ctx(0, ctx(0, b"\x01", constructed=False))
                + ctx(2, normal))


def pres_user_data(pdu, context_id):
    """fully-encoded-data, [APPLICATION 1], one PDV-list entry."""
    pdv = univ(16, (univ(2, int_content(context_id), constructed=False)
                    + ctx(0, pdu)))
    return tlv(APPLICATION, 1, pdv)


def mms_initiate_request(local_detail=65000, max_out_calling=5,
                         max_out_called=5, nesting=10):
    detail = (ctx(0, b"\x01", constructed=False)
              + ctx(1, bytes([0x05, 0xF1, 0x00]), constructed=False)
              + ctx(2, bytes.fromhex("03ee1c00000408000079ef18"),
                    constructed=False))
    # localDetailCalling is Integer32: encode minimally rather than padding
    # to a fixed three octets, which produced a non-minimal encoding for
    # anything under 0x800000 and overflowed above it.
    body = (ctx(0, int_content(local_detail), constructed=False)
            + ctx(1, bytes([max_out_calling]), constructed=False)
            + ctx(2, bytes([max_out_called]), constructed=False)
            + ctx(3, bytes([nesting]), constructed=False)
            + ctx(4, detail))
    return ctx(8, body)


def acse_aarq(mms_init, direct_reference=True):
    """ACSE AARQ carrying the MMS Initiate in user-information.

    X.690 EXTERNAL makes direct-reference OPTIONAL and it comes first when
    present. Omitting it is legal and some stacks accept that, but stacks
    observed in the field send the BER transfer-syntax OID 2.1.1 ahead of the
    indirect reference, so including it is the safer default: it matches what
    real devices are known to accept.
    """
    ext_body = b""
    if direct_reference:
        ext_body += univ(6, bytes([0x51, 0x01]), constructed=False)   # 2.1.1
    ext_body += (univ(2, int_content(MMS_CONTEXT_ID), constructed=False)
                 + ctx(0, mms_init))
    ext = univ(8, ext_body)
    body = (ctx(1, univ(6, MMS_AC_OID, constructed=False))
            + ctx(2, univ(6, bytes([0x29, 0x01, 0x87, 0x67, 0x01]),
                          constructed=False))
            + ctx(3, univ(2, b"\x0c", constructed=False))
            + ctx(6, univ(6, bytes([0x29, 0x01, 0x87, 0x67]),
                          constructed=False))
            + ctx(7, univ(2, b"\x0c", constructed=False))
            + ctx(30, ext))
    return tlv(APPLICATION, 0, body)


def confirmed_request(invoke_id, service):
    return ctx(0, univ(2, int_content(invoke_id), constructed=False) + service)


CONCLUDE_REQUEST = ctx(PDU_CONCLUDE_REQUEST, b"", constructed=False)


# ---------------------------------------------------------------------------
#  Inbound: descend the layers properly rather than scanning for a tag byte
# ---------------------------------------------------------------------------

def strip_tpkt_cotp(frame):
    """-> (kind, user_data, eot).

    `eot` is the End-of-TSDU bit from a DT TPDU's flags octet. A device that
    negotiates a small TPDU size splits a large response across several DT
    TPDUs with EOT clear on all but the last. Ignoring the bit means reading
    one fragment and then failing to parse it, so the caller MUST reassemble
    until eot is true. For non-DT TPDUs eot is reported true, since there is
    nothing to reassemble.
    """
    if len(frame) < 6 or frame[0] != 0x03:
        raise BerError(f"not a TPKT frame: {frame[:8].hex()}")
    plen = struct.unpack("!H", frame[2:4])[0]
    # Trusting the declared length against a short buffer silently produced
    # an empty, complete TSDU, which every caller then read as "the device
    # answered with nothing".
    if plen < 6:
        raise BerError(f"implausible TPKT length {plen}")
    if plen > len(frame):
        raise BerError(f"TPKT declares {plen} bytes but {len(frame)} arrived")
    body = frame[4:plen]
    li = body[0]
    code = body[1]
    if code == 0xD0:
        return "cc", body[1 + li:], True
    if code == 0x80:
        return "dr", body[1 + li:], True
    if code != 0xF0:
        return f"cotp-{code:02x}", body[1 + li:], True
    eot = bool(body[2] & 0x80) if len(body) > 2 else True
    return "dt", body[1 + li:], eot


def cotp_cc_tpdu_size(user_data_frame):
    """Negotiated TPDU size in octets from a COTP CC, or None.

    The CC carries parameter 0xc0 with the agreed log2 code. It may be lower
    than proposed and it is what governs fragmentation from here on.
    """
    try:
        plen = struct.unpack("!H", user_data_frame[2:4])[0]
        body = user_data_frame[4:plen]
        li = body[0]
        # body[0]=LI, [1]=code, [2:4]=dst-ref, [4:6]=src-ref, [6]=class,
        # parameters from [7]. The TPDU occupies body[1:1+li].
        p = 7
        while p + 2 <= 1 + li:
            code, ln = body[p], body[p + 1]
            if code == 0xC0 and ln == 1:
                return TPDU_SIZES.get(body[p + 2])
            p += 2 + ln
    except Exception:
        pass
    return None


def strip_session(buf):
    """Return (kind, user_data).

    kind is 'data' for a GIVE TOKENS / DATA TRANSFER pair, 'accept' for a
    CONNECT ACCEPT, 'refuse' for a REFUSE, else 'spdu-NN'.
    """
    if buf[:4] == SESSION_DT:
        return "data", buf[4:]
    if buf[:2] == bytes([0x01, 0x00]):
        return "data", buf[2:]
    if not buf:
        return "empty", b""
    si = buf[0]
    if si in (0x0E, 0x0D, 0x0C):
        body = buf[2:]
        if buf[1] == 0xFF:
            n = struct.unpack("!H", buf[2:4])[0]
            body = buf[4:4 + n]
        else:
            body = buf[2:2 + buf[1]]
        kind = {0x0E: "accept", 0x0D: "connect", 0x0C: "refuse"}[si]
        return kind, _session_pgi(body, 0xC1)
    return f"spdu-{si:02x}", buf


def _session_pgi(body, want):
    """Pull one PI/PGI unit's content out of an ISO 8327 SPDU body."""
    p = 0
    while p + 1 < len(body):
        pi = body[p]
        ln = body[p + 1]
        p += 2
        if ln == 0xFF:
            ln = struct.unpack("!H", body[p:p + 2])[0]
            p += 2
        if pi == want:
            return body[p:p + ln]
        p += ln
    return b""


class Desynchronised(BerError):
    """A reply arrived whose invokeID is not the one we sent.

    Raised rather than recovered from, because once the response stream is
    off by one every later value is attributed to the wrong object and
    nothing in the data says so.
    """


def pdu_invoke_id(pdu):
    """The invokeID a reply is answering, or None.

    The MMS ASN.1 is inconsistent here and that inconsistency is the bug
    trap: in confirmed-RequestPDU and confirmed-ResponsePDU the invokeID is
    an UNTAGGED universal INTEGER, while in confirmed-ErrorPDU and rejectPDU
    it is context [0] (and OPTIONAL in rejectPDU).
    """
    if pdu.is_(CONTEXT, PDU_CONFIRMED_RESPONSE):
        for f in ber_tlvs(pdu.value):
            if f.cls == UNIVERSAL and f.num == 2:
                return int.from_bytes(f.value, "big")
        return None
    if pdu.is_(CONTEXT, PDU_CONFIRMED_ERROR) or pdu.is_(CONTEXT, PDU_REJECT):
        f = find_tlv(pdu.value, CONTEXT, 0)
        if f is not None and not f.constructed:
            return int.from_bytes(f.value, "big")
    return None


def mms_pdus_from_data(user_data):
    """EVERY MMS PDU in a presentation user-data, as (context_id, pdu).

    One frame can carry several PDV-lists, and an IEC 61850 device with
    reporting enabled emits unsolicited informationReports whenever it likes
    -- including in the same frame as a reply, or in a frame of their own
    between a request and its answer. Taking only the first PDV-list drops
    the rest without trace, and treating whatever arrives as the answer to
    the last request desynchronises the stream permanently.
    """
    out = []
    for ud in ber_tlvs(user_data):
        if not ud.is_(APPLICATION, 1):
            continue
        for pdv in ber_tlvs(ud.value):
            if pdv.cls != UNIVERSAL or pdv.num != 16:
                continue
            cid, sat = None, None
            for f in ber_tlvs(pdv.value):
                if f.cls == UNIVERSAL and f.num == 2:
                    cid = int.from_bytes(f.value, "big")
                elif f.is_(CONTEXT, 0):
                    sat = f
            if sat is None:
                continue
            pdu = first_tlv(sat.value)
            if pdu is not None:
                out.append((cid, pdu))
    return out


def mms_from_data(user_data):
    """presentation fully-encoded-data -> the FIRST MMS PDU TLV.

    Kept for the association handshake, where exactly one PDU is expected.
    Use mms_pdus_from_data on the data path.
    """
    ud = find_tlv(user_data, APPLICATION, 1)
    if ud is None:
        raise BerError("no presentation user-data in frame")
    pdv = find_tlv(ud.value, UNIVERSAL, 16)
    if pdv is None:
        raise BerError("no PDV-list")
    sat = find_tlv(pdv.value, CONTEXT, 0)
    if sat is None:
        raise BerError("PDV-list carries no single-ASN1-type")
    pdu = first_tlv(sat.value)
    if pdu is None:
        raise BerError("empty single-ASN1-type")
    return pdu


def mms_from_accept(user_data):
    """CPA -> AARE -> user-information -> EXTERNAL -> MMS initiate response.

    Both the presentation fully-encoded-data and the ACSE AARE are tagged
    [APPLICATION 1], so this has to descend structurally. Searching for a tag
    finds the wrong one.
    """
    cpa = first_tlv(user_data)
    if cpa is None:
        raise BerError("no presentation PDU in session ACCEPT")
    nmp = find_tlv(cpa.value, CONTEXT, 2)
    if nmp is None:
        raise BerError("CPA has no normal-mode-parameters")
    pres_ud = find_tlv(nmp.value, APPLICATION, 1)
    if pres_ud is None:
        raise BerError("CPA carries no user-data")
    pdv = find_tlv(pres_ud.value, UNIVERSAL, 16)
    if pdv is None:
        raise BerError("CPA user-data has no PDV-list")
    sat = find_tlv(pdv.value, CONTEXT, 0)
    if sat is None:
        raise BerError("CPA PDV-list carries no single-ASN1-type")
    aare = find_tlv(sat.value, APPLICATION, 1)
    if aare is None:
        raise BerError("no ACSE AARE")
    ui = find_tlv(aare.value, CONTEXT, 30)
    if ui is None:
        raise BerError("AARE carries no user-information")
    ext = find_tlv(ui.value, UNIVERSAL, 8)
    if ext is None:
        raise BerError("user-information is not an EXTERNAL")
    inner = find_tlv(ext.value, CONTEXT, 0)
    if inner is None:
        raise BerError("EXTERNAL carries no single-ASN1-type")
    pdu = first_tlv(inner.value)
    if pdu is None:
        raise BerError("empty MMS payload in AARE")
    return pdu


# ===========================================================================
#  MMS request builders
# ===========================================================================

def obj_name_domain(domain, item):
    """ObjectName ::= domain-specific [1] SEQUENCE { domainID, itemID }"""
    return ctx(1, vis(domain) + vis(item))


def req_identify():
    """Identify-Request ::= NULL, implicitly tagged, so primitive."""
    return ctx(SVC["identify"], b"", constructed=False)


def req_status(extended=False):
    return ctx(SVC["status"], b"\xff" if extended else b"\x00",
               constructed=False)


def req_get_name_list(object_class=0, domain=None, continue_after=None):
    if not 0 <= object_class <= 0x7FFFFFFF:
        raise ValueError(f"objectClass out of range: {object_class}")
    body = ctx(0, ctx(0, int_content(object_class), constructed=False))
    if domain is None:
        body += ctx(1, ctx(0, b"", constructed=False))
    else:
        body += ctx(1, ctx(1, domain.encode("ascii"), constructed=False))
    if continue_after is not None:
        if isinstance(continue_after, str):
            continue_after = continue_after.encode("ascii")
        body += ctx(2, continue_after, constructed=False)
    return ctx(SVC["getNameList"], body)


# ---------------------------------------------------------------------------
#  alternateAccess
# ---------------------------------------------------------------------------
#
# Array and component sub-addressing. Reachable only when the server set
# `valt` in ParameterSupportOptions during Initiate.
#
#     ListOfVariableSeq ::= SEQUENCE {
#         variableSpecification VariableSpecification,
#         alternateAccess       [5] IMPLICIT AlternateAccess OPTIONAL }
#
#     AlternateAccess ::= SEQUENCE OF CHOICE {
#         unnamed  AlternateAccessSelection,
#         named    [5] IMPLICIT SEQUENCE {
#                      componentName [0] IMPLICIT Identifier,
#                      access        AlternateAccessSelection } }
#
#     AlternateAccessSelection ::= CHOICE {
#         selectAlternateAccess [0] IMPLICIT SEQUENCE {
#             accessSelection CHOICE { component    [0] IMPLICIT Identifier,
#                                      index        [1] IMPLICIT Unsigned32,
#                                      indexRange   [2] IMPLICIT SEQUENCE {
#                                          lowIndex         [0],
#                                          numberOfElements [1] },
#                                      allElements  [3] IMPLICIT NULL },
#             alternateAccess AlternateAccess },
#         selectAccess CHOICE {        component    [1] IMPLICIT Identifier,
#                                      index        [2] IMPLICIT Unsigned32,
#                                      indexRange   [3] IMPLICIT SEQUENCE {
#                                          lowIndex         [0],
#                                          numberOfElements [1] },
#                                      allElements  [4] IMPLICIT NULL } }
#
# THE TRAP, and it is the reason this was built from the ASN.1 rather than
# from worked examples: the SAME four alternatives are numbered DIFFERENTLY
# in the two places they appear. At the member level, through the untagged
# `selectAccess` CHOICE, they are 1/2/3/4. Inside `selectAlternateAccess`
# they are 0/1/2/3. Published hex for these structures disagrees, and an
# encoder that uses one scheme in both places produces a request the server
# either rejects or, worse, misinterprets as a different selector.
#
# Tag numbers above were taken from the asn1c member tables generated from
# the MMS ASN.1 module, then confirmed on the wire against an independent
# server holding a known array. See test_mms_recon.py.

# selectAccess, used at member level
AA_COMPONENT, AA_INDEX, AA_INDEX_RANGE, AA_ALL = 1, 2, 3, 4
# accessSelection, used inside selectAlternateAccess
AA_INNER_COMPONENT, AA_INNER_INDEX = 0, 1
AA_INNER_INDEX_RANGE, AA_INNER_ALL = 2, 3


def aa_index(n, inner=False):
    """Select one element. Unsigned32, so encoded as a non-negative INTEGER:
    0xffffffff needs the leading zero pad or it reads as -1."""
    return ctx(AA_INNER_INDEX if inner else AA_INDEX, int_content(n),
               constructed=False)


def aa_index_range(low, count, inner=False):
    """Select `count` elements starting at `low`."""
    body = (ctx(0, int_content(low), constructed=False)
            + ctx(1, int_content(count), constructed=False))
    return ctx(AA_INNER_INDEX_RANGE if inner else AA_INDEX_RANGE, body)


def aa_component(name, inner=False):
    """Select a named component of a structure."""
    if isinstance(name, str):
        name = name.encode("ascii")
    return ctx(AA_INNER_COMPONENT if inner else AA_COMPONENT, name,
               constructed=False)


def aa_all_elements(inner=False):
    return ctx(AA_INNER_ALL if inner else AA_ALL, b"", constructed=False)


def aa_named(component, access):
    """named [5]: a component name plus a further selection within it."""
    if isinstance(component, str):
        component = component.encode("ascii")
    return ctx(5, ctx(0, component, constructed=False) + access)


def aa_nested(outer, inner_members):
    """selectAlternateAccess [0]: apply `outer` (in the INNER tag scheme),
    then descend into the result with `inner_members`.

    This is the form a server recognises as access to a component of an
    array element, e.g. element 2's `mag`: outer=aa_index(2, inner=True),
    inner_members=[aa_component('mag')].
    """
    return ctx(0, outer + univ(16, b"".join(inner_members)))


def alternate_access(*members):
    """AlternateAccess, implicitly tagged [5] inside ListOfVariableSeq."""
    return ctx(5, b"".join(members))


def req_read(domain, item, alt=None):
    """Read, optionally with an alternateAccess selection.

    `alt` is the output of alternate_access(...), already tagged [5].
    """
    inner = ctx(0, obj_name_domain(domain, item))
    if alt:
        inner += alt
    var = univ(16, inner)
    return ctx(SVC["read"], ctx(1, ctx(0, var)))


def req_get_var_access_attrs(domain, item):
    """GetVariableAccessAttributes-Request ::= CHOICE { name [0] ObjectName }.

    ObjectName is itself a CHOICE, so [0] must be explicit.
    """
    return ctx(SVC["getVariableAccessAttributes"],
               ctx(0, obj_name_domain(domain, item)))


def req_get_capability_list(continue_after=None):
    """Service 71. Above 30, so the tag is the two-byte form 0xbf 0x47."""
    body = b""
    if continue_after is not None:
        body += ctx(0, continue_after.encode("ascii"), constructed=False)
    return ctx(SVC["getCapabilityList"], body)


def req_get_domain_attributes(domain):
    """Service 37. Request is an Identifier, implicitly tagged, so primitive:
    0x9f 0x25."""
    return ctx(SVC["getDomainAttributes"], domain.encode("ascii"),
               constructed=False)


def req_file_directory(path=None, continue_after=None):
    """Service 77, tag 0xbf 0x4d. Both fields optional; empty lists all."""
    body = b""
    if path:
        body += ctx(0, univ(25, path.encode("ascii"), constructed=False))
    if continue_after:
        body += ctx(1, univ(25, continue_after.encode("ascii"),
                            constructed=False))
    return ctx(SVC["fileDirectory"], body)


# ===========================================================================
#  MMS response decoders
# ===========================================================================

def service_response(pdu):
    """(service_number, value) from a confirmed-ResponsePDU, else raise."""
    if pdu.is_(CONTEXT, PDU_CONFIRMED_ERROR):
        raise MmsServiceError(decode_error(pdu.value))
    if pdu.is_(CONTEXT, PDU_REJECT):
        raise MmsServiceError(f"rejected: {decode_reject(pdu.value)}")
    if not pdu.is_(CONTEXT, PDU_CONFIRMED_RESPONSE):
        name = PDU_NAMES.get(pdu.num, f"pdu-{pdu.num}")
        raise MmsServiceError(f"unexpected {name}")
    for t in ber_tlvs(pdu.value):
        if t.cls == UNIVERSAL and t.num == 2:
            continue                      # invokeID
        return t.num, t.value
    raise MmsServiceError("confirmed-ResponsePDU carried no service response")


class MmsServiceError(Exception):
    pass


def decode_error(value):
    """confirmed-ErrorPDU -> a readable description.

        ConfirmedErrorPDU ::= SEQUENCE {
          invokeID         [0] IMPLICIT Unsigned32,
          modifierPosition [1] IMPLICIT Unsigned32 OPTIONAL,
          serviceError     [2] IMPLICIT ServiceError }
        ServiceError ::= SEQUENCE {
          errorClass            [0] CHOICE { ... },
          additionalCode        [1] IMPLICIT INTEGER OPTIONAL,
          additionalDescription [2] IMPLICIT VisibleString OPTIONAL,
          serviceSpecificInfo   [3] CHOICE OPTIONAL }

    Note that invokeID here is context [0], unlike ConfirmedRequestPDU and
    ConfirmedResponsePDU where it is an untagged universal INTEGER. The MMS
    ASN.1 is genuinely inconsistent on this point, and a decoder that assumes
    the untagged form misreads the whole PDU.

    The numeric code is always included alongside the name, so a label this
    table gets wrong still leaves the raw value visible.
    """
    parts = []
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0) and not t.constructed:
            continue                                   # invokeID
        if t.is_(CONTEXT, 1) and not t.constructed:
            parts.append(f"modifierPosition="
                         f"{int.from_bytes(t.value, 'big')}")
        elif t.is_(CONTEXT, 2):
            parts.append(_decode_service_error(t.value))
        else:
            parts.append(f"tag{t.num}={t.value.hex()}")
    return "; ".join(p for p in parts if p) or value.hex()


def _decode_service_error(value):
    out = []
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            alt = first_tlv(t.value)
            if alt is None:
                continue
            cls_name, codes = SERVICE_ERROR_CLASS.get(
                alt.num, (f"class{alt.num}", {}))
            code = int.from_bytes(alt.value, "big") if alt.value else 0
            out.append(f"{cls_name}/{codes.get(code, 'unnamed')}({code})")
        elif t.is_(CONTEXT, 1):
            out.append(f"additionalCode="
                       f"{int.from_bytes(t.value, 'big') if t.value else 0}")
        elif t.is_(CONTEXT, 2):
            out.append(f"description={t.value.decode('ascii', 'replace')!r}")
    return " ".join(out)


def decode_reject(value):
    """rejectPDU -> a readable description.

        RejectPDU ::= SEQUENCE {
          originalInvokeID [0] IMPLICIT Unsigned32 OPTIONAL,
          rejectReason CHOICE { confirmed-requestPDU [1] INTEGER, ... } }
    """
    invoke, reason = None, None
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            invoke = int.from_bytes(t.value, "big") if t.value else None
        else:
            group, codes = REJECT_REASON.get(t.num, (f"reason{t.num}", {}))
            code = int.from_bytes(t.value, "big") if t.value else 0
            reason = f"{group}/{codes.get(code, 'unnamed')}({code})"
    bits = [b for b in (f"invokeID={invoke}" if invoke is not None else None,
                        reason) if b]
    return ", ".join(bits) or value.hex()


def decode_identify(value):
    """vendorName [0], modelName [1], revision [2], all mandatory.

    Matched by tag rather than by position, so a non-conformant ordering is
    reported correctly instead of silently mis-assigned.
    """
    out = {}
    names = {0: "vendor", 1: "model", 2: "revision"}
    for t in ber_tlvs(value):
        if t.num in names and not t.constructed:
            out[names[t.num]] = t.value.decode("ascii", "replace")
        elif t.num == 3:
            oids = [o.value.hex() for o in ber_tlvs(t.value)]
            out["abstractSyntaxes"] = oids
    return out


def decode_strings(value, tag_nums=(26, 25), _depth=0):
    """SEQUENCE OF VisibleString (26) or GraphicString (25).

    MMS Identifier is VisibleString. MMS FileName is SEQUENCE OF
    GraphicString. Accepting both is the difference between listing a file
    directory and reporting it empty.
    """
    # Capped: a response of deeply nested constructed types fits easily
    # inside a normal max-PDU and would otherwise raise RecursionError.
    if _depth > 64:
        return []
    out = []
    for t in ber_tlvs(value):
        if t.cls == UNIVERSAL and t.num in tag_nums:
            out.append(t.value.decode("ascii", "replace"))
        elif t.constructed:
            out.extend(decode_strings(t.value, tag_nums, _depth + 1))
    return out


def decode_name_list(value):
    """(identifiers, more_follows).

    moreFollows is BOOLEAN DEFAULT TRUE. Absence therefore means MORE DATA
    FOLLOWS. Reading absence as completion silently truncates enumeration.
    """
    names, more = [], True
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            # Identifier is VisibleString(26), but accept GraphicString(25)
            # and the other string universals too: a device encoding names
            # with a different universal tag otherwise decodes to zero names
            # with moreFollows defaulting true, which reads as a clean
            # negative rather than as an encoding deviation.
            names = decode_strings(t.value, (26, 25, 19, 12))
        elif t.is_(CONTEXT, 1):
            more = bool(t.value and t.value[0])
    return names, more


def decode_capability_list(value):
    """(capabilities, more_follows). moreFollows is DEFAULT TRUE here too."""
    caps, more = [], True
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            caps = decode_strings(t.value, (26, 25))
        elif t.is_(CONTEXT, 1):
            more = bool(t.value and t.value[0])
    return caps, more


def decode_domain_attributes(value):
    out = {}
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            out["capabilities"] = decode_strings(t.value, (26, 25))
        elif t.is_(CONTEXT, 1):
            n = int.from_bytes(t.value, "big") if t.value else None
            out["state"] = DOMAIN_STATE.get(n, f"state-{n}")
        elif t.is_(CONTEXT, 2):
            out["mmsDeletable"] = bool(t.value and t.value[0])
        elif t.is_(CONTEXT, 3):
            out["programInvocations"] = decode_strings(t.value, (26, 25))
        elif t.is_(CONTEXT, 4):
            out["uploadsInProgress"] = (int.from_bytes(t.value, "big")
                                        if t.value else 0)
    return out


def decode_file_directory(value):
    """(entries, more_follows). moreFollows here is DEFAULT FALSE, the
    opposite of GetNameList."""
    entries, more = [], False
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            for ent in ber_tlvs(t.value):
                e = {}
                for f in ber_tlvs(ent.value):
                    if f.is_(CONTEXT, 0):
                        parts = decode_strings(f.value, (25, 26))
                        e["name"] = "/".join(parts)
                    elif f.is_(CONTEXT, 1):
                        for a in ber_tlvs(f.value):
                            if a.is_(CONTEXT, 0):
                                e["size"] = int.from_bytes(a.value, "big")
                            elif a.is_(CONTEXT, 1):
                                e["modified"] = a.value.decode(
                                    "ascii", "replace")
                if e:
                    entries.append(e)
        elif t.is_(CONTEXT, 1):
            more = bool(t.value and t.value[0])
    return entries, more


def render_data(t):
    """One MMS Data CHOICE alternative -> a readable Python value.

    Every type is rendered. A decoder that handles only strings and integers
    makes other values vanish without trace, which is worse than printing hex.
    """
    name = DATA_TYPES.get(t.num, f"tag-{t.num}")
    v = t.value
    if t.num in (1, 2):
        return {name: [render_data(c) for c in ber_tlvs(v)]}
    if t.num == 3:
        return bool(v and v[0])
    if t.num == 4:
        idx, total = bitstring_indices(v)
        return {"bit-string": {"bits": total, "set": idx, "hex": v.hex()}}
    if t.num == 5:
        return int.from_bytes(v, "big", signed=True) if v else 0
    if t.num == 6:
        return int.from_bytes(v, "big") if v else 0
    if t.num == 7:
        if len(v) == 5:
            return struct.unpack("!f", v[1:])[0]
        if len(v) == 9:
            return struct.unpack("!d", v[1:])[0]
        return {"floating-point": v.hex()}
    if t.num in (10, 16):
        return v.decode("ascii", "replace").rstrip("\x00")
    if t.num == 11:
        return v.decode("ascii", "replace")
    if t.num == 12:
        return {"binary-time": v.hex()}
    if t.num == 17:
        if len(v) >= 4:
            secs = int.from_bytes(v[:4], "big")
            return {"utc-time": secs, "hex": v.hex()}
        return {"utc-time": v.hex()}
    if t.num == 9:
        return {"octet-string": v.hex()}
    if t.num == 14:
        idx, total = bitstring_indices(v)
        return {"booleanArray": {"bits": total, "set": idx}}
    if t.num == 15:
        return {"objId": v.hex()}
    if t.num == 13:
        return {"bcd": v.hex()}
    return {name: v.hex()}


def decode_read_response(value):
    """-> list of either a rendered value or {'failure': reason}."""
    results = []
    for t in ber_tlvs(value):
        if not t.is_(CONTEXT, 1):
            continue
        for ar in ber_tlvs(t.value):
            if ar.is_(CONTEXT, 0) and not ar.constructed:
                code = int.from_bytes(ar.value, "big") if ar.value else None
                results.append({"failure": DATA_ACCESS_ERROR.get(
                    code, f"error-{code}")})
            else:
                results.append(render_data(ar))
    return results


def decode_type_description(value):
    """GetVariableAccessAttributes-Response -> (kind, elements, depth).

    typeDescription is [2], and the TypeDescription CHOICE alternative sits
    directly inside it.
    """
    td = find_tlv(value, CONTEXT, 2)
    if td is None:
        return None, None, 0
    alt = first_tlv(td.value)
    if alt is None:
        return None, None, 0
    kind = TYPE_DESC.get(alt.num, f"tag-{alt.num}")
    elements = None
    if alt.num == 1:
        n = find_tlv(alt.value, CONTEXT, 1)
        if n is not None:
            elements = int.from_bytes(n.value, "big")
    return kind, elements, _type_depth(alt)


def _type_depth(alt, cap=64):
    """Nesting depth of a TypeDescription subtree.

        array [1]     SEQUENCE { packed [0], numberOfElements [1],
                                 elementType [2] TypeSpecification }
        structure [2] SEQUENCE { packed [0],
                                 components [1] SEQUENCE OF SEQUENCE {
                                     componentName [0] OPTIONAL,
                                     componentType [1] TypeSpecification } }
        TypeSpecification ::= CHOICE { typeName [0] ObjectName,
                                       typeDescription TypeDescription }

    Counts CONSTRUCTED levels only, matching what MMS
    dataStructureNestingLevel means: a scalar is 0, a flat structure of
    scalars is 1, a structure holding a structure is 2.

    TypeSpecification is a CHOICE, so elementType and componentType are
    EXPLICIT wrappers. Those wrappers are constructed and context-tagged, and
    so is the components list. A walker that recurses on any constructed
    context tag counts all three as nesting and over-reports badly: a flat
    structure of 44 scalars comes out as depth 44.
    """
    if cap <= 0:
        return 0
    if alt.num == 1:
        et = find_tlv(alt.value, CONTEXT, 2)
        return 1 + (_spec_depth(et, cap - 1) if et is not None else 0)
    if alt.num == 2:
        comps = find_tlv(alt.value, CONTEXT, 1)
        if comps is None:
            return 1
        deepest = 0
        for comp in ber_tlvs(comps.value):
            if not comp.constructed:
                continue
            ct = find_tlv(comp.value, CONTEXT, 1)
            if ct is None:
                continue
            deepest = max(deepest, _spec_depth(ct, cap - 1))
        return 1 + deepest
    return 0                              # a scalar is not nested


def _spec_depth(wrapper, cap):
    """Step through an explicit TypeSpecification wrapper into the type."""
    if cap <= 0:
        return 0
    inner = first_tlv(wrapper.value)
    if inner is None:
        return 0
    if inner.num == 0 and inner.constructed:
        return 0                          # typeName reference, no inline type
    if inner.num in (1, 2):
        return _type_depth(inner, cap)
    return 0


# ===========================================================================
#  Client
# ===========================================================================

class MmsClient:
    """One MMS association. Use as a context manager so it always Concludes."""

    def __init__(self, host, port=102, timeout=8.0, rate=0.0,
                 recorder=None, tpdu_size=0x0A, direct_reference=True,
                 progress=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.rate = rate
        self.recorder = recorder
        self.tpdu_size = tpdu_size
        self.direct_reference = direct_reference
        self.progress = progress
        self.sock = None
        self.invoke_id = 0
        self.negotiated = {}
        self.cotp_tpdu_octets = TPDU_SIZES.get(tpdu_size, 1024)
        self.tpdu_negotiated = "proposed, not yet negotiated"
        # Unsolicited PDUs the device sent us. Not errors: a device with
        # reporting enabled is supposed to do this.
        self.unsolicited = []
        self.latencies = []
        self._last = 0.0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- plumbing -------------------------------------------------------
    def _record(self, direction, label, raw):
        if self.recorder is not None:
            self.recorder.append({"dir": direction, "label": label,
                                  "hex": raw.hex()})

    def _throttle(self):
        if self.rate <= 0:
            return
        delta = time.monotonic() - self._last
        if delta < self.rate:
            time.sleep(self.rate - delta)
        self._last = time.monotonic()

    def _send(self, frame, label):
        self._throttle()
        self._record("tx", label, frame)
        self.sock.sendall(frame)

    def _recv_tpkt(self):
        hdr = self._recv_exact(4)
        length = struct.unpack("!H", hdr[2:4])[0]
        if length < 4 or length > 65535:
            raise BerError(f"implausible TPKT length {length}")
        frame = hdr + self._recv_exact(length - 4)
        self._record("rx", "tpkt", frame)
        return frame

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise BerError("connection closed by peer")
            buf += chunk
        return buf

    def _send_cotp(self, payload, label):
        """Send one COTP TSDU, fragmenting to the negotiated TPDU size.

        Outbound fragmentation matters less than inbound, because requests
        are small, but a long continueAfter identifier can push a GetNameList
        over a 128- or 256-octet TPDU limit.
        """
        room = max(64, self.cotp_tpdu_octets - 3)
        if len(payload) <= room:
            self._send(cotp_dt(payload), label)
            return
        n = (len(payload) + room - 1) // room
        for i in range(n):
            chunk = payload[i * room:(i + 1) * room]
            eot = 0x80 if i == n - 1 else 0x00
            body = bytes([0x02, 0xF0, eot]) + chunk
            self._send(tpkt(body), f"{label}[{i + 1}/{n}]")

    def _recv_cotp(self):
        """Read one complete COTP TSDU, reassembling DT fragments.

        This is the whole reason the EOT bit is exposed. A device that
        negotiates a 1024-octet TPDU size splits any larger response across
        several DT TPDUs, and the ISO session header appears only on the
        first fragment, so the payload has to be concatenated before the
        session layer is stripped. Reading a single frame instead yields a
        fragment that cannot be parsed at all.
        """
        parts, frames = [], 0
        while True:
            kind, data, eot = strip_tpkt_cotp(self._recv_tpkt())
            if kind != "dt":
                return kind, data
            parts.append(data)
            frames += 1
            if eot:
                break
            if frames > 4096 or sum(len(x) for x in parts) > 16 * 1024 * 1024:
                raise BerError("COTP reassembly limit exceeded; the peer is "
                               "not setting the end-of-TSDU bit")
        if frames > 1:
            self._record("rx", f"reassembled {frames} COTP fragments",
                         b"".join(parts))
        return "dt", b"".join(parts)

    # -- association ----------------------------------------------------
    def connect(self, initiate=None):
        check_target(self.host)
        self.sock = socket.create_connection((self.host, self.port),
                                             self.timeout)
        self.sock.settimeout(self.timeout)
        t0 = time.monotonic()
        self._send(cotp_cr(tpdu_size=self.tpdu_size), "cotp-cr")
        cc_frame = self._recv_tpkt()
        kind, _, _ = strip_tpkt_cotp(cc_frame)
        self.latencies.append({"step": "cotp-cr/cc",
                               "ms": (time.monotonic() - t0) * 1000})
        if kind != "cc":
            raise BerError(f"COTP connect refused ({kind})")
        agreed = cotp_cc_tpdu_size(cc_frame)
        if agreed:
            self.cotp_tpdu_octets = agreed
            self.tpdu_negotiated = "negotiated"
        else:
            # ISO 8073 negotiates downward only, and an ABSENT TPDU-size
            # parameter means the default of 128 octets -- not the value we
            # proposed. Carrying the proposal forward printed a negotiated
            # size the device never sent and sent DT TPDUs up to 8x the real
            # limit.
            self.cotp_tpdu_octets = 128
            self.tpdu_negotiated = ("absent from the CC, ISO 8073 default "
                                    "128 assumed")

        init = initiate if initiate is not None else mms_initiate_request()
        self.proposed = decode_initiate_response(
            first_tlv(init).value) if init else {}
        t0 = time.monotonic()
        self._send_cotp(session_connect(pres_cp_type(
            acse_aarq(init, self.direct_reference))), "session-connect")
        kind, cotp = self._recv_cotp()
        self.latencies.append({"step": "associate",
                               "ms": (time.monotonic() - t0) * 1000})
        if kind != "dt":
            raise BerError(f"expected COTP DT, got {kind}")
        skind, user_data = strip_session(cotp)
        if skind == "refuse":
            raise BerError("ISO session REFUSE")
        if skind != "accept":
            raise BerError(f"expected session ACCEPT, got {skind}")

        # A session-layer ACCEPT is not an association. A server that will not
        # associate, because its pool is full or it dislikes the proposed
        # parameters, accepts here and then refuses at the MMS layer with an
        # initiate-ErrorPDU. Treating ACCEPT as success inflates the
        # association count and makes a later release report slots never held.
        pdu = mms_from_accept(user_data)
        if pdu.is_(CONTEXT, PDU_INITIATE_ERROR):
            raise BerError(f"MMS initiate-Error, association refused: "
                           f"{pdu.value.hex()}")
        if not pdu.is_(CONTEXT, PDU_INITIATE_RESPONSE):
            raise BerError(f"no initiate-Response, got "
                           f"{PDU_NAMES.get(pdu.num, pdu.num)}")
        self.negotiated = decode_initiate_response(pdu.value)
        return self.negotiated

    def request(self, service, label="request"):
        self.invoke_id = (self.invoke_id + 1) & 0x7FFFFFFF
        pdu = confirmed_request(self.invoke_id, service)
        check_pdu_safety(pdu)
        t0 = time.monotonic()
        self._send_cotp(SESSION_DT + pres_user_data(pdu, MMS_CONTEXT_ID),
                        label)
        want = self.invoke_id
        # Read until the reply to THIS request arrives, setting aside any
        # unsolicited PDU that turns up on the way.
        for _ in range(64):
            kind, cotp = self._recv_cotp()
            if kind != "dt":
                raise BerError(f"expected COTP DT, got {kind}")
            skind, user_data = strip_session(cotp)
            if skind != "data":
                raise BerError(f"expected session data, got {skind}")
            answer = None
            for cid, pdu in mms_pdus_from_data(user_data):
                if pdu.is_(CONTEXT, PDU_UNCONFIRMED):
                    self.unsolicited.append({
                        "after": label, "contextId": cid,
                        "pdu": "unconfirmed-PDU", "hex": pdu.value.hex()})
                    continue
                got = pdu_invoke_id(pdu)
                if got is None or got == want:
                    answer = pdu
                    continue
                raise Desynchronised(
                    f"reply carries invokeID {got} but {want} was sent; the "
                    f"response stream is out of step and every later value "
                    f"would be attributed to the wrong object")
            if answer is not None:
                self.latencies.append(
                    {"step": label, "ms": (time.monotonic() - t0) * 1000})
                if self.progress:
                    self.progress(label)
                return answer
            # The frame held only unsolicited data; keep waiting for the
            # actual reply rather than returning a report as the answer.
        raise BerError("too many unsolicited PDUs while awaiting a reply")

    def send_raw_mms(self, mms_pdu, label="raw", context_id=None,
                     expect_reply=True, timeout=None):
        """Send an arbitrary MMS PDU on an arbitrary presentation context.

        Used by the gated probes, which need to put a well-formed PDU on an
        unexpected context id or send a PDU out of its normal state order.
        Returns the raw reassembled session user data, or None on timeout,
        because a probe's whole point may be that nothing comes back.
        """
        check_pdu_safety(mms_pdu)
        cid = MMS_CONTEXT_ID if context_id is None else context_id
        t0 = time.monotonic()
        self._send_cotp(SESSION_DT + pres_user_data(mms_pdu, cid), label)
        if not expect_reply:
            return None
        # Silence is often the expected answer here, so the caller can ask
        # for a shorter wait than the normal request timeout rather than
        # stalling the run on every probe that is supposed to get nothing.
        if timeout is not None:
            try:
                self.sock.settimeout(timeout)
            except Exception:
                pass
        try:
            kind, cotp = self._recv_cotp()
        except (socket.timeout, OSError):
            self.latencies.append({"step": label, "ms": None,
                                   "note": "no reply"})
            return None
        finally:
            if timeout is not None:
                try:
                    self.sock.settimeout(self.timeout)
                except Exception:
                    pass
        self.latencies.append({"step": label,
                               "ms": (time.monotonic() - t0) * 1000})
        if kind != "dt":
            return None
        try:
            skind, user_data = strip_session(cotp)
        except Exception:
            return None
        return user_data

    def service_call(self, service, label):
        """-> (service_number, value). Raises MmsServiceError on refusal."""
        return service_response(self.request(service, label))

    def close(self):
        if self.sock is None:
            return
        try:
            self._send_cotp(SESSION_DT + pres_user_data(
                CONCLUDE_REQUEST, MMS_CONTEXT_ID), "conclude")
            self.sock.settimeout(2.0)
            try:
                self._recv_tpkt()
            except Exception:
                pass
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None


def decode_initiate_response(value):
    out = {}
    for t in ber_tlvs(value):
        if t.is_(CONTEXT, 0):
            out["maxPduSize"] = int.from_bytes(t.value, "big")
        elif t.is_(CONTEXT, 1):
            out["maxOutstandingCalling"] = int.from_bytes(t.value, "big")
        elif t.is_(CONTEXT, 2):
            out["maxOutstandingCalled"] = int.from_bytes(t.value, "big")
        elif t.is_(CONTEXT, 3):
            out["nestingLevel"] = int.from_bytes(t.value, "big")
        elif t.is_(CONTEXT, 4):
            for d in ber_tlvs(t.value):
                if d.is_(CONTEXT, 0):
                    out["version"] = int.from_bytes(d.value, "big")
                elif d.is_(CONTEXT, 1):
                    idx, total = bitstring_indices(d.value)
                    out["parameterCbbRaw"] = d.value.hex()
                    out["parameterCbbBits"] = idx
                    out["parameterCbb"] = [
                        PARAM_SUPPORT[i] if i < len(PARAM_SUPPORT)
                        else f"bit{i}" for i in idx]
                elif d.is_(CONTEXT, 2):
                    idx, total = bitstring_indices(d.value)
                    out["servicesRaw"] = d.value.hex()
                    out["servicesBits"] = idx
                    out["servicesBitCount"] = total
                    out["services"] = [
                        SERVICES[i] if i < len(SERVICES) else f"reserved{i}"
                        for i in idx]
    return out


# ===========================================================================
#  Signature matching
# ===========================================================================

def load_signatures(path):
    """Load a signature table.

    Schema:
      {"signatures": [{"name": "...",
                       "required": "<hex service bitmap>",
                       "optional": "<hex mask of don't-care bits>",
                       "notes": "..."}]}

    Bitmaps are the ServiceSupportOptions content WITHOUT the leading
    unused-bit count. Bits set in 'optional' are ignored when comparing.

    No table ships with this tool. Shipping fabricated signatures would be
    worse than shipping none: the comparison is only as good as its corpus,
    and a wrong "nearest relative" reads as a finding. Build one from devices
    you can attest to, with --record.
    """
    data = json.loads(Path(path).read_text())
    sigs = data["signatures"] if isinstance(data, dict) else data
    out = []
    for s in sigs:
        req = bytes.fromhex(s["required"])
        opt = bytes.fromhex(s.get("optional", "")) or bytes(len(req))
        out.append({"name": s["name"], "required": req, "optional": opt,
                    "notes": s.get("notes", "")})
    return out


def service_bitmap(negotiated):
    """ServiceSupportOptions content with the unused-bit count stripped."""
    raw = negotiated.get("servicesRaw")
    if not raw:
        return None
    return bytes.fromhex(raw)[1:]


def signature_distances(observed, signatures):
    """Hamming distance per signature, ignoring don't-care bits."""
    out = []
    for sig in signatures:
        req, opt = sig["required"], sig["optional"]
        n = min(len(req), len(observed))
        dist, differing = 0, []
        for i in range(n):
            mask = ~opt[i] if i < len(opt) else 0xFF
            x = (observed[i] ^ req[i]) & mask & 0xFF
            for b in range(8):
                if x & (0x80 >> b):
                    dist += 1
                    idx = i * 8 + b
                    differing.append(SERVICES[idx] if idx < len(SERVICES)
                                     else f"reserved{idx}")
        out.append({"stack": sig["name"], "distance": dist,
                    "differing": differing, "notes": sig["notes"],
                    "compared_bytes": n})
    return sorted(out, key=lambda d: d["distance"])


# ===========================================================================
#  Object-name classification
# ===========================================================================

def classify_name(name, object_class=0, ln_classes=LN_CLASSES):
    """-> list of {signal, confidence, note}.

    Two signals with very different precision, reported separately rather than
    merged. A '$$' prefix is close to conclusive. An unfamiliar logical node
    class is weak: the class list cannot be complete, vendors add their own,
    and treating the two alike buries the strong signal under the weak one.
    """
    out = []
    printable = all(0x20 <= ord(c) <= 0x7E for c in name)
    if not printable:
        out.append({"signal": "non-printable characters",
                    "confidence": "high",
                    "note": "outside the IEC 61850 identifier character set"})
    if name.startswith("$$") or "$$" in name:
        out.append({"signal": "$$ in name", "confidence": "high",
                    "note": "vendor command-style object naming; these are "
                            "typically undocumented and sometimes writable"})
    if object_class not in (0, 1):
        # Only namedVariable(0) and scatteredAccess(1) names carry the
        # LN$FC$DO$DA structure. A domain is a bare identifier; a dataset
        # (namedVariableList, class 2, which IS in the default sweep) is
        # LLN0$name with no functional constraint in position 2 by
        # construction, so every dataset on every 61850 device used to
        # produce a false medium-confidence notable.
        return out
    if out:
        # Already conclusive. The structural checks below assume an
        # IEC 61850-shaped name and would add meaningless empty-string
        # complaints on top of a name that is plainly not one.
        return out

    parts = name.split("$")
    head = parts[0]
    if len(parts) >= 2 and parts[1] not in FUNCTIONAL_CONSTRAINTS:
        out.append({"signal": f"'{parts[1]}' is not an IEC 61850 functional "
                              f"constraint", "confidence": "medium",
                    "note": "second path element is normally an FC such as "
                            "ST, MX, CO, SP, CF or DC"})
    cls = head.rstrip("0123456789") or head
    if head.upper() != "LLN0" and cls.upper() not in ln_classes:
        out.append({"signal": f"'{head}' is not a known logical node class",
                    "confidence": "low",
                    "note": "the class list is not exhaustive and vendors add "
                            "their own; treat as a hint, not a finding"})
    return out


def highest_confidence(signals):
    order = {"high": 3, "medium": 2, "low": 1}
    return max((order.get(s["confidence"], 0) for s in signals), default=0)


# ===========================================================================
#  Probes
# ===========================================================================

NAMEPLATE_ITEMS = [
    ("LPHD1$DC$PhyNam$vendor", "vendor"),
    ("LPHD1$DC$PhyNam$hwRev", "hardware revision"),
    ("LPHD1$DC$PhyNam$swRev", "software revision"),
    ("LPHD1$DC$PhyNam$serNum", "serial number"),
    ("LPHD1$DC$PhyNam$model", "model"),
    ("LPHD1$DC$PhyNam$location", "location"),
    ("LLN0$DC$NamPlt$vendor", "LLN0 vendor"),
    ("LLN0$DC$NamPlt$swRev", "LLN0 software revision"),
    ("LLN0$DC$NamPlt$configRev", "configuration revision"),
    ("LLN0$DC$NamPlt$ldNs", "logical device namespace"),
]

NAMEPLATE_HINTS = ("PhyNam", "NamPlt", "swRev", "SwRev", "hwRev",
                   "vendor", "Vendor", "configRev", "serNum", "ldNs")


def enumerate_names(cli, object_class=0, domain=None, cap=20000,
                    max_rounds=200, log=None):
    """GetNameList with continuation.

    Loops until a round yields no new names. moreFollows is deliberately NOT
    the stopping condition: it is DEFAULT TRUE, so a server with more data may
    omit it, and stopping on absence truncates silently. It is recorded for
    reporting but not trusted for control flow.
    """
    names, seen, cont = [], set(), None
    rounds, truncated, declared_more = 0, None, None
    scope = f"domain {domain}" if domain else "VMD"
    status = getattr(log, "status", None)
    while rounds < max_rounds and len(names) < cap:
        rounds += 1
        if status:
            status(f"  enumerating {OBJECT_CLASSES.get(object_class, object_class)}"
                   f" at {scope}: round {rounds}, {len(names)} name(s)")
        try:
            num, value = cli.service_call(
                req_get_name_list(object_class, domain, cont),
                f"getNameList(class={object_class},domain={domain})")
        except MmsServiceError as e:
            # A refusal part way through is not the end of the list. Saying
            # so is the difference between a clean negative and an unknown.
            truncated = f"refused mid-enumeration after {len(names)}: {e}"
            break
        except (socket.timeout, OSError, BerError) as e:
            truncated = f"transport error after {len(names)}: {e}"
            break
        got, declared_more = decode_name_list(value)
        new = [g for g in got if g not in seen]
        if not new:
            if declared_more:
                truncated = ("a round returned no new names while the device "
                             "declared moreFollows TRUE; continueAfter "
                             "semantics may differ from resume-after-this-name")
            break
        seen.update(new)
        names.extend(new)
        cont = got[-1] if got else new[-1]
    if truncated:
        pass
    elif rounds >= max_rounds:
        truncated = f"stopped at the {max_rounds}-round limit"
    elif len(names) >= cap:
        truncated = f"stopped at the {cap}-name cap"
    elif declared_more:
        truncated = "the device still declared moreFollows TRUE at exit"
    if truncated and log:
        log(f"    enumeration incomplete: {truncated}")
    return {"names": names, "rounds": rounds, "truncated": truncated,
            "lastDeclaredMoreFollows": declared_more}


def read_item(cli, domain, item):
    """One Read. Refuses control attributes unconditionally."""
    refuse_control_attr(item)
    num, value = cli.service_call(req_read(domain, item),
                                  f"read({domain}/{item})")
    return decode_read_response(value)


CTL_MODEL = {
    0: "status-only",
    1: "direct-with-normal-security",
    2: "sbo-with-normal-security",
    3: "direct-with-enhanced-security",
    4: "sbo-with-enhanced-security",
}


def ctl_model_paths(names):
    """Control objects seen under FC=CO -> their FC=CF ctlModel paths.

    `GGIO1$CO$SPCSO1$SBOw` yields `GGIO1$CF$SPCSO1$ctlModel`.

    Reading ctlModel is safe: the functional constraint is CF, configuration,
    not CO. It is the FC=CO attributes that carry the control model, and
    reading $SBO there performs a SELECT. This reads the configuration that
    *describes* the control model without touching the model itself.
    """
    out = []
    seen = set()
    for n in names:
        parts = n.split("$")  # noqa: E501
        if len(parts) < 3 or parts[1] != "CO":
            continue
        path = f"{parts[0]}$CF${parts[2]}$ctlModel"
        if path not in seen:
            seen.add(path)
            out.append((f"{parts[0]}${parts[2]}", path))
    return out


def probe_ctl_models(cli, domain, names, log=None):
    """Which control objects exist, and how each expects to be operated.

    On a bay controller this is the single most operationally relevant
    read-only fact available: it says which switches require
    Select-before-Operate and which accept a direct Operate. It also tells
    you which objects a careless FC=CO read would have reserved.
    """
    out = []
    paths = ctl_model_paths(names)
    status = getattr(log, "status", None)
    for i, (label, path) in enumerate(paths, 1):
        if status:
            status(f"  reading ctlModel {i}/{len(paths)}: {label}")
        try:
            vals = read_item(cli, domain, path)
        except (MmsServiceError, Refused, BerError):
            continue
        except Exception:
            continue
        if not vals:
            continue
        v = vals[0]
        if isinstance(v, dict):
            continue
        try:
            n = int(v)
        except (TypeError, ValueError):
            continue
        rec = {"object": label, "path": path, "ctlModel": n,
               "meaning": CTL_MODEL.get(n, f"unknown-{n}"),
               "selectRequired": n in (2, 4)}
        out.append(rec)
    # No per-object line here: the caller renders these as a column-aligned
    # table. Printing them again with a fixed :34 field misaligned every row
    # whose object name was longer than that.
    return out


def file_directory(cli, path=None, limit=500, log=None):
    """FileDirectory with continuation. moreFollows is DEFAULT FALSE here."""
    entries, cont, rounds, truncated = [], None, 0, None
    seen = set()
    status = getattr(log, "status", None)
    while rounds < 50 and len(entries) < limit:
        rounds += 1
        if status:
            status(f"  listing files: round {rounds}, {len(entries)} entry/entries")
        try:
            num, value = cli.service_call(req_file_directory(path, cont),
                                          "fileDirectory")
        except (socket.timeout, OSError, BerError) as e:
            truncated = f"transport error after {len(entries)}: {e}"
            break
        got, more = decode_file_directory(value)
        # Deduplicate: a device that ignores continueAfter and resends the
        # same entry would otherwise be reported as a filestore with 50
        # files in it, which is a false number in a report.
        fresh = [e for e in got if e.get("name") not in seen]
        if not fresh:
            if got:
                truncated = ("the device resent entries already seen; "
                             "continueAfter is not advancing")
            break
        seen.update(e.get("name") for e in fresh)
        entries.extend(fresh)
        if not more:
            break
        cont = fresh[-1].get("name")
        if not cont:
            truncated = "no usable continuation anchor in the last entry"
            break
    if truncated:
        pass
    elif rounds >= 50:
        truncated = "stopped at the 50-round limit"
    elif len(entries) >= limit:
        truncated = f"stopped at the {limit}-entry limit"
    if truncated and log:
        log(f"    listing incomplete: {truncated}")
    return {"entries": entries[:limit], "truncated": truncated}


def reduced_osi_probe(host, port, initiate, timeout, recorder,
                      tpdu_size=0x0A):
    """Does the server accept MMS directly over COTP, with no session,
    presentation or ACSE layer?

    Read-only and conformant: the PDU is a normal Initiate, only the
    framing below it is unusual.
    """
    check_target(host)
    out = {}
    s = socket.create_connection((host, port), timeout)
    try:
        s.settimeout(timeout)
        frame = cotp_cr(tpdu_size=tpdu_size)
        recorder.append({"dir": "tx", "label": "reduced:cotp-cr",
                         "hex": frame.hex()})
        s.sendall(frame)
        cc = s.recv(2048)
        recorder.append({"dir": "rx", "label": "reduced:cotp-cc",
                         "hex": cc.hex()})
        if not cc or len(cc) < 6 or cc[5] != 0xD0:
            out["error"] = "COTP connect refused"
            return out
        frame = cotp_dt(initiate)
        recorder.append({"dir": "tx", "label": "reduced:mms-initiate",
                         "hex": frame.hex()})
        s.sendall(frame)
        try:
            resp = s.recv(8192)
        except socket.timeout:
            resp = b""
        recorder.append({"dir": "rx", "label": "reduced:response",
                         "hex": resp.hex()})
        out["responseBytes"] = len(resp)
        out["responseHex"] = resp.hex()
        # bool(resp) was true for an initiate-Error and for a COTP Disconnect
        # Request, so the tool asserted "two independent parse paths exist"
        # for a refusal. Only a parsed initiate-ResponsePDU counts.
        out["answered"] = False
        out["outcome"] = "silence" if not resp else "unparsed"
        if resp:
            try:
                kind, cotp, _ = strip_tpkt_cotp(resp)
                pdu = first_tlv(cotp)
                if kind != "dt":
                    out["outcome"] = f"cotp-{kind}"
                elif pdu is not None:
                    out["pduType"] = PDU_NAMES.get(pdu.num, f"pdu-{pdu.num}")
                    if pdu.is_(CONTEXT, PDU_INITIATE_RESPONSE):
                        out["answered"] = True
                        out["outcome"] = "initiate-Response"
                        out["negotiated"] = decode_initiate_response(pdu.value)
                    elif pdu.is_(CONTEXT, PDU_INITIATE_ERROR):
                        out["outcome"] = "initiate-Error"
                    elif pdu.is_(CONTEXT, PDU_REJECT):
                        out["outcome"] = "rejectPDU"
                    else:
                        out["outcome"] = out["pduType"]
            except Exception as e:
                out["parseError"] = str(e)
    finally:
        # Always release, including when nothing came back: the slot may
        # still have been allocated, and leaking it is the exact behaviour
        # this assessment criticises in other clients.
        try:
            s.sendall(cotp_dt(CONCLUDE_REQUEST))
            s.settimeout(2.0)
            s.recv(2048)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    return out


# ===========================================================================
#  Gated probes
# ===========================================================================
#
# Each of these either holds a resource the device needs, or deliberately
# deviates from the protocol to see how the implementation reacts. They are
# the reason --lab exists. Every one is individually named in --probes so
# nothing runs by accident, and every one reports what it did rather than
# just whether it "worked".

LAB_PROBES = {}


# What a probe needs collected before it can run. A probe that needs only
# the association should not pay for a full data-model sweep to get there.
LAB_NEEDS = {"none": 0, "domains": 1, "objects": 2}


def lab_probe(name, risk, summary, needs="none"):
    def deco(fn):
        LAB_PROBES[name] = {"fn": fn, "risk": risk, "summary": summary,
                            "needs": needs}
        return fn
    return deco


@lab_probe("services", "low",
           "probe every MMS service, declared or not, and compare the "
           "answers against the Initiate bitmap", needs="none")
def probe_declared_vs_actual(cli, args, R, out):
    """A declared service that refuses, or an undeclared one that answers.

    The Initiate bitmap is a self-declaration. Both directions of mismatch
    are interesting: a service the device denies declaring but still
    implements is reachable code nobody audits, and a declared service that
    rejects every call suggests the bitmap is a copied constant rather than a
    description of this build.

    Sends each service with an empty or minimal body, so most answers will be
    an error or a reject. The answer KIND is the signal, not success.
    """
    declared = set(R["negotiated"].get("services", []))
    # Only services whose invocation cannot change or destroy anything. The
    # previous version swept every number up to 77, which put fileDelete,
    # deleteDomain, kill, stop, reset and a dozen other handlers on the wire
    # at risk label "low", protected by nothing except the argument parser
    # happening to reject an empty body. fileDelete's body is a FileName, a
    # SEQUENCE OF GraphicString, and an empty SEQUENCE OF is valid.
    probe_set = [(n, i) for i, n in enumerate(SERVICES)
                 if i in READ_ONLY_SERVICES]
    skipped = sorted(SERVICES[i] for i in DESTRUCTIVE_SERVICES
                     if i < len(SERVICES))
    out.info(f"probing {len(probe_set)} read-only services; "
             f"{len(skipped)} destructive service numbers are never sent")
    findings, rows = [], []
    status = getattr(out, "status", None)
    dead = 0
    for idx, (name, num) in enumerate(probe_set, 1):
        if dead >= 5:
            out.flag("association appears dead; abandoning the sweep rather "
                     "than reporting a clean negative")
            rows.append(("<aborted>", False, "aborted",
                         "association down after repeated no-replies"))
            break
        if status:
            status(f"  probing service {idx}/{len(probe_set)}: {name}")
        body = b"\x00" if num == 0 else b""
        # status(0) and identify(2) are primitive; getDomainAttributes(37)
        # carries a bare Identifier so it is primitive too. The rest are
        # constructed SEQUENCEs.
        constructed = num not in (0, 2, 37)
        try:
            pdu = cli.request(ctx(num, body, constructed=constructed),
                              f"probe:{name}")
        except (socket.timeout, OSError, BerError) as e:
            dead += 1
            rows.append((name, name in declared, "no-reply", str(e)[:40]))
            continue
        dead = 0
        if pdu.is_(CONTEXT, PDU_REJECT):
            kind, detail = "reject", decode_reject(pdu.value)
        elif pdu.is_(CONTEXT, PDU_CONFIRMED_ERROR):
            kind, detail = "error", decode_error(pdu.value)
        elif pdu.is_(CONTEXT, PDU_CONFIRMED_RESPONSE):
            kind, detail = "response", "answered"
        else:
            kind, detail = PDU_NAMES.get(pdu.num, str(pdu.num)), ""
        rows.append((name, name in declared, kind, detail))
        unrecognised = "unrecognized-service" in detail
        if name not in declared and not unrecognised and kind != "no-reply":
            findings.append({"service": name, "declared": False,
                             "observed": kind, "detail": detail,
                             "note": "undeclared but did not report "
                                     "unrecognized-service"})
        if name in declared and unrecognised:
            findings.append({"service": name, "declared": True,
                             "observed": kind, "detail": detail,
                             "note": "declared but reports "
                                     "unrecognized-service"})
    out(f"    probed {len(rows)} read-only services")
    for f in findings:
        out.flag(f"{f['service']}: {f['note']}", indent=4)
    aborted = any(r[0] == "<aborted>" for r in rows)
    if not findings and not aborted:
        out.ok("no declared-versus-actual mismatches among read-only services",
               indent=4)
    elif aborted:
        out.flag("sweep incomplete: no conclusion about the remaining "
                 "services", indent=4)
    return {"rows": [{"service": a, "declared": b, "kind": c, "detail": d}
                     for a, b, c, d in rows], "mismatches": findings,
            "aborted": aborted, "probedReadOnlyOnly": True,
            "neverSent": skipped}


@lab_probe("ctxid", "low",
           "send a well-formed MMS PDU on an undeclared presentation "
           "context id", needs="none")
def probe_context_id(cli, args, R, out):
    """Does the presentation layer validate the context id?

    The association declared exactly two presentation contexts, 1 for ACSE
    and 3 for MMS. A PDU arriving on any other id should be refused by the
    presentation layer before MMS sees it. An implementation that instead
    dispatches on content, ignoring the id, has no context check at all, and
    that check is the gate protecting everything above it.

    The PDU itself is a perfectly legal Identify. Only the context id is
    wrong, so a server that answers has told you something specific.
    """
    results = {}
    for cid in (0, 2, 4, 99):
        ud = cli.send_raw_mms(req_identify_pdu(cli), f"ctxid:{cid}",
                              context_id=cid,
                              timeout=min(2.0, args.timeout))
        if ud is None:
            results[cid] = {"answered": False}
            out(f"    context id {cid:3}: no reply (expected)")
            continue
        try:
            pdu = mms_from_data(ud)
            name = PDU_NAMES.get(pdu.num, f"pdu-{pdu.num}")
        except Exception:
            results[cid] = {"answered": True, "parsed": False,
                            "raw": ud.hex()[:120]}
            out(f"    context id {cid:3}: ANSWERED, unparsed: {ud.hex()[:40]}")
            continue
        processed = pdu.is_(CONTEXT, PDU_CONFIRMED_RESPONSE)
        results[cid] = {"answered": True, "pdu": name, "processed": processed}
        flag = "  <-- PROCESSED, no context-id validation" if processed else ""
        out(f"    context id {cid:3}: {name}{flag}")
    answered = [c for c, r in results.items() if r.get("processed")]
    return {"byContextId": results, "processedOn": answered,
            "finding": bool(answered)}


@lab_probe("error-append", "low",
           "measure how much the error response grows per failing item",
           needs="domains")
def probe_error_growth(cli, args, R, out):
    """Response growth per failing item in one request.

    A server that builds its error response by appending per-item detail into
    a buffer sized for the common case grows linearly until it does not. This
    measures the growth rate with a handful of items, which is enough to
    establish the per-item cost and whether the server bounds the total,
    without going anywhere near a size that could matter.

    It is the precondition, measured. It is not an attempt to exceed it.
    """
    dom = (R["domains"] or [None])[0]
    if dom is None:
        out("    no domain to address; skipped")
        return {"skipped": "no domain"}
    sizes = {}
    for n in (1, 2, 4, 8):
        var = b"".join(
            univ(16, ctx(0, obj_name_domain(dom, f"NOSUCHOBJ{i}$ST$x")))
            for i in range(n))
        try:
            pdu = cli.request(ctx(SVC["read"], ctx(1, ctx(0, var))),
                              f"error-append:{n}")
        except Exception as e:
            out(f"    {n} items: {e}")
            continue
        sizes[n] = len(pdu.value)
        out(f"    {n:2} failing item(s): response body {len(pdu.value):5} bytes")
    if len(sizes) >= 2:
        ks = sorted(sizes)
        per = [(sizes[b] - sizes[a]) / (b - a)
               for a, b in zip(ks, ks[1:])]
        out(f"    growth per item: {[round(x, 1) for x in per]} bytes")
        if per and max(per) - min(per) > 2:
            out("    growth is NOT linear; the server bounds or batches it")
    return {"sizes": sizes}


@lab_probe("pdu", "medium",
           "send a request larger than the negotiated maximum PDU size",
           needs="none")
def probe_pdu_boundary(cli, args, R, out):
    """How is an oversized request handled?

    The device declared a maximum PDU size during Initiate. A conformant
    server rejects anything larger cleanly. The interesting answers are a
    silent truncation, a dropped association, or a reply that indicates the
    size was never checked.

    Oversize is reached with a long but entirely legal continueAfter
    identifier, so the PDU is well-formed; only its length is out of bounds.
    """
    limit = R["negotiated"].get("maxPduSize") or 32000
    # A GetNameList identifier is the longest legal single field available,
    # but BER definite length caps what can be encoded here, so very large
    # declared limits cannot be reached this way. Say so rather than
    # labelling a clamped request "over-limit" when it is not.
    results, cap = {}, 60000
    for frac, label in ((0.5, "half"), (1.0, "at-limit"),
                        (1.2, "over-limit")):
        size = max(1, int(limit * frac))
        clamped = size > cap
        ident = b"A" * min(size, cap)
        if clamped:
            out(f"    {label:11}: wanted {size} B but the identifier is "
                f"capped at {cap} B; not a true {label} test")
        try:
            pdu = cli.request(req_get_name_list(0, None, ident),
                              f"pdu:{label}")
            name = PDU_NAMES.get(pdu.num, str(pdu.num))
            detail = (decode_reject(pdu.value) if pdu.num == PDU_REJECT
                      else decode_error(pdu.value)
                      if pdu.num == PDU_CONFIRMED_ERROR else "answered")
            results[label] = {"bytes": len(ident), "wanted": size,
                              "clamped": clamped, "pdu": name,
                              "detail": detail}
            out(f"    {label:11} ({len(ident):6} B identifier): "
                f"{name} {detail[:50]}")
        except Exception as e:
            results[label] = {"bytes": len(ident), "error": str(e)[:80]}
            out(f"    {label:11} ({len(ident):6} B identifier): {e}")
            break
    return results


AUTHZ_OUTCOMES = {
    "ok": "data returned",
    "denied": "access denied",
    "nonexistent": "object does not exist",
    "type-error": "wrong type for this selector",
    "other-error": "some other access error",
    "refused": "service-level refusal",
    "transport": "transport error",
}


def _classify_read(result):
    """One read's outcome, reduced to a comparable class."""
    if isinstance(result, str):
        return ("transport", result) if "ERROR" in result else ("refused", result)
    if not result:
        return "other-error", "empty response"
    first = result[0]
    if isinstance(first, dict) and "failure" in first:
        f = first["failure"]
        if f in ("object-access-denied",):
            return "denied", f
        if f in ("object-non-existent", "object-undefined"):
            return "nonexistent", f
        if f in ("type-inconsistent", "type-unsupported", "invalid-address",
                 "object-attribute-inconsistent"):
            return "type-error", f
        return "other-error", f
    return "ok", "data"


def _read_paths(cli, domain, item):
    """The same object by three access paths. Reads only, nothing written."""
    paths = {
        "whole": None,
        "index0": alternate_access(aa_index(0)),
        "range0_2": alternate_access(aa_index_range(0, 2)),
    }
    out = {}
    for label, alt in paths.items():
        try:
            num, value = cli.service_call(req_read(domain, item, alt),
                                          f"authz:{label}:{item}")
            out[label] = _classify_read(decode_read_response(value))
        except Refused as e:
            out[label] = ("refused", f"guard: {e}")
        except MmsServiceError as e:
            out[label] = ("refused", str(e)[:70])
        except (socket.timeout, OSError, BerError) as e:
            out[label] = ("transport", str(e)[:70])
    return out


@lab_probe("authz-matrix", "low",
           "read each object by name, by index and by index range, and "
           "report any object where the three paths disagree",
           needs="objects")
def probe_authz_matrix(cli, args, R, out):
    """Does the access check live on only one of the read paths?

    A published authorization bypass in a different stack had whole-object
    and single-element WRITES denied while the same change through an
    indexRange write succeeded, because the range path is a separate function
    and the check existed only in the other one. Nothing requires the write
    side to demonstrate that split: if a range READ returns data where a
    plain read returns access-denied, the check is missing on one path and
    not a byte has changed on the device.

    Everything here is a read. The probe refuses to conclude unless it has
    first proved its own alternateAccess encoding works on THIS device,
    because otherwise a denial is indistinguishable from a tool bug.
    """
    names = []
    for key, res in R["objects"].items():
        if not key.endswith("/namedVariable"):
            continue
        scope = key.split("/")[0]
        if scope == "vmd":
            continue
        for n in res.get("names", []):
            names.append((scope, n))
    if not names:
        out.skip("no enumerated objects to test; run without --quiet and "
                 "with at least the default scope first")
        return {"skipped": "no objects"}

    # Self-calibration. Without this, "every range read was denied" is as
    # likely to mean the encoder is wrong as that the device is strict.
    out.status("  calibrating the alternateAccess encoding")
    calibrated, calib_note = False, "no object accepted a selector read"
    cap = args.shape_samples or len(names)
    for dom, item in names[:cap]:
        try:
            refuse_control_attr(item)
        except Refused:
            continue
        paths = _read_paths(cli, dom, item)
        if paths["whole"][0] == "ok" and paths["index0"][0] in ("ok",
                                                                "type-error"):
            calibrated = True
            calib_note = (f"{dom}/{item}: whole={paths['whole'][0]} "
                          f"index0={paths['index0'][0]}")
            break
    if calibrated:
        out.ok(f"alternateAccess encoding accepted by this device "
               f"({calib_note})", indent=4)
    else:
        out.flag(f"could NOT calibrate: {calib_note}", indent=4)
        out.note("Every selector read below may be failing because of this "
                 "tool rather than because of the device, so no conclusion "
                 "is drawn from a denial.", indent=4)

    rows, splits, skipped_co = [], [], 0
    total = min(len(names), args.authz_max)
    for i, (dom, item) in enumerate(names[:total], 1):
        try:
            refuse_control_attr(item)
        except Refused:
            skipped_co += 1
            continue
        out.status(f"  authz matrix {i}/{total}: {item}")
        paths = _read_paths(cli, dom, item)
        row = {"domain": dom, "item": item,
               **{k: {"outcome": v[0], "detail": v[1]}
                  for k, v in paths.items()}}
        rows.append(row)
        w, ix, rg = (paths["whole"][0], paths["index0"][0],
                     paths["range0_2"][0])
        # The finding is narrow on purpose: a selector read SUCCEEDING where
        # the plain read was DENIED. A selector failing on a non-array object
        # is correct behaviour, not a split.
        if w == "denied" and (ix == "ok" or rg == "ok"):
            row["finding"] = ("plain read denied but a selector read "
                              "returned data")
            splits.append(row)
    out.clear_status()

    out(f"    tested {len(rows)} object(s)"
        + (f", skipped {skipped_co} under FC=CO" if skipped_co else ""))
    agg = {}
    for r in rows:
        key = (r["whole"]["outcome"], r["index0"]["outcome"],
               r["range0_2"]["outcome"])
        agg[key] = agg.get(key, 0) + 1
    out.table(["whole", "index0", "range0_2", "objects"],
              [[a, b, c, n] for (a, b, c), n in
               sorted(agg.items(), key=lambda kv: -kv[1])], indent=4)
    if splits:
        for r in splits:
            out.alert(f"{r['domain']}/{r['item']}: {r['finding']}", indent=4)
            out.info(f"whole={r['whole']['detail']}  "
                     f"index0={r['index0']['detail']}  "
                     f"range={r['range0_2']['detail']}", indent=10)
        out.note("This is an incorrect-authorization finding and no byte was "
                 "written. Capture the raw hex from the evidence file for "
                 "each one.", indent=4)
    elif calibrated:
        out.ok("no object was readable by a selector while denied by name",
               indent=4)
    else:
        out.flag("no conclusion: the encoding was never calibrated", indent=4)
    return {"rows": rows, "splits": splits, "calibrated": calibrated,
            "calibrationNote": calib_note, "skippedControlObjects": skipped_co}


def req_identify_pdu(cli):
    """A full confirmed-request PDU for Identify, for the raw-send paths."""
    cli.invoke_id = (cli.invoke_id + 1) & 0x7FFFFFFF
    return confirmed_request(cli.invoke_id, req_identify())


def probe_assoc_pool(args, R, out, recorder, make_init):
    """How many concurrent associations will the device accept?

    This is the only probe that needs more than one association, and the one
    with real consequence: while the slots are held, the device has none left
    for anyone else, including whatever normally polls it. Every association
    is released with a proper Conclude, and the function verifies the pool
    came back before returning.

    Run it when you can tolerate the device being unreachable for the few
    seconds it takes, and not otherwise.
    """
    held, refused_at, err = [], None, None
    try:
        for i in range(args.pool_max):
            c = MmsClient(args.host, args.port, args.timeout,
                          rate=args.rate, recorder=recorder,
                          tpdu_size=args.tpdu_size,
                          direct_reference=not args.no_direct_reference,
                          progress=getattr(out, "tick", None))
            try:
                c.connect(make_init())
            except Exception as e:
                refused_at = i + 1
                err = str(e)[:120]
                break
            held.append(c)
            out.status(f"  pool: {i + 1} association(s) held")
            out.info(f"association {i + 1} established", indent=4)
    finally:
        out(f"    releasing {len(held)} association(s) with Conclude")
        for c in held:
            try:
                c.close()
            except Exception:
                pass
    recovered = None
    if held:
        time.sleep(args.settle)
        probe = MmsClient(args.host, args.port, args.timeout,
                          recorder=recorder, tpdu_size=args.tpdu_size,
                          direct_reference=not args.no_direct_reference)
        try:
            probe.connect(make_init())
            recovered = True
            probe.close()
        except Exception as e:
            recovered = False
            err = (err or "") + f" | recovery failed: {str(e)[:80]}"
    out(f"    accepted {len(held)}"
        + (f", refused at {refused_at}" if refused_at else "")
        + (f", pool recovered: {recovered}" if recovered is not None else ""))
    if recovered is False:
        out("    *** the pool did NOT come back. The device needs attention "
            "before anything else is run against it. ***")
    return {"accepted": len(held), "refusedAt": refused_at,
            "recovered": recovered, "error": err}


# ===========================================================================
#  Advisory matching
# ===========================================================================
#
# Many protocol-stack vulnerabilities have no reachable trigger: the vendor
# publishes an affected version range and nothing else. For those the version
# reading IS the finding, and the right tool behaviour is to read the version
# carefully and compare it against a range you supply.
#
# No advisory data ships with this tool, for the same reason no signature
# table does.

def parse_version(s):
    """'11.00.01.30' -> (11, 0, 1, 30).

    Splits on dots only, and takes the leading digits of each component, so
    a git-describe tail like '1.6.2.1-89-gabc' yields (1, 6, 2, 1) rather
    than silently folding the commit count in as a fifth component. A
    component with no leading digit ends the version.
    """
    out = []
    for part in str(s).strip().split("."):
        mm = re.match(r"^(\d+)", part)
        if not mm:
            break
        out.append(int(mm.group(1)))
    return tuple(out)


def version_in_range(v, lo, hi):
    """Inclusive compare on dotted tuples, zero-padded to equal length.

    Padding matters: an advisory whose bound reads '2.2.6' and a device
    reporting '2.2.6.0' describe the same release, but a naive tuple compare
    sorts the shorter one first and would call the device out of range.
    """
    n = max(len(v), len(lo or ()), len(hi or ()))
    pad = lambda x: tuple(list(x) + [0] * (n - len(x)))
    vv = pad(v)
    if lo and vv < pad(lo):
        return False
    if hi and vv > pad(hi):
        return False
    return True


def load_advisories(path):
    data = json.loads(Path(path).read_text())
    return data["advisories"] if isinstance(data, dict) else data


def match_advisories(advisories, identify, nameplate):
    """-> list of {advisory, verdict, because, notes}.

    verdict is IN_RANGE, OUT_OF_RANGE or INDETERMINATE. INDETERMINATE is a
    real answer rather than a failure: when the version cannot be extracted
    from the field an advisory names, saying so beats guessing, and an
    undefined comparison does not discharge a finding.
    """
    fields = dict(identify or {})
    for k, v in (nameplate or {}).items():
        val = v[0] if isinstance(v, list) and v else v
        # A nameplate key looks like 'LD/LPHD1$DC$PhyNam$swRev'. Register the
        # whole key, the part after the last '/', and the leaf after the last
        # '$', so an advisory can name whichever is natural.
        for alias in {k, k.split("/")[-1], k.split("$")[-1]}:
            fields.setdefault(alias, val)
    out = []
    for adv in advisories:
        aid = adv.get("id", "<unnamed>")
        why, ok, unknown = [], True, False
        for field, pattern in (adv.get("match") or {}).items():
            val = fields.get(field)
            # An ABSENT field and a field that does not match are different
            # answers. A device that never reported the field the advisory
            # keys on has not been shown to be out of range; it has not been
            # compared at all. Collapsing the two would report "out of
            # range" for a device whose version was never read, which is the
            # one wrong answer that matters.
            if val is None:
                unknown = True
                why.append(f"{field} is absent from this device, so the "
                           f"comparison cannot be made")
                break
            if not re.search(pattern, str(val), re.I):
                ok = False
                why.append(f"{field}={val!r} does not match /{pattern}/")
                break
            why.append(f"{field}={val!r} matches /{pattern}/")
        if unknown:
            out.append({"advisory": aid, "verdict": "INDETERMINATE",
                        "because": why, "notes": adv.get("notes", "")})
            continue
        if not ok:
            out.append({"advisory": aid, "verdict": "OUT_OF_RANGE",
                        "because": why, "notes": adv.get("notes", "")})
            continue
        vr = adv.get("versionRange")
        if not vr:
            out.append({"advisory": aid, "verdict": "IN_RANGE",
                        "because": why + ["no version range given"],
                        "notes": adv.get("notes", "")})
            continue
        raw = fields.get(vr.get("field", "revision"))
        if raw is None:
            out.append({"advisory": aid, "verdict": "INDETERMINATE",
                        "because": why + [f"field {vr.get('field')} absent"],
                        "notes": adv.get("notes", "")})
            continue
        text = str(raw)
        if vr.get("extract"):
            m = re.search(vr["extract"], text)
            if not m:
                out.append({"advisory": aid, "verdict": "INDETERMINATE",
                            "because": why + [f"/{vr['extract']}/ did not "
                                              f"match {text!r}"],
                            "notes": adv.get("notes", "")})
                continue
            text = m.group(1) if m.groups() else m.group(0)
        # A version that will not parse, and a BOUND that will not parse, are
        # both undefined comparisons. Previously the first produced an empty
        # tuple whose falsiness fell through to OUT_OF_RANGE -- reading as
        # "unaffected" -- and the second silently became "no bound", making
        # everything IN_RANGE while the printed reasoning showed a bound the
        # comparison never used.
        v = parse_version(text)
        if not v:
            out.append({"advisory": aid, "verdict": "INDETERMINATE",
                        "because": why + [f"{text!r} is not a dotted "
                                          f"version; use an extract regex"],
                        "notes": adv.get("notes", "")})
            continue
        bad = []
        lo = hi = None
        if vr.get("from"):
            lo = parse_version(vr["from"])
            if not lo:
                bad.append(f"lower bound {vr['from']!r} is unparseable")
        if vr.get("to"):
            hi = parse_version(vr["to"])
            if not hi:
                bad.append(f"upper bound {vr['to']!r} is unparseable")
        if bad:
            out.append({"advisory": aid, "verdict": "INDETERMINATE",
                        "because": why + bad,
                        "notes": adv.get("notes", "")})
            continue
        inr = version_in_range(v, lo, hi)
        why.append(f"version {text!r} -> {v}, range "
                   f"{vr.get('from', '*')}..{vr.get('to', '*')}")
        out.append({"advisory": aid,
                    "verdict": "IN_RANGE" if inr else "OUT_OF_RANGE",
                    "because": why, "notes": adv.get("notes", ""),
                    "fixedIn": adv.get("fixedIn")})
    return out


# ===========================================================================
#  Reporting
# ===========================================================================

class Report:
    """Terminal output: live progress while working, aligned results after.

    Three things make this more than cosmetic on a long sweep. Enumeration
    across ten object classes and several logical devices can run for a while
    with nothing to say, and a tool that goes silent is indistinguishable from
    one that has hung. Findings need to be visually separable from the
    narration around them, because a flagged object in a wall of grey is a
    findng nobody reads. And every one of those effects has to vanish when the
    output is not a terminal, so that piping to a file or a pager produces
    clean text rather than escape sequences.

    Transient status lines are written with a carriage return and erased
    before anything permanent is printed, so a captured log never contains a
    half-overwritten progress line.
    """

    RESET = "\033[0m"
    STYLES = {
        "bold": "\033[1m", "dim": "\033[2m",
        "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
        "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
        "brred": "\033[91m", "brgreen": "\033[92m",
        "bryellow": "\033[93m", "brcyan": "\033[96m",
    }

    def __init__(self, quiet=False, color=None, stream=None, tee=None):
        self.quiet = quiet
        self.stream = stream or sys.stdout
        # The saved log is the primary artefact, so it keeps the colour: a
        # plain-text dump of a coloured report loses the markers that make a
        # finding findable. When a tee is active colour is forced on unless
        # it was explicitly disabled, so the file and the terminal agree.
        self.tee_fh = None
        if tee:
            try:
                Path(tee).parent.mkdir(parents=True, exist_ok=True)
                self.tee_fh = open(tee, "w", encoding="utf-8")
                if color is None:
                    color = True
            except Exception as e:
                print(f"[!] cannot write {tee}: {e}", file=sys.stderr)
        try:
            self.tty = self.stream.isatty()
        except Exception:
            self.tty = False
        self.color = self._decide_color(color)
        self.unicode = self._can_encode("\u2500\u2501\u2714\u25c6\u2026")
        self._status = ""
        self._t0 = time.monotonic()
        self._requests = 0

    # -- capability detection -------------------------------------------
    def _decide_color(self, explicit):
        if explicit is True:
            return True
        if explicit is False:
            return False
        # NO_COLOR is honoured whatever its value, per the informal standard.
        if os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("TERM", "") in ("dumb", ""):
            return False
        return self.tty

    def _can_encode(self, s):
        enc = getattr(self.stream, "encoding", None) or "ascii"
        try:
            s.encode(enc)
            return True
        except (UnicodeEncodeError, LookupError):
            return False

    def _width(self):
        if not self.tty:
            return 76
        try:
            return max(50, min(110, shutil.get_terminal_size((76, 24)).columns))
        except Exception:
            return 76

    def c(self, text, *styles):
        if not self.color or not styles:
            return str(text)
        pre = "".join(self.STYLES.get(s, "") for s in styles)
        return f"{pre}{text}{self.RESET}" if pre else str(text)

    # Marker glyphs. Kept as named constants and resolved OUTSIDE the
    # f-strings that use them: a backslash inside an f-string expression is
    # a syntax error before Python 3.12 (PEP 701 relaxed it), and this tool
    # should run on whatever Python an OT environment already has rather
    # than requiring a recent one.
    G_OK = ("\u2714", "+")
    G_INFO = ("\u00b7", ".")
    G_FLAG = ("\u25b2", "!")
    G_ALERT = ("\u25c6", "*")
    G_SKIP = ("\u2014", "-")
    G_RULE = ("\u2500", "-")
    G_HEAD = ("\u2501", "=")
    G_ELLIPSIS = ("\u2026", "~")

    def _glyph(self, uni, ascii_=None):
        """Accepts either a (unicode, ascii) pair or the two separately."""
        if ascii_ is None and isinstance(uni, tuple):
            uni, ascii_ = uni
        return uni if self.unicode else ascii_

    # -- transient progress ---------------------------------------------
    def status(self, msg):
        """A line that will be overwritten. Only on a terminal."""
        if self.quiet or not self.tty:
            return
        w = self._width() - 1
        ell = self._glyph(self.G_ELLIPSIS)
        line = msg if len(msg) <= w else msg[:w - 1] + ell
        pad = max(0, len(self._status) - len(line))
        self.stream.write("\r" + self.c(line, "dim") + " " * pad)
        self.stream.flush()
        self._status = line

    def clear_status(self):
        if self._status and self.tty and not self.quiet:
            self.stream.write("\r" + " " * (len(self._status) + 1) + "\r")
            self.stream.flush()
        self._status = ""

    def tick(self, label=""):
        """Called per request so the elapsed/throughput line stays alive."""
        self._requests += 1
        if self._requests % 2 == 0 or label:
            el = time.monotonic() - self._t0
            self.status(f"  {self._requests} requests, {el:5.1f}s  {label}")

    # -- permanent output -----------------------------------------------
    def __call__(self, line=""):
        if self.tee_fh is not None:
            try:
                self.tee_fh.write(str(line) + "\n")
                self.tee_fh.flush()
            except Exception:
                pass
        if self.quiet:
            return
        self.clear_status()
        self.stream.write(str(line) + "\n")
        self.stream.flush()

    def close(self):
        if self.tee_fh is not None:
            try:
                self.tee_fh.close()
            except Exception:
                pass
            self.tee_fh = None

    def retee(self, path):
        """Point the saved log at a new file, for the next target in a sweep."""
        self.close()
        if not path:
            return
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.tee_fh = open(path, "w", encoding="utf-8")
        except Exception as e:
            print(f"[!] cannot write {path}: {e}", file=sys.stderr)

    def rule(self, char=None):
        ch = char or self._glyph(self.G_RULE)
        self(self.c(ch * self._width(), "dim"))

    def head(self, title):
        self("")
        bar = self._glyph(self.G_HEAD)
        n = max(4, self._width() - len(title) - 5)
        self(self.c(f"{bar * 3} {title} {bar * n}", "bold", "brcyan"))

    def banner(self, lines):
        self("")
        for i, ln in enumerate(lines):
            self(self.c(ln, "bold", "brcyan") if i == 0 else self.c(ln, "dim"))
        self.rule()

    # -- semantic markers -----------------------------------------------
    def _marker(self, glyph, style, msg, indent, msg_styles=()):
        mark = self.c(self._glyph(glyph), *style)
        body = self.c(msg, *msg_styles) if msg_styles else msg
        self((" " * indent) + mark + " " + str(body))

    def ok(self, msg, indent=2):
        self._marker(self.G_OK, ("brgreen",), msg, indent)

    def info(self, msg, indent=2):
        self._marker(self.G_INFO, ("dim",), msg, indent)

    def flag(self, msg, indent=2):
        self._marker(self.G_FLAG, ("bryellow",), msg, indent, ("bryellow",))

    def alert(self, msg, indent=2):
        self._marker(self.G_ALERT, ("brred",), msg, indent,
                     ("brred", "bold"))

    def skip(self, msg, indent=2):
        mark = self._glyph(self.G_SKIP)
        self(self.c((" " * indent) + mark + " " + str(msg), "dim"))

    def note(self, text, indent=2):
        """Wrapped explanatory prose, dimmed so it reads as commentary."""
        width = self._width() - indent - 2
        for para in text.strip().split("\n\n"):
            words, line = para.split(), ""
            for w in words:
                if line and len(line) + 1 + len(w) > width:
                    self(self.c(" " * indent + line, "dim"))
                    line = w
                else:
                    line = f"{line} {w}".strip()
            if line:
                self(self.c(" " * indent + line, "dim"))

    # -- aligned output -------------------------------------------------
    def kv(self, key, value, note=None, style=None, width=28, indent=2):
        k = f"{' ' * indent}{key}".ljust(width + indent)
        v = self.c(value, *(style or ("bold",)))
        line = f"{k}{v}"
        if note:
            line += "  " + self.c(note, "dim")
        self(line)

    def table(self, headers, rows, indent=2, styles=None):
        """Column-aligned table. styles maps a column index to a style tuple,
        or a callable taking the cell value and returning a style tuple."""
        if not rows:
            return
        cols = len(headers)
        cells = [[("" if c is None else str(c)) for c in r] for r in rows]
        w = [len(str(headers[i])) for i in range(cols)]
        for r in cells:
            for i in range(cols):
                w[i] = max(w[i], len(r[i]) if i < len(r) else 0)
        avail = self._width() - indent - 2 * (cols - 1)
        while sum(w) > avail and max(w) > 8:
            w[w.index(max(w))] -= 1
        pad = " " * indent
        self(pad + self.c("  ".join(str(headers[i]).ljust(w[i])
                                    for i in range(cols)), "bold", "dim"))
        for r in cells:
            out_cells = []
            for i in range(cols):
                val = r[i] if i < len(r) else ""
                if len(val) > w[i]:
                    val = val[:w[i] - 1] + self._glyph(self.G_ELLIPSIS)
                st = None
                if styles and i in styles:
                    st = styles[i](val) if callable(styles[i]) else styles[i]
                out_cells.append(self.c(val.ljust(w[i]), *st) if st
                                 else val.ljust(w[i]))
            self(pad + "  ".join(out_cells).rstrip())

    def elapsed(self):
        return time.monotonic() - self._t0


VERDICT_STYLE = {
    "IN_RANGE": ("brred", "bold"),
    "INDETERMINATE": ("bryellow", "bold"),
    "OUT_OF_RANGE": ("dim",),
}

RISK_STYLE = {
    "none": ("brgreen",), "read-only": ("brgreen",), "low": ("green",),
    "medium": ("bryellow",), "high": ("brred", "bold"),
}


def dry_run_plan(args):
    """Every request this run would send, in hex. Opens no socket."""
    init = mms_initiate_request(local_detail=args.max_pdu,
                                nesting=args.nesting)
    plan = [
        ("COTP connection request", cotp_cr()),
        ("session CONNECT with ACSE AARQ and MMS Initiate",
         cotp_dt(session_connect(pres_cp_type(acse_aarq(init))))),
        ("Identify", req_identify()),
        ("Status", req_status()),
        ("GetCapabilityList (service 71, tag bf 47)",
         req_get_capability_list()),
        ("GetNameList, domain scope list (class 9)",
         req_get_name_list(object_class=9)),
        ("GetNameList, named variables in domain EXAMPLE",
         req_get_name_list(object_class=0, domain="EXAMPLE")),
        ("GetDomainAttributes for EXAMPLE (service 37, tag 9f 25)",
         req_get_domain_attributes("EXAMPLE")),
        ("Read LPHD1$DC$PhyNam$swRev in domain EXAMPLE",
         req_read("EXAMPLE", "LPHD1$DC$PhyNam$swRev")),
        ("GetVariableAccessAttributes for the same object",
         req_get_var_access_attrs("EXAMPLE", "LPHD1$DC$PhyNam$swRev")),
    ]
    if args.file_dir:
        plan.append(("FileDirectory (service 77, tag bf 4d)",
                     req_file_directory()))
    plan.append(("Conclude", CONCLUDE_REQUEST))
    return plan


# ===========================================================================
#  Main
# ===========================================================================

class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Wider help column, and a verbatim epilog.

    Two problems with the defaults. max_help_position is 24, so an
    invocation like `--authz-max AUTHZ_MAX` (23 columns with the indent)
    leaves no room and its description is pushed onto its own line; short
    metavars plus a 32-column position keep every description beside its
    option. And the plain formatter re-wraps the epilog, which turns a block
    of worked examples into a paragraph. RawDescription leaves the epilog and
    description alone while still wrapping each option's own help text.
    """

    def __init__(self, prog):
        try:
            width = min(100, max(60,
                                 shutil.get_terminal_size((80, 24)).columns))
        except Exception:
            width = 80
        super().__init__(prog, max_help_position=32, width=width)


def _help_formatter(prog):
    return _HelpFormatter(prog)


# Worked examples, shown at the bottom of --help. Kept under 76 columns so a
# narrow terminal does not fold them, since the epilog is passed through
# verbatim and will not re-wrap.
EXAMPLES = """
examples

  look first, nothing is sent and no socket opens
    mms_recon.py --dry-run
    mms_recon.py --list-probes

  enumerate one device, saving the readable log
    mms_recon.py 192.0.2.10 --save out/relay.log

  the same, and also the machine-readable evidence
    mms_recon.py 192.0.2.10 --save out/relay.log --json out/relay.json

  sweep a list: one .log per target, sweep.log and index.json
    mms_recon.py --targets relays.txt --out sweep/

  collect as much as the device will give, for offline analysis
    mms_recon.py --targets relays.txt --out sweep/ --read-values

  a quick inventory instead of a full sweep
    mms_recon.py 192.0.2.10 --quick --save out/quick.log

  check the version against advisory ranges you supply
    mms_recon.py 192.0.2.10 --advisories advisories.json --save out/a.log

  slow link, loaded device, or a serial or radio hop
    mms_recon.py 192.0.2.10 --rate 0.25 --timeout 30 --max-domains 8

  fingerprint the stack only, no enumeration
    mms_recon.py 192.0.2.10 --fingerprint --record sig.json
    mms_recon.py 192.0.2.11 --fingerprint --signatures sig.json

  lab work: each probe collects only what it needs, nothing more
    mms_recon.py 192.0.2.10 --lab --probes services,ctxid,error-append
    mms_recon.py 192.0.2.10 --lab --probes authz-matrix --authz-max 200
    mms_recon.py 192.0.2.10 --lab --probes pool --pool-max 8

  an association the device refuses: things to try, in this order
    mms_recon.py 192.0.2.10 --no-direct-reference
    mms_recon.py 192.0.2.10 --outstanding 1 --max-pdu 32000
    mms_recon.py 192.0.2.10 --tpdu-size 0x0a

  keep the colour when writing to a file, or drop it when piping
    mms_recon.py 192.0.2.10 --color > run.log
    mms_recon.py 192.0.2.10 --no-color --no-progress | tee run.log

a target file is one entry per line, '#' comments ignored

  10.0.0.10
  10.0.0.11:1102        a port for this entry only
  10.0.0.12 1102        a space works too
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="mms_recon.py",
        formatter_class=_help_formatter,
        description="Read-only MMS / IEC 61850 enumeration.\n"
                    "Collects as much as a server will tell you without "
                    "changing anything, and\nwrites it as JSON so the "
                    "analysis can happen later and elsewhere.",
        epilog=EXAMPLES + "\nObtain written authorization before pointing "
               "this at equipment you do not own.\n")
    p.add_argument("host", nargs="?", help="target address or hostname")
    p.add_argument("--targets", metavar="FILE",
                   help="file of targets, one per line: 'host', 'host:port' "
                        "or 'host port'. '#' comments and blank lines are "
                        "ignored. Combines with a host given on the command "
                        "line")
    p.add_argument("--out", metavar="DIR",
                   help="write one JSON per target here, plus index.json "
                        "summarising the sweep. Required for more than one "
                        "target")
    p.add_argument("--port", type=int, default=102, metavar="N",
                   help="TCP port (default 102). A target file may override "
                        "it per entry")
    p.add_argument("--timeout", type=float, default=8.0, metavar="SEC",
                   help="socket timeout (default 8). Raise it for a slow "
                        "link or a device under load")

    g = p.add_argument_group("pacing")
    g.add_argument("--dry-run", action="store_true",
                   help="print every request that would be sent, as hex, and "
                        "open no socket")
    g.add_argument("--max-assoc", type=int, default=3, metavar="N",
                   help="association budget (default 3)")
    g.add_argument("--rate", type=float, default=0.05, metavar="SEC",
                   help="minimum seconds between requests (default 0.05). "
                        "A deep sweep is thousands of sequential requests; "
                        "unthrottled enumeration of an in-service IED is "
                        "something many asset owners forbid outright")
    g.add_argument("--settle", type=float, default=1.0, metavar="SEC",
                   help="seconds between associations (default 1)")

    l = p.add_argument_group("gated probes: these change state or deviate "
                             "from the protocol")
    l.add_argument("--lab", action="store_true",
                   help="unlock the gated probes. Read-only reconnaissance "
                        "needs no flag; these are different in kind")
    l.add_argument("--probes", metavar="LIST", default="",
                   help="comma-separated probe names, or 'all' (which means "
                        "every probe that is not high risk). Needs --lab")
    l.add_argument("--list-probes", action="store_true",
                   help="describe the gated probes and exit")
    l.add_argument("--authz-max", type=int, default=120, metavar="N",
                   help="objects to test in the authz-matrix probe "
                        "(3 reads each, default 120)")
    l.add_argument("--pool-max", type=int, default=16, metavar="N",
                   help="ceiling for the association-pool probe (default 16)")

    s = p.add_argument_group("scope")
    s.add_argument("--quick", action="store_true",
                   help="narrow the sweep: three common object classes "
                        "instead of ten, no shape probe, no file listing. "
                        "The default is thorough, because the point is to "
                        "collect once and analyse later")
    s.add_argument("--no-file-dir", action="store_true",
                   help="skip the file directory listing (on by default; "
                        "it is read-only and names every file the server "
                        "will admit to)")
    s.add_argument("--read-values", action="store_true",
                   help="read the VALUE of every enumerated data attribute, "
                        "not just the data model. The largest single "
                        "increase in collected data, and the largest "
                        "increase in request count. Never reads FC=CO")
    s.add_argument("--read-values-max", type=int, default=2000, metavar="N",
                   help="ceiling on --read-values reads (default 2000)")
    s.add_argument("--file-dir-limit", type=int, default=2000, metavar="N",
                   help="ceiling on file-directory entries (default 2000)")
    s.add_argument("--max-domains", type=int, default=64, metavar="N",
                   help="logical devices to sweep (default 64)")
    s.add_argument("--shape-samples", type=int, default=0, metavar="N",
                   help="objects for the type/shape probe, 0 for no limit "
                        "(default 0)")
    s.add_argument("--show-weak", action="store_true",
                   help="include low-confidence object-name flags")

    n = p.add_argument_group("negotiation")
    n.add_argument("--max-pdu", type=int, default=65000, metavar="N",
                   help="localDetailCalling to propose")
    n.add_argument("--nesting", type=int, default=10, metavar="N",
                   help="dataStructureNestingLevel to propose")
    n.add_argument("--outstanding", type=int, default=5, metavar="N",
                   help="maxServOutstanding to propose both ways. Proposing "
                        "1 makes the answer meaningless, because the device "
                        "simply echoes it (default 5)")
    n.add_argument("--tpdu-size", type=lambda s: int(s, 0), default=0x0A,
                   metavar="CODE",
                   help="COTP TPDU size as the log2 code: 0x0a=1024 "
                        "(default, widely accepted), 0x0d=8192")
    n.add_argument("--no-direct-reference", action="store_true",
                   help="omit the BER transfer-syntax OID from the ACSE "
                        "EXTERNAL. Legal, but some stacks expect it")

    o = p.add_argument_group("output")
    o.add_argument("--signatures", metavar="PATH",
                   help="signature table for stack matching (see README)")
    o.add_argument("--ln-classes", metavar="PATH",
                   help="extra logical node classes, whitespace separated")
    o.add_argument("--record", metavar="PATH",
                   help="write a signature stub for this device")
    o.add_argument("--fingerprint", action="store_true",
                   help="stop after the negotiated parameters, Identify and "
                        "the signature match. One association, a handful of "
                        "requests, no enumeration. What --record and "
                        "--signatures actually need")
    o.add_argument("--advisories", metavar="PATH",
                   help="advisory file to match the version against")
    o.add_argument("--save", metavar="PATH",
                   help="save the console output, colour and all, to this "
                        "file. This is the readable record; in --out DIR "
                        "mode it is written per target automatically")
    o.add_argument("--json", metavar="PATH",
                   help="ALSO write the machine-readable evidence file: raw "
                        "hex of every frame, every enumerated name, "
                        "latencies. Harder to read, better for scripting")
    o.add_argument("--color", dest="color", action="store_true", default=None,
                   help="force colour even when not a terminal")
    o.add_argument("--no-color", dest="color", action="store_false",
                   help="disable colour. NO_COLOR in the environment and a "
                        "non-terminal stdout do this automatically")
    o.add_argument("--no-progress", action="store_true",
                   help="suppress the live progress line")
    o.add_argument("--quiet", action="store_true",
                   help="no console output. The evidence file is still "
                        "written, which is the point when sweeping many "
                        "targets")
    o.add_argument("--version", action="version",
                   version=f"mms_recon.py {__version__}")
    return p


def scan_target(args, out, advisories, signatures, ln_classes, lab,
                selected):
    """Enumerate one target. Returns (evidence, exit code).

    args.host and args.port name the target, and args.json names where the
    evidence goes. The caller sets all three per target, which is what makes
    a multi-target run a loop over this rather than a special case inside it.
    The evidence file is written incrementally, so a run that dies part way
    still leaves everything gathered up to that point.
    """
    wire = []
    R = {
        "tool": "mms_recon.py", "version": __version__,
        "target": {"host": args.host, "port": args.port},
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "associations": {"budget": args.max_assoc, "used": 0},
        "negotiated": {}, "identify": {}, "capabilityList": {},
        "domains": [], "domainAttributes": {}, "nameplate": {},
        "objects": {}, "flagged": [], "shape": [], "fileDirectory": {},
        "controlModels": {}, "proposedVsGranted": {}, "latencies": [],
        "labProbes": {}, "advisoryMatches": [], "values": {},
        "valuesMeta": {}, "unsolicited": [],
        "reducedOsi": {}, "serviceInterest": [], "signatureMatch": None,
        "errors": [], "wire": wire,
    }

    budget = {"left": args.max_assoc}

    def write_json():
        if not args.json:
            return
        R["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        R["labProbeLog"] = lab.log
        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(R, indent=2, default=str))

    def new_client(label):
        """Charge the budget only once an association actually exists."""
        if budget["left"] <= 0:
            out(f"[!] association budget exhausted, skipping: {label}")
            return None
        cli = MmsClient(args.host, args.port, args.timeout,
                        rate=args.rate, recorder=wire,
                        tpdu_size=args.tpdu_size,
                        direct_reference=not args.no_direct_reference,
                        progress=out.tick)
        try:
            cli.connect(make_init())
        except Refused as e:
            out(f"[!] {e}")
            R["errors"].append({"stage": label, "refused": str(e)})
            return None
        except Exception as e:
            out(f"[!] association failed ({label}): {e}")
            R["errors"].append({"stage": label, "error": str(e)})
            return None
        budget["left"] -= 1
        R["associations"]["used"] += 1
        return cli

    def make_init():
        return mms_initiate_request(local_detail=args.max_pdu,
                                    max_out_calling=args.outstanding,
                                    max_out_called=args.outstanding,
                                    nesting=args.nesting)

    out.banner([
        f"mms_recon.py {__version__}   read-only MMS / IEC 61850 reconnaissance",
        f"target {args.host}:{args.port}   association budget {args.max_assoc}"
        f"   scope {'deep' if args.deep else 'standard'}",
    ])
    if args.lab and selected:
        out.flag(f"gated probes enabled: {', '.join(sorted(selected))}", indent=0)
    else:
        out.ok("read-only conformant requests only, nothing held or changed",
               indent=0)

    # What the selected probes actually need. A probe wanting only the
    # association should not trigger a full data-model sweep to reach it;
    # only authz-matrix needs the enumerated objects.
    probe_need = 2
    if args.lab and selected:
        probe_need = max((LAB_NEEDS[LAB_PROBES[n]["needs"]]
                          for n in selected if n in LAB_PROBES), default=0)
    full_scope = probe_need >= 2
    if not full_scope:
        out.info("gated probes only: skipping the data-model sweep, which "
                 "none of them needs", indent=0)

    try:
        cli = new_client("primary")
        if cli is None:
            write_json()
            return R, 1

        with cli:
            neg = cli.negotiated
            R["negotiated"] = neg

            # -- 1. negotiated parameters ------------------------------
            out.head("1. NEGOTIATED PARAMETERS")
            out.kv("MMS version", neg.get("version"))
            out.kv("max PDU size", neg.get("maxPduSize"),
                   "buffer budget for one PDU")
            out.kv("max outstanding, calling",
                   neg.get("maxOutstandingCalling"))
            out.kv("max outstanding, called", neg.get("maxOutstandingCalled"))
            out.kv("data structure nesting", neg.get("nestingLevel"),
                   "nesting depth the parser accepts")
            out.kv("COTP TPDU size", f"{cli.cotp_tpdu_octets} octets",
                   cli.tpdu_negotiated)
            out.kv("services advertised", len(neg.get("services", [])))
            out.kv("services bitmap", neg.get("servicesRaw", "(absent)"),
                   style=("dim",))
            out("")
            cbb = neg.get("parameterCbb", [])
            out.kv("ParameterSupportOptions", ", ".join(cbb) or "(none)")
            for flag in cbb:
                if flag in PARAM_MEANING:
                    if flag == "valt":
                        out.flag(f"{flag:6s} {PARAM_MEANING[flag]}", indent=6)
                    else:
                        out.info(f"{flag:6s} {PARAM_MEANING[flag]}", indent=6)

            prop = getattr(cli, "proposed", {}) or {}
            deltas = []
            for key, label in (("maxPduSize", "max PDU size"),
                               ("nestingLevel", "nesting level"),
                               ("maxOutstandingCalling", "outstanding, calling"),
                               ("maxOutstandingCalled", "outstanding, called")):
                pv, gv = prop.get(key), neg.get(key)
                if pv is not None and gv is not None and pv != gv:
                    deltas.append((label, pv, gv))
            R["proposedVsGranted"] = {
                "proposed": {k: v for k, v in prop.items()
                             if not k.endswith(("Raw", "Bits"))},
                "granted": {k: v for k, v in neg.items()
                            if not k.endswith(("Raw", "Bits"))},
                "reduced": [{"parameter": a, "proposed": b, "granted": c}
                            for a, b, c in deltas]}
            if deltas:
                out("")
                out("  the device REDUCED what was proposed:")
                out.table(["parameter", "proposed", "granted"],
                          [[a, b, c] for a, b, c in deltas], indent=6,
                          styles={2: ("bryellow", "bold")})
                out.note("Those granted values are the hard limits anything "
                         "later has to fit inside.", indent=6)
            svc_prop = set(prop.get("services", []))
            svc_grant = set(neg.get("services", []))
            if svc_prop and svc_grant and svc_prop != svc_grant:
                only_dev = sorted(svc_grant - svc_prop)
                if only_dev:
                    out(f"  device declares services this client did not "
                        f"offer: {', '.join(only_dev)}")

            # -- 2. identify -------------------------------------------
            out.head("2. IDENTIFY")
            try:
                num, value = cli.service_call(req_identify(), "identify")
                ident = decode_identify(value)
                R["identify"] = ident
                for k in ("vendor", "model", "revision"):
                    out.kv(k, ident.get(k, "(absent)"))
                if ident.get("abstractSyntaxes"):
                    out.kv("abstract syntaxes",
                           ", ".join(ident["abstractSyntaxes"]),
                           style=("dim",))
            except Exception as e:
                out(f"  [!] {e}")
                R["errors"].append({"stage": "identify", "error": str(e)})
            out("")
            out("")
            out.note("All three fields are set by the application rather than "
                     "derived from the stack, so treat them as a claim. "
                     "Section 6 reads the IEC 61850 nameplate for a version "
                     "taken from the data model instead.")

            if advisories:
                out.head("2b. ADVISORY VERSION MATCH")
                out(f"  {len(advisories)} advisory record(s) loaded")
                matches = match_advisories(advisories, R["identify"], {})
                R["advisoryMatches"] = matches
                out("")
                out.table(["verdict", "advisory"],
                          [[m["verdict"], m["advisory"]] for m in matches],
                          styles={0: lambda v: VERDICT_STYLE.get(
                              v.strip(), ("dim",))})
                out("")
                for m in matches:
                    emit = {"IN_RANGE": out.alert,
                            "INDETERMINATE": out.flag}.get(m["verdict"],
                                                           out.skip)
                    emit(m["advisory"])
                    for b in m["because"]:
                        out.info(b, indent=8)
                    if m.get("fixedIn"):
                        out.info(f"fixed in {m['fixedIn']}", indent=8)
                    if m.get("notes"):
                        out.note(m["notes"], indent=8)
                inr = [m for m in matches if m["verdict"] == "IN_RANGE"]
                ind = [m for m in matches if m["verdict"] == "INDETERMINATE"]
                out("")
                out(f"  {len(inr)} in range, {len(ind)} indeterminate, "
                    f"{len(matches) - len(inr) - len(ind)} out of range")
                if ind:
                    out("  An indeterminate result is not a pass. The "
                        "comparison could not be")
                    out("  made, and an undefined comparison does not "
                        "discharge a finding.")
                out("  This matches versions only. It does not test "
                    "whether anything is")
                out("  actually exploitable, and a version finding should "
                    "be reported as one.")

            # -- 3. GetCapabilityList ----------------------------------
            out.head("3. GETCAPABILITYLIST")
            out("  IEC 61850-8-1 does not use this service, so whatever comes")
            out("  back is implementation-chosen.")
            try:
                num, value = cli.service_call(req_get_capability_list(),
                                              "getCapabilityList")
                caps, more = decode_capability_list(value)
                R["capabilityList"] = {"capabilities": caps,
                                       "moreFollows": more}
                if caps:
                    out(f"  {len(caps)} capability string(s):")
                    for c in caps:
                        out(f"      {c!r}")
                else:
                    out("  supported, but returned no capability strings")
            except MmsServiceError as e:
                out(f"  not available: {e}")
                R["capabilityList"] = {"error": str(e)}
            except Exception as e:
                out(f"  [!] {e}")
                R["capabilityList"] = {"error": str(e)}

            # -- 4. service interest -----------------------------------
            out.head("4. ADVERTISED SERVICES OF INTEREST")
            svcs = neg.get("services", [])
            notable = [s for s in svcs if s in SERVICE_NOTES]
            if not notable:
                out("  nothing in the interest table is advertised")
            for s in notable:
                note, studied = SERVICE_NOTES[s]
                out(f"  {s}  [{studied}]")
                out(f"      {note}")
                R["serviceInterest"].append({"service": s, "note": note,
                                             "coverage": studied})
            unexamined = [s for s in notable
                          if SERVICE_NOTES[s][1] == "largely unexamined"]
            if unexamined:
                out("")
                out(f"  Largely unexamined in published work: "
                    f"{', '.join(unexamined)}")
            out("")
            out("  A service being advertised is a place to look. It is not a")
            out("  finding.")

            # -- 5. signature match ------------------------------------
            out.head("5. STACK SIGNATURE")
            observed = service_bitmap(neg)
            if observed is None:
                out("  no services bitmap was returned, cannot compare")
            elif not signatures:
                out("  no signature table loaded, so NO comparison was made.")
                out("  Pass --signatures PATH to compare. This tool ships no")
                out("  table: a 'nearest relative' is only as good as its")
                out("  corpus, and a guess here reads as a finding.")
                out(f"  Observed bitmap: {observed.hex()}")
                out("  Use --record to emit a signature stub for this device.")
            else:
                dists = signature_distances(observed, signatures)
                R["signatureMatch"] = dists
                for d in dists[:6]:
                    mark = "   EXACT" if d["distance"] == 0 else ""
                    out(f"  {d['stack'][:34]:34s} distance "
                        f"{d['distance']:3d}{mark}")
                if dists and dists[0]["distance"] != 0:
                    out("")
                    out(f"  No exact match in the {len(signatures)} "
                        f"signature(s) loaded.")
                    out("  Nearest differs on:")
                    for s in dists[0]["differing"][:12]:
                        out(f"      {s}")
                    out("  This bounds the claim to the table you supplied,")
                    out("  not to the universe of MMS stacks.")

            if args.record and observed is not None:
                stub = {"signatures": [{
                    "name": f"UNNAMED {args.host}:{args.port}",
                    "required": observed.hex(),
                    "optional": "00" * len(observed),
                    "notes": (f"recorded by mms_recon.py {__version__}; "
                              f"identify="
                              f"{R['identify'].get('vendor', '?')}/"
                              f"{R['identify'].get('model', '?')}/"
                              f"{R['identify'].get('revision', '?')}")}]}
                Path(args.record).parent.mkdir(parents=True, exist_ok=True)
                Path(args.record).write_text(json.dumps(stub, indent=2))
                out(f"\n  signature stub written to {args.record}")
                out("  Name it, set don't-care bits in 'optional', and only")
                out("  publish it for a device whose stack you can attest to.")

            if args.fingerprint:
                # Everything above comes from the Initiate response and one
                # Identify. --record and --signatures need nothing more, so
                # paying for a full enumeration to get a fingerprint was
                # incidental rather than intended.
                R["latencies"].extend(cli.latencies)
                R["unsolicited"].extend(cli.unsolicited)
                out("")
                out.ok("fingerprint only: stopping before enumeration")
                write_json()
                out.head("SUMMARY")
                out.kv("requests sent", out._requests)
                out.kv("elapsed", f"{out.elapsed():.1f} s")
                out.kv("services advertised",
                       len(R["negotiated"].get("services", [])))
                for k in ("vendor", "model", "revision"):
                    out.kv(k, R["identify"].get(k, "(absent)"))
                return R, 0

            # -- 6. domains and nameplate ------------------------------
            out.head("6. DOMAINS AND THE IEC 61850 NAMEPLATE")
            dom_res = enumerate_names(cli, object_class=9, log=out)
            domains = dom_res["names"]
            R["domains"] = domains
            R["objects"]["vmd/domain"] = dom_res
            out(f"  {len(domains)} domain(s): {domains[:12]}"
                f"{' ...' if len(domains) > 12 else ''}")

            for dom in (domains[:args.max_domains] if full_scope
                        else domains[:2]):
                try:
                    num, value = cli.service_call(
                        req_get_domain_attributes(dom),
                        f"getDomainAttributes({dom})")
                    attrs = decode_domain_attributes(value)
                    R["domainAttributes"][dom] = attrs
                    bits = [f"state={attrs.get('state')}"]
                    if attrs.get("capabilities"):
                        bits.append(f"capabilities="
                                    f"{attrs['capabilities']}")
                    if attrs.get("mmsDeletable") is not None:
                        bits.append(f"deletable={attrs['mmsDeletable']}")
                    out(f"    {dom}: {', '.join(bits)}")
                except MmsServiceError as e:
                    R["domainAttributes"][dom] = {"error": str(e)}
                except Exception as e:
                    R["domainAttributes"][dom] = {"error": str(e)}

            out("")
            for dom in (domains[:args.max_domains] if full_scope else []):
                for item, label in NAMEPLATE_ITEMS:
                    try:
                        vals = read_item(cli, dom, item)
                    except (MmsServiceError, Refused, BerError):
                        continue
                    except Exception:
                        continue
                    if not vals or any(isinstance(v, dict) and "failure" in v
                                       for v in vals):
                        continue
                    R["nameplate"][f"{dom}/{item}"] = vals
                    out(f"  {label:26s} {vals[0]}")

            if not R["nameplate"] and domains:
                out("  standard LPHD1/LLN0 paths returned nothing; "
                    "enumerating instead")
                for dom in domains[:min(4, args.max_domains)]:
                    res = enumerate_names(cli, 0, dom, log=out)
                    R["objects"][f"{dom}/namedVariable"] = res
                    cands = [n for n in res["names"]
                             if any(h in n for h in NAMEPLATE_HINTS)]
                    out(f"    {dom}: {len(res['names'])} objects, "
                        f"{len(cands)} nameplate candidate(s)")
                    for n in cands[:24]:
                        try:
                            vals = read_item(cli, dom, n)
                        except Exception:
                            continue
                        if vals and not any(isinstance(v, dict)
                                            and "failure" in v
                                            for v in vals):
                            R["nameplate"][f"{dom}/{n}"] = vals
                            out(f"      {n:44s} {vals[0]}")

            if R["nameplate"]:
                out("")
                out("  A software-revision string here comes from the data")
                out("  model, independently of Identify. It is still")
                out("  vendor-populated, so it is evidence rather than proof.")

            # Set before the gate: the summary reads it whether or not
            # the sweep ran.
            strong = []

            if full_scope:
                # -- 6b. control models ------------------------------------
                out.head("6b. CONTROL MODELS (read-only, FC=CF)")
                out("  Which control objects exist and how each expects to be")
                out("  operated. Read at FC=CF, which is configuration; the")
                out("  control model itself lives at FC=CO, where reading $SBO")
                out("  would perform a SELECT.")
                any_ctl = False
                for dom in domains[:args.max_domains]:
                    res = R["objects"].get(f"{dom}/namedVariable")
                    if res is None:
                        res = enumerate_names(cli, 0, dom, log=out)
                        R["objects"][f"{dom}/namedVariable"] = res
                    models = probe_ctl_models(cli, dom, res["names"], log=out)
                    if models:
                        any_ctl = True
                        R["controlModels"][dom] = models
                        out.table(["object", "ctlModel", "meaning", "select"],
                                  [[m2["object"], m2["ctlModel"], m2["meaning"],
                                    "required" if m2["selectRequired"] else "-"]
                                   for m2 in models], indent=4,
                                  styles={3: lambda v: ("bryellow",)
                                          if v.strip() == "required" else ("dim",)})
                if not any_ctl:
                    out("  no control objects found under FC=CO")
                else:
                    sel = [m2 for v in R["controlModels"].values() for m2 in v
                           if m2["selectRequired"]]
                    out("")
                    out(f"  {sum(len(v) for v in R['controlModels'].values())} "
                        f"control object(s), {len(sel)} requiring "
                        f"Select-before-Operate")
                    out("  Those are exactly the objects a careless FC=CO read")
                    out("  would have reserved. This tool never reads FC=CO.")

                # -- 7. object hunt ----------------------------------------
                out.head("7. NON-IEC-61850 OBJECT HUNT")
                classes = sorted(OBJECT_CLASSES) if args.deep else [0, 2, 9]
                out(f"  object classes {classes}"
                    f"{'' if args.deep else '  (--deep for all)'}")

                def hunt(scope, oc, res):
                    key = f"{scope}/{OBJECT_CLASSES[oc]}"
                    R["objects"][key] = res
                    if not res["names"]:
                        return
                    strong = 0
                    for n in res["names"]:
                        sig = classify_name(n, oc, ln_classes)
                        if not sig:
                            continue
                        rank = highest_confidence(sig)
                        rec = {"scope": scope, "class": OBJECT_CLASSES[oc],
                               "name": n, "signals": sig,
                               "confidence": ("high" if rank == 3
                                              else "medium" if rank == 2
                                              else "low")}
                        R["flagged"].append(rec)
                        if rank >= 2:
                            strong += 1
                            if strong <= 20:
                                (out.alert if rank == 3 else out.flag)(
                                    f"{n}   [{rec['confidence']}]", indent=6)
                                for s in sig:
                                    if s["confidence"] != "low":
                                        out.info(s["signal"], indent=12)
                    out(f"    {key:38s} {len(res['names'])} name(s)"
                        f"{f', {strong} notable' if strong else ''}")
                    if strong > 20:
                        out(f"      ... {strong - 20} more notable, see --json")

                for oc in classes:
                    hunt("vmd", oc, enumerate_names(cli, oc, None, log=out))
                for dom in domains[:args.max_domains]:
                    for oc in classes:
                        if oc == 9:
                            continue
                        hunt(dom, oc, enumerate_names(cli, oc, dom, log=out))

                if advisories and R["nameplate"]:
                    # Section 2b ran before the nameplate existed and passed {},
                    # so every advisory keyed on a nameplate field such as swRev
                    # came back INDETERMINATE because of the ORDER OF THE REPORT,
                    # not because of anything the device said.
                    redone = match_advisories(advisories, R["identify"],
                                              R["nameplate"])
                    before = {m2["advisory"]: m2["verdict"]
                              for m2 in R["advisoryMatches"]}
                    changed = [m2 for m2 in redone
                               if before.get(m2["advisory"]) != m2["verdict"]]
                    R["advisoryMatches"] = redone
                    if changed:
                        out("")
                        out("  advisory verdicts revised now the nameplate is "
                            "known:")
                        for m2 in changed:
                            emit = {"IN_RANGE": out.alert,
                                    "INDETERMINATE": out.flag}.get(m2["verdict"],
                                                                   out.skip)
                            emit(f"{m2['advisory']}: "
                                 f"{before.get(m2['advisory'])} -> "
                                 f"{m2['verdict']}", indent=4)
                            for b in m2["because"]:
                                out.info(b, indent=10)

                strong = [f for f in R["flagged"] if f["confidence"] != "low"]
                weak = [f for f in R["flagged"] if f["confidence"] == "low"]
                out("")
                out(f"  {len(strong)} notable, {len(weak)} weak "
                    f"(unfamiliar logical node class only)")
                if weak and args.show_weak:
                    for f in weak[:40]:
                        out(f"      [low] {f['scope']}/{f['name']}")
                elif weak:
                    out("  Weak flags are suppressed; --show-weak to see them.")
                    out("  They are usually logical node classes this tool does")
                    out("  not know, not vendor objects. Extend --ln-classes.")
                if not strong:
                    out("")
                    out("  No high- or medium-confidence objects. Note the limit:")
                    out("  this covers the scopes enumerated, and says nothing")
                    out("  about objects reachable only after authentication.")
                truncs = [k for k, v in R["objects"].items()
                          if isinstance(v, dict) and v.get("truncated")]
                if truncs:
                    out("")
                    out(f"  INCOMPLETE enumeration for: {', '.join(truncs)}")
                    out("  Treat the negative above as provisional.")

                # -- 7b. values --------------------------------------------
                if args.read_values:
                    out.head("7b. DATA ATTRIBUTE VALUES")
                    out.note("Reads the value of every enumerated attribute. "
                             "FC=CO is refused by the guard, so control objects "
                             "are skipped rather than selected.")
                    targets_v, seen_v = [], set()
                    for key, res in R["objects"].items():
                        if not key.endswith("/namedVariable"):
                            continue
                        scope = key.split("/")[0]
                        if scope == "vmd":
                            continue
                        for n in res.get("names", []):
                            if (scope, n) not in seen_v:
                                seen_v.add((scope, n))
                                targets_v.append((scope, n))
                    cap_v = args.read_values_max or len(targets_v)
                    got, denied, skipped_v, failed = 0, 0, 0, 0
                    for vi, (dom, item) in enumerate(targets_v[:cap_v], 1):
                        out.status(f"  values {vi}/{min(cap_v, len(targets_v))}: "
                                   f"{item}")
                        try:
                            vals = read_item(cli, dom, item)
                        except Refused:
                            skipped_v += 1
                            continue
                        except (MmsServiceError, socket.timeout, OSError,
                                BerError) as e:
                            failed += 1
                            R["values"][f"{dom}/{item}"] = {"error": str(e)[:90]}
                            continue
                        if (vals and isinstance(vals[0], dict)
                                and "failure" in vals[0]):
                            denied += 1
                            R["values"][f"{dom}/{item}"] = {
                                "failure": vals[0]["failure"]}
                            continue
                        got += 1
                        R["values"][f"{dom}/{item}"] = vals
                    out.clear_status()
                    truncated_v = (len(targets_v) > cap_v)
                    out.kv("attributes read", got)
                    out.kv("refused by the device", denied,
                           style=("bryellow",) if denied else ("dim",))
                    out.kv("skipped (FC=CO)", skipped_v, style=("dim",))
                    out.kv("read errors", failed,
                           style=("bryellow",) if failed else ("dim",))
                    if truncated_v:
                        out.flag(f"stopped at --read-values-max "
                                 f"{args.read_values_max} of {len(targets_v)}; "
                                 f"the value set is INCOMPLETE")
                    R["valuesMeta"] = {"attempted": min(cap_v, len(targets_v)),
                                       "available": len(targets_v),
                                       "truncated": truncated_v,
                                       "read": got, "denied": denied,
                                       "skippedControlObjects": skipped_v,
                                       "errors": failed}

                # -- 8. file directory -------------------------------------
                if args.file_dir:
                    out.head("8. FILE DIRECTORY")
                    try:
                        res = file_directory(cli, None, args.file_dir_limit, out)
                        R["fileDirectory"] = res
                        out(f"  {len(res['entries'])} entry/entries")
                        for e in res["entries"][:30]:
                            size = e.get("size")
                            out(f"      {e.get('name', '?'):52s} "
                                f"{'' if size is None else size}")
                        if len(res["entries"]) > 30:
                            out(f"      ... {len(res['entries']) - 30} more, "
                                f"see --json")
                    except MmsServiceError as e:
                        out(f"  not available: {e}")
                        R["fileDirectory"] = {"error": str(e)}
                    except Exception as e:
                        out(f"  [!] {e}")
                        R["fileDirectory"] = {"error": str(e)}


        R["latencies"].extend(cli.latencies)
        R["unsolicited"].extend(cli.unsolicited)
        if cli.unsolicited:
            out("")
            out.flag(f"{len(cli.unsolicited)} unsolicited PDU(s) arrived "
                     f"during the scan")
            out.note("The device pushed data we did not ask for, which means "
                     "reporting is enabled and something is enrolled. The "
                     "raw PDUs are in the evidence under 'unsolicited'. "
                     "Worth noting in the report: whatever that stream is, "
                     "it reaches the master station's MMS client, which is a "
                     "parser nobody tests.")
        out("\n[+] primary association closed with Conclude")
        write_json()

        # -- 9. data model shape --------------------------------------
        if args.deep and full_scope:
            time.sleep(args.settle)
            cli2 = new_client("shape probe")
            if cli2 is not None:
                with cli2:
                    out.head("9. DATA MODEL SHAPE")
                    targets = []
                    for key, res in R["objects"].items():
                        if not key.endswith("/namedVariable"):
                            continue
                        scope = key.split("/")[0]
                        if scope == "vmd":
                            continue
                        for n in res["names"]:
                            targets.append((scope, n))
                    if not targets:
                        for dom in R["domains"][:min(2, args.max_domains)]:
                            res = enumerate_names(cli2, 0, dom, log=out)
                            R["objects"][f"{dom}/namedVariable"] = res
                            targets.extend((dom, n) for n in res["names"])

                    arrays, deepest, kinds = 0, 0, {}
                    shape_cap = args.shape_samples or len(targets)
                    status = getattr(out, "status", None)
                    for si, (dom, item) in enumerate(
                            targets[:shape_cap], 1):
                        if status:
                            status(f"  shape {si}/{min(shape_cap, len(targets))}"
                                   f": {item}")
                        try:
                            num, value = cli2.service_call(
                                req_get_var_access_attrs(dom, item),
                                f"getVarAccessAttrs({dom}/{item})")
                        except Exception:
                            continue
                        kind, elems, depth = decode_type_description(value)
                        if kind is None:
                            continue
                        R["shape"].append({
                            "domain": dom, "item": item, "type": kind,
                            "arrayElements": elems, "nesting": depth,
                            # The decoded summary is for the console; the
                            # raw TypeDescription is what someone with more
                            # time will actually want.
                            "raw": value.hex()})
                        kinds[kind] = kinds.get(kind, 0) + 1
                        deepest = max(deepest, depth)
                        if kind == "array":
                            arrays += 1
                            if arrays <= 20:
                                out(f"    array  {dom}/{item}  "
                                    f"elements={elems}  nesting={depth}")
                    out(f"  probed {len(R['shape'])} of {len(targets)} "
                        f"object(s)"
                        f"{'' if len(targets) <= shape_cap else f' (--shape-samples {args.shape_samples})'}")
                    out(f"  type mix: {kinds}")
                    out(f"  deepest nesting observed: {deepest}"
                        f"   (negotiated limit "
                        f"{R['negotiated'].get('nestingLevel')})")
                    out(f"  objects with an array type: {arrays}")
                    out("")
                    if arrays:
                        out("  Arrays exist in the data model, so array and")
                        out("  sub-element addressing is reachable here.")
                    else:
                        out("  No arrays in the sample. Array addressing may")
                        out("  not be reachable, but the sample is partial.")
                    out("  GetVariableAccessAttributes returns type metadata")
                    out("  and performs no control-model operation, which is")
                    out("  why shape probing uses it rather than Read.")
                out("[+] shape association closed with Conclude")
                write_json()

        # -- 10. reduced OSI -------------------------------------------
        # Deliberately non-conformant framing: IEC 61850-8-1 mandates the
        # full stack. By this tool's own criterion for --lab that belongs
        # behind the gate, and leaving it in the default path contradicted
        # the banner's claim of conformant requests only.
        want_reduced = args.lab and "reduced-osi" in selected
        if not want_reduced:
            out.head("10. REDUCED-OSI DIFFERENTIAL")
            out.skip("not run: --lab --probes reduced-osi to enable it")
            out.note("It sends an MMS Initiate with the session, "
                     "presentation and ACSE layers omitted, which is not "
                     "conformant framing, so it is gated like the other "
                     "deviations.")
            R["reducedOsi"] = {"skipped": "requires --lab --probes reduced-osi"}
        elif budget["left"] > 0:
            time.sleep(args.settle)
            out.head("10. REDUCED-OSI DIFFERENTIAL")
            out("  Does the server accept MMS straight over COTP, with no")
            out("  session, presentation or ACSE layer?")
            try:
                budget["left"] -= 1
                R["associations"]["used"] += 1
                res = reduced_osi_probe(args.host, args.port, make_init(),
                                        args.timeout, wire,
                                        tpdu_size=args.tpdu_size)
                R["reducedOsi"] = res
                if res.get("answered"):
                    out(f"  ANSWERED with {res['responseBytes']} bytes"
                        f"{', ' + res['pduType'] if res.get('pduType') else ''}")
                    out("  Two independent parse paths exist on this server.")
                    out("  The reduced path is normally the less exercised of")
                    out("  the two.")
                else:
                    out("  no response: full OSI framing only")
            except Refused as e:
                out(f"  [!] {e}")
                R["reducedOsi"] = {"refused": str(e)}
            except Exception as e:
                out(f"  [!] {e}")
                R["reducedOsi"] = {"error": str(e)}
        else:
            out.head("10. REDUCED-OSI DIFFERENTIAL")
            out.skip("skipped: association budget exhausted")
            R["reducedOsi"] = {"skipped": "association budget exhausted"}

        # -- 11. gated probes -----------------------------------------
        if args.lab and selected:
            _order = {"low": 0, "medium": 1, "high": 2}
            single = sorted((n for n in LAB_PROBES
                             if n in selected and n != "reduced-osi"),
                            key=lambda n: (_order.get(LAB_PROBES[n]["risk"], 9),
                                           n))
            if single:
                time.sleep(args.settle)
                cli3 = new_client("gated probes")
                if cli3 is not None:
                    with cli3:
                        for name in single:
                            meta = LAB_PROBES[name]
                            if not lab.allow(name, meta["summary"]):
                                continue
                            out.head(f"PROBE: {name}")
                            out.kv("risk", meta["risk"],
                                   style=RISK_STYLE.get(meta["risk"],
                                                        ("bold",)))
                            out.note(meta["summary"])
                            try:
                                R["labProbes"][name] = meta["fn"](
                                    cli3, args, R, out)
                            except Exception as e:
                                out(f"  [!] {e}")
                                R["labProbes"][name] = {"error": str(e)}
                            write_json()
                    out("[+] probe association closed with Conclude")
            if "pool" in selected and lab.allow("pool", "association pool"):
                time.sleep(args.settle)
                out.head("PROBE: pool  [risk high]")
                out("  Opens associations until the device refuses, then")
                out("  releases every one and verifies the pool came back.")
                out("  While they are held the device has no slots left for")
                out("  anything else that polls it.")
                try:
                    R["labProbes"]["pool"] = probe_assoc_pool(
                        args, R, out, wire, make_init)
                except Exception as e:
                    out(f"  [!] {e}")
                    R["labProbes"]["pool"] = {"error": str(e)}
                write_json()

        # -- summary ---------------------------------------------------
        out.head("SUMMARY")
        out.kv("associations used",
               f"{R['associations']['used']} of {args.max_assoc}")
        out.kv("requests sent", out._requests)
        out.kv("elapsed", f"{out.elapsed():.1f} s")
        out.kv("services advertised",
               len(R["negotiated"].get("services", [])))
        out.kv("capability strings",
               len(R["capabilityList"].get("capabilities", []) or []))
        out.kv("domains", len(R["domains"]))
        out.kv("notable objects", len(strong),
               style=("bryellow", "bold") if strong else ("bold",))
        nctl = sum(len(v) for v in R["controlModels"].values())
        nsel = len([1 for v in R["controlModels"].values() for x in v
                    if x["selectRequired"]])
        if R["valuesMeta"]:
            vm = R["valuesMeta"]
            out.kv("attribute values read", f"{vm['read']} of "
                   f"{vm['available']}",
                   "INCOMPLETE" if vm["truncated"] else None,
                   style=("bryellow", "bold") if vm["truncated"]
                   else ("bold",))
        out.kv("control objects", nctl,
               f"{nsel} select-before-operate" if nctl else None)
        # The nameplate maps a path to a LIST of decoded values, and an
        # attribute the device exposes but leaves empty decodes to [''], so
        # take the first non-empty string rather than printing a list repr.
        sw = [s for k, v in R["nameplate"].items() if "swRev" in k
              for s in (v if isinstance(v, list) else [v])
              if str(s).strip()]
        out.kv("nameplate swRev", sw[0] if sw else "(not recovered)",
               style=("bold",) if sw else ("dim",))
        out.kv("reduced-OSI answered",
               R["reducedOsi"].get("answered", "not probed"))
        if R["unsolicited"]:
            out.kv("unsolicited PDUs", len(R["unsolicited"]),
                   "reporting is enabled on this device",
                   style=("bryellow", "bold"))
        lats = [x for x in R["latencies"] if x.get("ms") is not None]
        if lats:
            worst = max(lats, key=lambda x: x["ms"])
            out.kv("slowest exchange", f"{worst['ms']:.1f} ms",
                   worst["step"])
        if R["advisoryMatches"]:
            inr = [m for m in R["advisoryMatches"]
                   if m["verdict"] == "IN_RANGE"]
            out.kv("advisories in range",
                   f"{len(inr)} of {len(R['advisoryMatches'])}",
                   style=("brred", "bold") if inr else ("bold",))
        if R["labProbes"]:
            out.kv("gated probes run", ", ".join(sorted(R["labProbes"])))
        if R["errors"]:
            out.kv("errors", len(R["errors"]),
                   "see the evidence file", style=("bryellow", "bold"))
        return R, 0

    except Refused as e:
        out(f"\n[!] {e}")
        R["errors"].append({"stage": "gate", "refused": str(e)})
        return R, 2
    except KeyboardInterrupt:
        out("\n[!] interrupted")
        R["errors"].append({"stage": "run", "error": "interrupted"})
        return R, 130
    except Exception as e:
        # On site the likely events are a device that pauses, a slow hop, or
        # an association closed part way. A traceback on someone's protection
        # relay loses every section after the failure and the summary with
        # them; the evidence file is written by the finally block either way.
        import traceback
        out("")
        out.alert(f"run aborted: {type(e).__name__}: {e}", indent=0)
        out.note("Everything gathered so far is in the evidence file. The "
                 "traceback is recorded there under errors.", indent=0)
        R["errors"].append({"stage": "run", "error": f"{type(e).__name__}: {e}",
                            "traceback": traceback.format_exc()})
        return R, 4
    finally:
        write_json()
        if args.json:
            out(f"\n[+] evidence written to {args.json}")


def resolve_targets(args):
    """-> [(host, port)].

    A target file is one entry per line, `host`, `host:port` or
    `host port`, with `#` comments and blank lines ignored. A bare host uses
    --port. Duplicates are dropped, order is preserved, because a scan you
    can diff against the previous one is worth more than a tidy set.
    """
    out = []
    seen = set()

    def add(host, port):
        host = host.strip()
        if not host:
            return
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append(key)

    if args.targets:
        for raw in Path(args.targets).read_text().splitlines():
            line = raw.split("#")[0].strip()
            if not line:
                continue
            parts = line.replace(",", " ").split()
            host = parts[0]
            port = args.port
            if ":" in host and host.count(":") == 1 and not host.startswith("["):
                host, _, p = host.partition(":")
                port = int(p)
            elif len(parts) > 1:
                port = int(parts[1])
            add(host, port)
    if args.host:
        add(args.host, args.port)
    return out


def target_slug(host, port):
    """A filename-safe stem for one target."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    return f"{safe}_{port}"


def main(argv=None):
    args = build_parser().parse_args(argv)
    # The body still speaks in terms of `deep` and `file_dir`; the CLI now
    # expresses the opposite, because thorough is the default.
    args.deep = not args.quick
    args.file_dir = not args.no_file_dir
    out = Report(args.quiet, color=args.color, tee=args.save)
    if args.no_progress:
        out.status = lambda *a, **k: None
        out.tick = lambda *a, **k: None

    if args.list_probes:
        out("Gated probes. Each needs --lab and an explicit --probes entry.")
        out("")
        for name in sorted(LAB_PROBES):
            meta = LAB_PROBES[name]
            out(f"  {name:14} [risk: {meta['risk']}]")
            out(f"      {meta['summary']}")
        out(f"  {'pool':14} [risk: high]")
        out("      open associations until the device refuses, then release "
            "every one")
        out("      with a Conclude and verify the pool came back. While held, "
            "the")
        out("      device has no slots left for anything else that polls it.")
        return 0

    if args.dry_run:
        out(f"mms_recon.py {__version__} - dry run, no socket will be opened")
        for label, pdu in dry_run_plan(args):
            out("")
            out(f"  {label}")
            out(f"    {pdu.hex()}")
        out("")
        out("  Requests above are shown as the service PDU except where a "
            "full frame is named.")
        return 0

    if not args.host and not args.targets:
        build_parser().error("give a host, or --targets FILE; or --dry-run "
                             "or --list-probes to inspect without "
                             "connecting")

    selected = set()
    if args.probes.strip():
        if args.probes.strip() == "all":
            # "all" means every probe that is not high risk. A high-risk
            # probe must be named, because the documented promise is that a
            # typo cannot start one you did not choose, and "all" is four
            # characters away from several real names.
            selected = {n for n, meta in LAB_PROBES.items()
                        if meta["risk"] != "high"} | {"reduced-osi"}
            out.info("--probes all selected the low and medium risk probes: "
                     f"{', '.join(sorted(selected))}")
            out.info("high-risk probes must be named individually: "
                     f"{', '.join(sorted(n for n, m2 in LAB_PROBES.items() if m2['risk'] == 'high')) or 'pool'}")
        else:
            selected = {x.strip() for x in args.probes.split(",") if x.strip()}
        unknown = selected - set(LAB_PROBES) - {"pool", "reduced-osi"}
        if unknown:
            build_parser().error(f"unknown probe(s): {', '.join(sorted(unknown))}"
                                 f". --list-probes to see them")
    if selected and not args.lab:
        build_parser().error("--probes needs --lab")
    lab = LabGate(enabled=args.lab, selected=selected)

    advisories = None
    if args.advisories:
        try:
            advisories = load_advisories(args.advisories)
        except Exception as e:
            out(f"[!] could not load advisories: {e}")

    ln_classes = set(LN_CLASSES)
    if args.ln_classes:
        ln_classes |= {w.strip().upper()
                       for w in Path(args.ln_classes).read_text().split()
                       if w.strip()}

    signatures = None
    if args.signatures:
        try:
            signatures = load_signatures(args.signatures)
        except Exception as e:
            out(f"[!] could not load signatures: {e}")
            signatures = None

    targets = resolve_targets(args)
    if not targets:
        build_parser().error("no targets: give a host, or --targets FILE")

    outdir = Path(args.out) if args.out else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    if len(targets) > 1 and not outdir and args.json:
        build_parser().error("--json names one file but there are "
                             f"{len(targets)} targets; use --out DIR")

    roll, worst = [], 0
    for n, (host, port) in enumerate(targets, 1):
        targs = argparse.Namespace(**vars(args))
        targs.host, targs.port = host, port
        if outdir:
            slug = target_slug(host, port)
            out.retee(str(outdir / f"{slug}.log"))
            targs.json = (str(outdir / f"{slug}.json")
                          if args.json or args.read_values else None)
        if len(targets) > 1:
            out("")
            out.rule()
            out(out.c(f"  target {n} of {len(targets)}: {host}:{port}",
                      "bold", "brcyan"))
        try:
            R, rc = scan_target(targs, out, advisories, signatures,
                                ln_classes, lab, selected)
        except Exception as e:
            # One unreachable target must not end a sweep.
            out.alert(f"{host}:{port} aborted: {type(e).__name__}: {e}",
                      indent=2)
            R, rc = {"target": {"host": host, "port": port},
                     "errors": [{"stage": "scan", "error": str(e)}]}, 4
        worst = max(worst, rc)
        ident = R.get("identify") or {}
        roll.append({
            "host": host, "port": port, "exit": rc,
            "evidence": targs.json if outdir else args.json,
            "vendor": ident.get("vendor"), "model": ident.get("model"),
            "revision": ident.get("revision"),
            "services": len(R.get("negotiated", {}).get("services", [])),
            "maxPduSize": R.get("negotiated", {}).get("maxPduSize"),
            "nestingLevel": R.get("negotiated", {}).get("nestingLevel"),
            "valt": "valt" in R.get("negotiated", {}).get("parameterCbb", []),
            "domains": len(R.get("domains", [])),
            "objects": sum(len(v.get("names", []))
                           for v in R.get("objects", {}).values()
                           if isinstance(v, dict)),
            "controlObjects": sum(len(v) for v in
                                  R.get("controlModels", {}).values()),
            "advisoriesInRange": len([m2 for m2 in
                                      R.get("advisoryMatches", [])
                                      if m2.get("verdict") == "IN_RANGE"]),
            "errors": len(R.get("errors", [])),
        })
        if outdir:
            (outdir / "index.json").write_text(json.dumps(
                {"tool": "mms_recon.py", "version": __version__,
                 "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 "targets": roll}, indent=2, default=str))

    if len(targets) == 1 and args.save:
        out("")
        out.kv("saved", args.save, "console output, colour preserved")

    if len(targets) > 1:
        out.retee(str(outdir / "sweep.log") if outdir else None)
        out.head("ALL TARGETS")
        out.table(
            ["host:port", "vendor", "model", "svc", "dom", "obj", "ctl",
             "adv", "err"],
            [[f"{r['host']}:{r['port']}", r["vendor"] or "-",
              r["model"] or "-", r["services"], r["domains"], r["objects"],
              r["controlObjects"], r["advisoriesInRange"], r["errors"]]
             for r in roll],
            styles={7: lambda v: ("brred", "bold") if v.strip() not in
                    ("0", "") else ("dim",),
                    8: lambda v: ("bryellow",) if v.strip() not in
                    ("0", "") else ("dim",)})
        reached = [r for r in roll if r["services"]]
        out("")
        out.kv("targets", len(roll))
        out.kv("associated", f"{len(reached)} of {len(roll)}",
               style=("bold",) if len(reached) == len(roll)
               else ("bryellow", "bold"))
        if outdir:
            out.kv("output", str(outdir),
                   "one .log per target, sweep.log, index.json")
    out.close()
    return worst


if __name__ == "__main__":
    sys.exit(main())
