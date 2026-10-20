#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Minimal IDL → libdcerpc coder compiler.

Compiles a small subset of MIDL/PIDL-style IDL into C coder functions that use
the same dcerpc_* helpers as libdcerpc (dcerpc_ptr_coder, dcerpc_uint32_coder,
dcerpc_union_coder, dcerpc_carray_coder, dcerpc_utf16z_coder, …).

Supported:
  - interface attributes: uuid, version, endpoint, pointer_default,
    helpstring / annotation (registration text for dcerpcd serviced)
  - data-only IDL: top-level typedefs with no interface block (coder only)
  - typedef of UTF-16 string handles
  - typedef enum { NAME [= n], ... } Name;  (NDR as uint16 by default; YAML names)
  - typedef [v1_enum] enum { ... } Name;     (NDR as uint32; YAML names;
    the C storage is uint32_t so it can also be a union discriminant)
  - typedef [bitmap32bit] bitmap { NAME = v, [mask(m)] NAME = v, ... } Name;
    a uint32_t flag word; YAML/JSON show "NAME | NAME | rest". A member
    with [mask(m)] is a multi-bit field that matches when
    (value & m) == v, e.g. the 2-bit share type in STYPE_*.
  - const <type> NAME = value;  (a #define)
  - C names of enum, bitmap and const members get the upper-case interface
    prefix (SRVSVC_STYPE_IPC); YAML/JSON use the IDL name (STYPE_IPC).
  - [case(NAME)] may name an enum member instead of a number
  - typedef struct { fields } Name, *LPName;
  - typedef [switch_type(...)] union { [case(n)] T field; } Name;
    an arm is a pointer to a structure (LP*) or the structure itself; a
    plain enum switch_type gives a 16-bit discriminant in NDR32
    (dcerpc_union_enum16_coder), any other a 32-bit one in NDR32 and NDR64
    (dcerpc_union_u32_coder); in NDR64 the arm is aligned to the largest
    arm ([MS-RPCE] 2.2.5.3.4.4), in NDR32 to its own ([C706] 14.3.2: "the
    NDR alignment of a union is determined by the tag type and the arm
    actually to be transmitted"); the largest arm still sets the alignment
    of a structure the union is a member of
  - [out,switch_is(x)] PUNION *param: a pointer to a unique pointer to a
    union, e.g. LsarQueryInformationPolicy's PolicyInformation; the C field
    is a union pointer, NULL for a NULL referent
  - a [size_is(n)] pointer field whose n is a later field of the struct
    (LSAPR_POLICY_AUDIT_EVENTS_INFO): NDR keeps the wire order and sizes
    the deferred array once n is known, YAML/JSON show n first
  - field types: enum Name, or bare Name for a prior typedef enum
  - functions with [opnum(N)], [in]/out], [unique]/ref], [size_is], [switch_is]
  - full pointers: [ptr] on a parameter or field, or "typedef [ptr] T *name"
    for every pointer of that type (PTR_FULL: referent ids 1, 2, ..., and
    the data after each one, as Windows sends them)
    (a union parameter's switch_is may name another parameter; for an [out]
    union switched by an [in]-only parameter the value is taken from the
    request, e.g. NetrShareGetInfo's Level)
  - [size_is(len), blob(T)] uint8_t *field: the bytes hold a packet-form T
    that libdcerpc knows how to code (see BLOB_TYPES, e.g.
    SECURITY_DESCRIPTOR). The C field is T *, NDR is the plain byte array,
    and YAML/JSON show T itself (len is wire-only).
  - builtins: uint8(_t), uint16(_t), uint32(_t), uint64(_t) / hyper,
    int32(_t) / int / long (signed 32-bit), DWORD, WERROR, NTSTATUS
  - libdcerpc built-in types (EXTERN_TYPES): RPC_SID, RPC_UNICODE_STRING
    and RPC_UNICODE_STRINGz / RRP_UNICODE_STRING (C char *), and
    typedef [context_handle] void *T (struct dcerpc_context_handle)
  - [max_length(n)] on an RPC_UNICODE_STRING parameter: MaximumLength is
    at least n bytes, for strings that announce a receive buffer (MS-RRP
    BaseRegEnumKey lpNameIn)
  - typedef T *NAME for an integer T, e.g. PREGISTRY_SERVER_NAME
  - a [unique] parameter pointing to a structure, or of a typedef'd
    pointer to an integer, is a real C pointer: NULL encodes a NULL
    referent and decode allocates the pointee. Other [unique] pointers to
    integers and enums are plain values that are always sent.
  - [size_is(n)] uint8_t *param: a byte array (uint8_t *, hex in
    YAML/JSON); with [length_is(l)] it is conformant-varying, n and l
    naming the parameters with the buffer size and the byte count
  - a [unique] T *field in a struct is a real C pointer: NULL encodes a NULL
    referent and decode allocates the pointee
  - [size_is(m), length_is(l)] uint8_t *field: struct dcerpc_varying_bytes;
    a number m is the max_count always sent (SAMPR_LOGON_HOURS)
  - [in, size_is(n)] T *param: a conformant array parameter; n may be a
    number. With [length_is(l)] it is conformant-varying.
  - a [size_is] array that a sender transmits as a pointer to zero elements
    decodes to NULL, like a NULL pointer
  - uint8_t name[N] in a structure: a fixed-size byte array, coded
    inline with no count (NETLOGON_CREDENTIAL); hex in YAML/JSON
  - arrays of plain values (integers, enums, strings, SIDs) are bare
    YAML/JSON lists (dcerpc_scalar_carray_coder); arrays of structures are
    lists of mappings

Emits:
  - coder .h: type / req / rep structs, enum/bitmap/const constants, opnum
    #defines (e.g. SRVSVC_NETRSHAREENUM 0x0f), coder prototypes,
    extern <iface>_interface and <iface>_procs[]
  - coder .c: p_syntax_id_t <iface>_interface, the coders and
    struct dcerpc_procedure <iface>_procs[] (opnum → req/rep coders + sizes)
  - server .h (<name>_server.h; full interfaces only): <iface>_UUID_STR /
    _VERSION_STR / _ANNOTATION / _PIPE_NAME registration strings, an inline
    <iface>_find_proc(opnum), extern <iface>_stubs[] and the stub
    prototypes. The stubs and the table live in a hand-written stubs .c,
    so clients link the coders only.
  - the IDL's SPDX-License-Identifier is copied into every generated file.

  Data-only files (typedefs only, no interface header) still produce a
  coder .c/.h pair (types + coders). C symbol prefix is the IDL file stem.
  They cannot produce stubs: --stubs requires a full interface.

  Optional --stubs writes a skeleton stubs .c for new interfaces; it
  refuses to overwrite an existing file unless --force-stubs is given
  (so hand-filled implementations are not clobbered on recompile).

  --libdcerpc makes the coder a libdcerpc source file (libdcerpc's include
  set, header included as <dcerpc/NAME.h>, no server header unless
  --server-header is given). --update-syms FILE rewrites the <iface>_*
  lines of a libtool -export-symbols list from the generated coder.

Usage:
  python3 idlcomp.py axpy.idl -o axpy_coder.c
  (also writes axpy_coder.h and axpy_server.h next to the .c)

  python3 idlcomp.py axpy.idl -o axpy_coder.c --stubs
  (also writes axpy_stubs.c skeleton next to the coder)

  python3 idlcomp.py srvsvc/srvsvc.idl --libdcerpc \\
      -o ../libdcerpc/srvsvc/srvsvc_coder.c \\
      --header ../libdcerpc/srvsvc/dcerpc/srvsvc.h \\
      --server-header srvsvc/srvsvc_server.h \\
      --update-syms ../libdcerpc/libdcerpc.syms
  (libdcerpc's srvsvc, plus dcerpcd's server header)

  python3 idlcomp.py config.idl -o config_coder.c
  (data-only typedefs → type coders; --stubs is an error)
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

TOKEN_SPEC = [
    ("COMMENT", r"/\*.*?\*/|//[^\n]*"),
    ("STRING", r'"(?:\\.|[^"\\])*"'),
    # hex, decimals, and simple dotted versions (3.0)
    ("NUMBER", r"0x[0-9A-Fa-f]+|\d+(?:\.\d+)?"),
    ("IDENT", r"[A-Za-z_][A-Za-z0-9_]*"),
    ("LBRACK", r"\["),
    ("RBRACK", r"\]"),
    ("LBRACE", r"\{"),
    ("RBRACE", r"\}"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("COMMA", r","),
    ("SEMI", r";"),
    ("STAR", r"\*"),
    ("EQ", r"="),
    ("MINUS", r"-"),
    # only inside attribute arguments, e.g. length_is((UnitsPerWeek+7)/8)
    ("PLUS", r"\+"),
    ("SLASH", r"/"),
    ("DOT", r"\."),
    ("WS", r"[ \t\r\n]+"),
    ("OTHER", r"."),
]
TOKEN_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in TOKEN_SPEC), re.S)


@dataclass
class Tok:
    kind: str
    value: str
    pos: int


def tokenize(src: str) -> List[Tok]:
    toks: List[Tok] = []
    for m in TOKEN_RE.finditer(src):
        kind = m.lastgroup
        if kind in ("COMMENT", "WS"):
            continue
        if kind == "OTHER":
            raise SyntaxError(f"unexpected character {m.group()!r} at {m.start()}")
        toks.append(Tok(kind, m.group(), m.start()))
    toks.append(Tok("EOF", "", len(src)))
    return toks


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass
class Attr:
    name: str
    args: List[str] = field(default_factory=list)  # raw arg tokens joined


@dataclass
class Field:
    attrs: List[Attr]
    type_name: str
    stars: int  # number of * after type name
    name: str
    array_len: Optional[int] = None  # uint8_t name[N]: fixed-size array


@dataclass
class EnumMember:
    name: str
    value: int  # resolved wire/C value
    mask: Optional[int] = None  # bitmap: multi-bit field mask


@dataclass
class TypeDef:
    kind: str  # "alias" | "struct" | "union" | "enum" | "const"
    # an enum with a "bitmap" attr is a [bitmap32bit] bitmap
    name: str
    attrs: List[Attr] = field(default_factory=list)
    # alias
    base_type: Optional[str] = None
    stars: int = 0
    # struct/union
    fields: List[Field] = field(default_factory=list)
    # pointer aliases declared with the struct: *LPSHARE_INFO_0
    ptr_aliases: List[str] = field(default_factory=list)
    # enum / bitmap
    enum_members: List[EnumMember] = field(default_factory=list)
    # const
    const_value: int = 0
    const_hex: bool = False  # written in hex in the IDL


@dataclass
class Param:
    attrs: List[Attr]
    type_name: str
    stars: int
    name: str


@dataclass
class Function:
    attrs: List[Attr]
    ret_type: str
    name: str
    params: List[Param]


@dataclass
class Interface:
    name: str
    attrs: List[Attr]
    types: List[TypeDef]
    functions: List[Function]
    # False when the IDL is data-only (top-level typedefs, no interface block).
    # Coders are still generated; stubs / UUID / procs require has_interface.
    has_interface: bool = True


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class Parser:
    def __init__(self, toks: List[Tok]):
        self.toks = toks
        self.i = 0

    def cur(self) -> Tok:
        return self.toks[self.i]

    def peek(self, kind: str = None, value: str = None) -> bool:
        t = self.cur()
        if kind and t.kind != kind:
            return False
        if value is not None and t.value != value:
            return False
        return True

    def eat(self, kind: str = None, value: str = None) -> Tok:
        t = self.cur()
        if kind and t.kind != kind:
            raise SyntaxError(f"expected {kind}, got {t.kind} ({t.value!r}) at {t.pos}")
        if value is not None and t.value != value:
            raise SyntaxError(f"expected {value!r}, got {t.value!r} at {t.pos}")
        self.i += 1
        return t

    def parse(self) -> Interface:
        """
        Parse either a full interface IDL or a data-only typedef file.

        Full interface:
          [ uuid(...), version(...), ... ]
          interface Name { typedef ...; [opnum(N)] ret fn(...); }

        Data-only (types / coders only; no stubs):
          typedef struct { ... } Name;
          typedef ...;
        """
        # Leading [attrs] or the interface keyword → full interface form.
        # Top-level [ is only used for interface attributes (typedef attrs
        # come after the typedef keyword).
        if self.peek("LBRACK") or self.peek("IDENT", "interface"):
            return self.parse_interface()
        return self.parse_data_only()

    def parse_interface(self) -> Interface:
        attrs: List[Attr] = []
        if self.peek("LBRACK"):
            attrs = self.parse_attr_list()
        self.eat("IDENT", "interface")
        name = self.eat("IDENT").value
        self.eat("LBRACE")
        types: List[TypeDef] = []
        functions: List[Function] = []
        while not self.peek("RBRACE"):
            if self.peek("IDENT", "typedef"):
                types.append(self.parse_typedef())
            elif self.peek("IDENT", "const"):
                types.append(self.parse_const())
            else:
                functions.append(self.parse_function())
        self.eat("RBRACE")
        # Trailing junk after the interface block is an error.
        if not self.peek("EOF"):
            t = self.cur()
            raise SyntaxError(
                f"unexpected {t.kind} ({t.value!r}) after interface at {t.pos}"
            )
        return Interface(
            name=name,
            attrs=attrs,
            types=types,
            functions=functions,
            has_interface=True,
        )

    def parse_data_only(self) -> Interface:
        """Top-level typedefs only (no interface / functions)."""
        types: List[TypeDef] = []
        while not self.peek("EOF"):
            if self.peek("IDENT", "typedef"):
                types.append(self.parse_typedef())
                continue
            if self.peek("IDENT", "const"):
                types.append(self.parse_const())
                continue
            t = self.cur()
            raise SyntaxError(
                f"data-only IDL allows only typedefs; "
                f"got {t.kind} ({t.value!r}) at {t.pos}"
            )
        if not types:
            raise SyntaxError("empty IDL: expected interface or at least one typedef")
        # name is filled in by main() from the IDL file stem (C symbol prefix)
        return Interface(
            name="",
            attrs=[],
            types=types,
            functions=[],
            has_interface=False,
        )

    def parse_attr_list(self) -> List[Attr]:
        self.eat("LBRACK")
        attrs: List[Attr] = []
        while True:
            attrs.append(self.parse_attr())
            if self.peek("COMMA"):
                self.eat("COMMA")
                continue
            break
        self.eat("RBRACK")
        return attrs

    def parse_attr(self) -> Attr:
        name = self.eat("IDENT").value
        args: List[str] = []
        if self.peek("LPAREN"):
            self.eat("LPAREN")
            depth = 1
            parts: List[str] = []
            while depth:
                t = self.cur()
                if t.kind == "LPAREN":
                    depth += 1
                    parts.append(t.value)
                    self.i += 1
                elif t.kind == "RPAREN":
                    depth -= 1
                    if depth:
                        parts.append(t.value)
                    self.i += 1
                elif t.kind == "EOF":
                    raise SyntaxError("unterminated attribute args")
                else:
                    parts.append(t.value)
                    self.i += 1
            args = ["".join(parts).strip()] if parts else []
        return Attr(name=name, args=args)

    def parse_number(self) -> int:
        neg = False
        if self.peek("MINUS"):
            self.eat("MINUS")
            neg = True
        val = int(self.eat("NUMBER").value, 0)
        return -val if neg else val

    def parse_const(self) -> TypeDef:
        """const <type> NAME = value;"""
        self.eat("IDENT", "const")
        self.eat("IDENT")  # type: only integers are supported
        name = self.eat("IDENT").value
        self.eat("EQ")
        hexa = self.peek("NUMBER") and self.cur().value.lower().startswith("0x")
        val = self.parse_number()
        self.eat("SEMI")
        return TypeDef(kind="const", name=name, const_value=val, const_hex=hexa)

    def parse_typedef(self) -> TypeDef:
        self.eat("IDENT", "typedef")
        attrs: List[Attr] = []
        if self.peek("LBRACK"):
            attrs = self.parse_attr_list()

        if self.peek("IDENT", "struct"):
            return self.parse_struct_typedef(attrs)
        if self.peek("IDENT", "union"):
            return self.parse_union_typedef(attrs)
        if self.peek("IDENT", "enum"):
            return self.parse_enum_typedef(attrs)
        if self.peek("IDENT", "bitmap"):
            return self.parse_enum_typedef(attrs, bitmap=True)

        # alias: typedef [attrs] base *** Name;
        base = self.eat("IDENT").value
        stars = 0
        while self.peek("STAR"):
            self.eat("STAR")
            stars += 1
        name = self.eat("IDENT").value
        self.eat("SEMI")
        return TypeDef(kind="alias", name=name, attrs=attrs, base_type=base, stars=stars)

    def parse_struct_typedef(self, attrs: List[Attr]) -> TypeDef:
        self.eat("IDENT", "struct")
        # optional tag
        if self.peek("IDENT"):
            self.eat("IDENT")
        self.eat("LBRACE")
        fields: List[Field] = []
        while not self.peek("RBRACE"):
            fields.append(self.parse_field())
        self.eat("RBRACE")
        name = self.eat("IDENT").value
        ptr_aliases: List[str] = []
        while self.peek("COMMA"):
            self.eat("COMMA")
            while self.peek("STAR"):
                self.eat("STAR")
            ptr_aliases.append(self.eat("IDENT").value)
        self.eat("SEMI")
        return TypeDef(
            kind="struct",
            name=name,
            attrs=attrs,
            fields=fields,
            ptr_aliases=ptr_aliases,
        )

    def parse_union_typedef(self, attrs: List[Attr]) -> TypeDef:
        self.eat("IDENT", "union")
        if self.peek("IDENT"):
            self.eat("IDENT")
        self.eat("LBRACE")
        fields: List[Field] = []
        while not self.peek("RBRACE"):
            fields.append(self.parse_field())
        self.eat("RBRACE")
        name = self.eat("IDENT").value
        ptr_aliases: List[str] = []
        while self.peek("COMMA"):
            self.eat("COMMA")
            while self.peek("STAR"):
                self.eat("STAR")
            ptr_aliases.append(self.eat("IDENT").value)
        self.eat("SEMI")
        return TypeDef(
            kind="union",
            name=name,
            attrs=attrs,
            fields=fields,
            ptr_aliases=ptr_aliases,
        )

    def parse_enum_typedef(self, attrs: List[Attr], bitmap: bool = False) -> TypeDef:
        """
        typedef enum [tag] {
            NAME [= value],
            ...
        } Name [, *PName];
        Unspecified values follow C rules (0, then previous+1).
        """
        self.eat("IDENT", "bitmap" if bitmap else "enum")
        if self.peek("IDENT"):
            self.eat("IDENT")  # optional tag
        self.eat("LBRACE")
        members: List[EnumMember] = []
        next_val = 0
        while not self.peek("RBRACE"):
            mattrs: List[Attr] = []
            if bitmap and self.peek("LBRACK"):
                mattrs = self.parse_attr_list()
            mname = self.eat("IDENT").value
            if self.peek("EQ"):
                self.eat("EQ")
                next_val = self.parse_number()
            elif bitmap:
                raise SyntaxError(f"bitmap member {mname} needs a value")
            members.append(EnumMember(name=mname, value=next_val,
                                      mask=attr_int(mattrs, "mask")))
            next_val += 1
            if self.peek("COMMA"):
                self.eat("COMMA")
                # allow trailing comma before }
                if self.peek("RBRACE"):
                    break
                continue
            break
        self.eat("RBRACE")
        name = self.eat("IDENT").value
        ptr_aliases: List[str] = []
        while self.peek("COMMA"):
            self.eat("COMMA")
            while self.peek("STAR"):
                self.eat("STAR")
            ptr_aliases.append(self.eat("IDENT").value)
        self.eat("SEMI")
        if not members:
            raise SyntaxError(f"enum {name} has no members")
        if bitmap:
            attrs = attrs + [Attr(name="bitmap")]
        return TypeDef(
            kind="enum",
            name=name,
            attrs=attrs,
            enum_members=members,
            ptr_aliases=ptr_aliases,
        )

    def parse_type_name(self) -> Tuple[str, int]:
        """
        Type specifier + optional *s.
        Accepts: Type, enum Type, struct Type, union Type.
        """
        if self.peek("IDENT", "enum") or self.peek("IDENT", "struct") or self.peek(
            "IDENT", "union"
        ):
            self.eat("IDENT")  # enum / struct / union keyword
            type_name = self.eat("IDENT").value
        else:
            type_name = self.eat("IDENT").value
        stars = 0
        while self.peek("STAR"):
            self.eat("STAR")
            stars += 1
        return type_name, stars

    def parse_field(self) -> Field:
        attrs: List[Attr] = []
        if self.peek("LBRACK"):
            attrs = self.parse_attr_list()
        type_name, stars = self.parse_type_name()
        name = self.eat("IDENT").value
        array_len = None
        if self.peek("LBRACK"):
            self.eat("LBRACK")
            array_len = self.parse_number()
            self.eat("RBRACK")
            if (type_name not in ("uint8", "uint8_t") or stars or attrs
                    or array_len <= 0):
                raise SyntaxError(f"fixed-size arrays are only supported as "
                                  f"uint8_t {name}[N] ({name})")
        self.eat("SEMI")
        return Field(attrs=attrs, type_name=type_name, stars=stars, name=name,
                     array_len=array_len)

    def parse_function(self) -> Function:
        attrs: List[Attr] = []
        if self.peek("LBRACK"):
            attrs = self.parse_attr_list()
        ret = self.eat("IDENT").value
        name = self.eat("IDENT").value
        self.eat("LPAREN")
        params: List[Param] = []
        if not self.peek("RPAREN"):
            while True:
                params.append(self.parse_param())
                if self.peek("COMMA"):
                    self.eat("COMMA")
                    continue
                break
        self.eat("RPAREN")
        self.eat("SEMI")
        return Function(attrs=attrs, ret_type=ret, name=name, params=params)

    def parse_param(self) -> Param:
        attrs: List[Attr] = []
        if self.peek("LBRACK"):
            attrs = self.parse_attr_list()
        type_name, stars = self.parse_type_name()
        name = self.eat("IDENT").value
        # T name[]: an array parameter, passed by reference like T *name
        if self.peek("LBRACK"):
            self.eat("LBRACK")
            self.eat("RBRACK")
            stars += 1
        return Param(attrs=attrs, type_name=type_name, stars=stars, name=name)


# ---------------------------------------------------------------------------
# Semantic helpers
# ---------------------------------------------------------------------------

# IDL scalar name → C type
# DCE/RPC classical names: hyper is 64-bit (we map to uint64_t for wire coders).
BUILTINS = {
    "uint8": "uint8_t",
    "uint8_t": "uint8_t",
    "uint16": "uint16_t",
    "uint16_t": "uint16_t",
    "uint32": "uint32_t",
    "uint32_t": "uint32_t",
    "uint64": "uint64_t",
    "uint64_t": "uint64_t",
    "hyper": "uint64_t",
    "int32": "int32_t",
    "int32_t": "int32_t",
    "int": "int32_t",
    "long": "int32_t",
    "DWORD": "uint32_t",
    "WERROR": "uint32_t",
    "NTSTATUS": "uint32_t",
    "error_status_t": "uint32_t",
}

# Function return types that are a status value at the end of the reply
STATUS_TYPES = ("WERROR", "NTSTATUS", "DWORD", "uint32", "error_status_t")

# C type → dcerpc_*_coder for NDR/YAML/JSON
BUILTIN_CODERS = {
    "uint8_t": "dcerpc_uint8_coder",
    "uint16_t": "dcerpc_uint16_coder",
    "uint32_t": "dcerpc_uint32_coder",
    "int32_t": "dcerpc_uint32_coder",  # same 4-byte NDR coding
    "uint64_t": "dcerpc_uint64_coder",
}


def builtin_coder(tname: str) -> Optional[str]:
    """Return dcerpc_*_coder name for a builtin IDL type, or None."""
    ctype = BUILTINS.get(tname)
    if ctype is None:
        return None
    return BUILTIN_CODERS.get(ctype)


# libdcerpc built-in types an IDL can use directly (MS-DTYP base types with
# their own coder-table slots): IDL name -> (C type, coder, header).
EXTERN_TYPES = {
    "RPC_SID": ("RPC_SID", "dcerpc_sid_coder", "dcerpc/dcerpc-dtyp.h"),
    "RPC_UNICODE_STRING": ("char *", "dcerpc_RPC_UNICODE_STRING_coder", None),
    # MS-RRP RRP_UNICODE_STRING: NUL-terminated Buffer
    "RPC_UNICODE_STRINGz": ("char *", "dcerpc_RPC_UNICODE_STRINGz_coder", None),
    "RRP_UNICODE_STRING": ("char *", "dcerpc_RPC_UNICODE_STRINGz_coder", None),
    # GUID
    "uuid_t": ("dcerpc_uuid_t", "dcerpc_uuid_coder", None),
    # C706 endpoint mapper: the protocol tower, a conformant structure, and
    # [string] char annotation[64], coded in dcerpc-epm.c
    "twr_t": ("struct epm_twr_t", "dcerpc_epm_twr_struct_coder", None),
    "EPM_ANNOTATION": ("char *", "dcerpc_epm_annotation_coder", None),
}

# Built-in types that are structures in YAML/JSON (a mapping, not a value)
STRUCTURED_EXTERNS = ("twr_t",)

# typedef [context_handle] void *NAME; -> this C type and coder
CONTEXT_HANDLE = ("struct dcerpc_context_handle", "dcerpc_context_handle_coder", None)


# Types implemented in libdcerpc that a [blob(T)] byte array may carry:
# T -> (C type, coder, header to include).
BLOB_TYPES = {
    "SECURITY_DESCRIPTOR": (
        "SECURITY_DESCRIPTOR",
        "dcerpc_SECURITY_DESCRIPTOR_coder",
        "dcerpc/dcerpc-dtyp.h",
    ),
}


def blob_type(f) -> Optional[Tuple[str, str, str]]:
    """BLOB_TYPES entry for a [blob(T)] field, or None."""
    name = attr_arg(f.attrs, "blob")
    if name is None:
        return None
    if name not in BLOB_TYPES:
        raise SystemExit(f"error: field {f.name}: unknown blob type {name} "
                         f"(known: {', '.join(sorted(BLOB_TYPES))})")
    if attr_arg(f.attrs, "size_is") is None:
        raise SystemExit(f"error: field {f.name}: blob() needs size_is()")
    return BLOB_TYPES[name]


def blob_len_fields(t) -> Dict[str, object]:
    """size_is field name -> the [blob] field it sizes, for one struct."""
    out: Dict[str, object] = {}
    names = [x.name for x in t.fields]
    for f in t.fields:
        if blob_type(f) is None:
            continue
        ln = attr_arg(f.attrs, "size_is")
        if ln not in names or names.index(ln) > names.index(f.name):
            raise SystemExit(f"error: {t.name}.{f.name}: blob length field "
                             f"{ln} must be a field declared before it")
        out[ln] = f
    return out


def attr_has(attrs: List[Attr], name: str) -> bool:
    return any(a.name == name for a in attrs)


def attr_arg(attrs: List[Attr], name: str) -> Optional[str]:
    for a in attrs:
        if a.name == name and a.args:
            return a.args[0]
    return None


def attr_int(attrs: List[Attr], name: str, default: Optional[int] = None) -> Optional[int]:
    a = attr_arg(attrs, name)
    if a is None:
        return default
    return int(a, 0)


def field_expr(expr: str, var: str) -> str:
    """
    A size_is/length_is expression over sibling fields as C, e.g.
    (UnitsPerWeek+7)/8 -> (s->UnitsPerWeek+7)/8.
    """
    return re.sub(r"\b([A-Za-z_]\w*)\b", lambda m: f"{var}->{m.group(1)}", expr)


def varying_bytes_sizes_lines(f: Field, var: str, indent: str) -> List[str]:
    """
    Set size_is and length_is for dcerpc_varying_bytes_checked_coder(),
    which checks the decoded bytes against them; the fields they come
    from precede the pointer, and a deferred pointer keeps both.
    """
    return [
        f"{indent}dcerpc_set_size_is(pdu, {field_expr(attr_arg(f.attrs, 'size_is'), var)});",
        f"{indent}dcerpc_set_length_is(pdu, {field_expr(attr_arg(f.attrs, 'length_is'), var)});",
    ]


def range_check_lines(attrs: List[Attr], value: str, indent: str) -> List[str]:
    """
    [range(lo, hi)] on a scalar: the peer's value must be in it on decode.
    The IDLs put it on the counts that size arrays (lsa's Entries, the
    Count of LookupNames, ...), so it bounds what a peer can ask for.
    """
    r = attr_arg(attrs, "range")
    if r is None:
        return []
    lo_s, _, hi_s = r.partition(",")
    lo, hi = int(lo_s.strip(), 0), int(hi_s.strip(), 0)
    cond = f"{value} > {hi}"
    if lo > 0:
        cond = f"{value} < {lo} || {cond}"
    return [
        f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&\n"
        f"{indent}    ({cond})) {{\n"
        f"{indent}        return -1;\n"
        f"{indent}}}"
    ]


def unique_string_field_lines(indent: str, disp: str, var: str,
                              field: str) -> List[str]:
    """
    Coder call for a [unique] string field of a structure. A NULL field is
    a NULL referent (NDR) or a missing key (YAML/JSON), not "", so pass a
    NULL pointer when encoding it, as for [unique] string parameters.
    """
    return [
        f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
        f"{indent}    {var}->{field} == NULL) {{\n"
        f'{indent}        if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, NULL,\n'
        f"{indent}                             PTR_UNIQUE, dcerpc_utf16z_coder)) {{\n"
        f"{indent}                return -1;\n"
        f"{indent}        }}\n"
        f"{indent}}} else if (dcerpc_ptr_coder(\"{disp}\", dce, pdu, iov, &{var}->{field},\n"
        f"{indent}                            PTR_UNIQUE, dcerpc_utf16z_coder)) {{\n"
        f"{indent}        return -1;\n"
        f"{indent}}}"
    ]


def c_string_literal(s: str) -> str:
    """Emit a C string literal, escaping backslashes and quotes."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def attr_unquoted(attrs: List[Attr], name: str) -> Optional[str]:
    """
    Attribute argument as a plain string: strip surrounding "…" if present
    (STRING tokens keep the quotes in the raw join).
    """
    a = attr_arg(attrs, name)
    if a is None:
        return None
    a = a.strip()
    if len(a) >= 2 and a[0] == '"' and a[-1] == '"':
        inner = a[1:-1]
        # Unescape the small set IDL strings use.
        out: List[str] = []
        i = 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                out.append(inner[i + 1])
                i += 2
            else:
                out.append(inner[i])
                i += 1
        return "".join(out)
    return a


def pipe_base_from_endpoint(endpoint: Optional[str]) -> Optional[str]:
    """
    From endpoint("ncacn_np:[\\pipe\\srvsvc]") return "srvsvc".
    Used for registration name when the C interface is prefixed.
    """
    if not endpoint:
        return None
    lower = endpoint.lower()
    for marker in ("\\pipe\\", "/pipe/"):
        i = lower.find(marker)
        if i < 0:
            continue
        rest = endpoint[i + len(marker) :]
        for stop in ("]", ":", "\\", "/"):
            j = rest.find(stop)
            if j >= 0:
                rest = rest[:j]
        rest = rest.strip()
        return rest if rest else None
    return None


class TypeEnv:
    """Resolve IDL type names to codegen facts."""

    def __init__(self, iface: Interface):
        self.iface = iface
        self.prefix = iface.name  # C symbol prefix, e.g. srvsvc
        self.types: Dict[str, TypeDef] = {t.name: t for t in iface.types}
        # LPFoo → Foo for pointer aliases declared with struct
        self.ptr_to_base: Dict[str, str] = {}
        # Foo → LPFoo (first alias)
        self.base_to_ptr: Dict[str, str] = {}
        # string aliases (handles): name → True
        self.string_aliases: Dict[str, TypeDef] = {}

        # typedef [context_handle] void *NAME
        self.context_handles: Dict[str, TypeDef] = {}
        # typedef T *NAME for an integer or enum T: NAME → (T, stars)
        self.scalar_ptr_aliases: Dict[str, Tuple[str, int]] = {}

        for t in iface.types:
            if t.kind == "alias" and attr_has(t.attrs, "context_handle"):
                self.context_handles[t.name] = t
                continue
            if t.kind == "alias":
                if attr_has(t.attrs, "string") or (
                    t.base_type in ("uint16", "uint16_t")
                    and t.stars >= 1
                    and attr_has(t.attrs, "charset")
                ):
                    self.string_aliases[t.name] = t
                elif t.stars >= 1 and (t.base_type in BUILTINS or
                                       t.base_type in self.types or
                                       t.base_type in EXTERN_TYPES):
                    self.scalar_ptr_aliases[t.name] = (t.base_type, t.stars)
            if t.kind in ("struct", "union"):
                for pa in t.ptr_aliases:
                    self.ptr_to_base[pa] = t.name
                    self.base_to_ptr.setdefault(t.name, pa)

    def is_string_type(self, type_name: str, stars: int, attrs: List[Attr]) -> bool:
        if attr_has(attrs, "string"):
            return True
        if type_name in self.string_aliases:
            return True
        if type_name in ("uint16", "uint16_t") and stars >= 1 and attr_has(
            attrs, "charset"
        ):
            return True
        return False

    def resolve_pointee(self, type_name: str, stars: int) -> Tuple[str, int]:
        """Peel LP* aliases into base type + remaining stars."""
        while type_name in self.ptr_to_base and stars == 0:
            type_name = self.ptr_to_base[type_name]
            stars += 1
        if type_name in self.scalar_ptr_aliases:
            type_name, n = self.scalar_ptr_aliases[type_name]
            stars += n
        if type_name in self.types and self.types[type_name].kind == "alias":
            # leave alias as-is for string handles
            pass
        return type_name, stars

    def extern(self, type_name: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """(C type, coder, header) for a libdcerpc built-in type, else None."""
        if type_name in self.context_handles:
            return CONTEXT_HANDLE
        return EXTERN_TYPES.get(type_name)

    def ptr_helper_name(self, type_name: str) -> str:
        """Coder for a nullable [unique] T * field (allocates on decode)."""
        return f"{self.prefix}_{type_name}_ptr_coder"

    def c_struct_name(self, type_name: str) -> str:
        return f"struct {self.prefix}_{type_name}"

    def c_union_name(self, type_name: str) -> str:
        return f"union {self.prefix}_{type_name}"

    def c_enum_name(self, type_name: str) -> str:
        """C storage type for an enum/bitmap field."""
        if self.is_u32_enum(type_name):
            return "uint32_t"
        return f"enum {self.prefix}_{type_name}"

    def is_u32_enum(self, type_name: str) -> bool:
        """[v1_enum] enums and bitmaps are stored as uint32_t."""
        td = self.types.get(type_name)
        return td is not None and td.kind == "enum" and (
            attr_has(td.attrs, "v1_enum") or attr_has(td.attrs, "bitmap"))

    def const_name(self, member: str) -> str:
        """C name of an enum/bitmap/const member: SRVSVC_STYPE_IPC."""
        return f"{self.prefix.upper()}_{member}"

    def case_value(self, f: "Field") -> Optional[str]:
        """[case(N)] or [case(ENUM_MEMBER)] → C expression."""
        a = attr_arg(f.attrs, "case")
        if a is None:
            return None
        try:
            return str(int(a, 0))
        except ValueError:
            pass
        for t in self.iface.types:
            if t.kind == "enum" and any(m.name == a for m in t.enum_members):
                return self.const_name(a)
        raise SystemExit(f"error: unknown case label {a}")

    def is_enum(self, type_name: str) -> bool:
        td = self.types.get(type_name)
        return td is not None and td.kind == "enum"

    def coder_name(self, type_name: str) -> str:
        return f"{self.prefix}_{type_name}_coder"

    def struct_coder_name(self, type_name: str) -> str:
        return f"{self.prefix}_{type_name}_struct_coder"

    def carray_coder_name(self, type_name: str) -> str:
        """type_name is an array element key: T, or T* (pointers to T)."""
        if type_name.endswith("*"):
            return f"{self.prefix}_{type_name[:-1]}_ptr_carray_coder"
        return f"{self.prefix}_{type_name}_carray_coder"

    def cvarray_coder_name(self, type_name: str) -> str:
        """As carray_coder_name, for a conformant-varying array."""
        if type_name.endswith("*"):
            return f"{self.prefix}_{type_name[:-1]}_ptr_cvarray_coder"
        return f"{self.prefix}_{type_name}_cvarray_coder"

    def elem_coder_name(self, type_name: str) -> str:
        """Element coder of an array of structures."""
        return f"{self.prefix}_{type_name}_elem_coder"

    def pelem_coder_name(self, type_name: str) -> str:
        """Element coder of an array of nullable pointers to type_name."""
        return f"{self.prefix}_{type_name}_pelem_coder"

    def enum_pp_name(self, type_name: str) -> str:
        return f"{self.prefix}_{type_name}_pp"


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------


HEADER_TEMPLATE = """\
/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
{license}/*
 * AUTO-GENERATED by idlcomp.py from {idl_name} — do not edit.
 *
 * Types and coders are derived from the IDL; field names follow the IDL.
 */
#ifndef _{guard}_
#define _{guard}_

#ifdef __cplusplus
extern "C" {{
#endif

#include <stddef.h>
#include <stdint.h>

#include <dcerpc/dcerpc.h>
{includes}
{body}

#ifdef __cplusplus
}}
#endif

#endif /* !_{guard}_ */
"""

C_HEADER = """\
/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
{license}/*
 * AUTO-GENERATED by idlcomp.py from {idl_name} — do not edit.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>

#include "{header_name}"

/* Not in the public dcerpc.h; exported by libdcerpc */
uint32_t dcerpc_pdu_direction(struct dcerpc_pdu *pdu);
enum dcerpc_encoding dcerpc_pdu_encoding(struct dcerpc_pdu *pdu);
int dcerpc_pdu_is_conformance_run(struct dcerpc_pdu *pdu);
void *dcerpc_alloc_array(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                         uint64_t count, size_t esize);
int dcerpc_varying_bytes_checked_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct dcerpc_iovec *iov, void *ptr);

"""

# --libdcerpc: the coder is part of libdcerpc itself (libdcerpc/dcerpc-*.c)
C_HEADER_LIBDCERPC = """\
/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
{license}/*
 * AUTO-GENERATED by idlcomp.py from {idl_name} — do not edit.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif

#include <errno.h>
#include <stdio.h>


#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/{header_name}>
#include "dcerpc-private.h"
"""

SERVER_HEADER_TEMPLATE = """\
/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
{license}/*
 * AUTO-GENERATED by idlcomp.py from {idl_name} — do not edit.
 *
 * Server-side declarations for dcerpcd services: registration strings,
 * the stub table and the stub prototypes. Clients only need {coder_header}.
 */
#ifndef _{guard}_
#define _{guard}_

#ifdef __cplusplus
extern "C" {{
#endif

#include {coder_include}

{body}

#ifdef __cplusplus
}}
#endif

#endif /* !_{guard}_ */
"""


def gen_c_type_for_field(env: TypeEnv, f: Field) -> str:
    """C type of a struct/union field."""
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    size_is = attr_arg(f.attrs, "size_is")

    bt = blob_type(f)
    if bt is not None:
        return f"{bt[0]} *"

    if env.is_string_type(f.type_name, f.stars, f.attrs) or tname in env.string_aliases:
        return "char *"

    if is_varying_bytes(f, tname):
        return "struct dcerpc_varying_bytes"

    if size_is is not None and stars >= 2:
        # conformant array of pointers to elements
        return c_ptr(c_ptr(pointee_ctype_coder(env, tname)[0]))

    ext = env.extern(tname)
    if ext is not None:
        # by value, or a nullable [unique] pointer / conformant array
        return ext[0] if stars == 0 and size_is is None else c_ptr(ext[0])

    if size_is is not None:
        # conformant array of elements → pointer to element
        if tname in env.types and env.types[tname].kind == "struct":
            return f"{env.c_struct_name(tname)} *"
        if tname in env.types and env.types[tname].kind == "enum":
            return f"{env.c_enum_name(tname)} *"
        if tname in BUILTINS:
            return f"{BUILTINS[tname]} *"
        return f"{env.c_struct_name(tname)} *"

    if tname in env.types:
        td = env.types[tname]
        if td.kind == "struct":
            if stars >= 1:
                # nullable [unique] pointer (union arms embed instead, see
                # gen_union_field_ctype)
                return f"{env.c_struct_name(tname)} *"
            return env.c_struct_name(tname)
        if td.kind == "union":
            return env.c_union_name(tname)
        if td.kind == "enum":
            if stars:
                return f"{env.c_enum_name(tname)} *"
            return env.c_enum_name(tname)
        if td.kind == "alias" and tname in env.string_aliases:
            return "char *"

    if tname in BUILTINS:
        if stars:
            # top-level out/ref scalars become non-pointer fields in req/rep;
            # for struct fields with explicit stars keep pointer.
            return f"{BUILTINS[tname]} *"
        return BUILTINS[tname]

    if stars:
        return f"void *"
    return f"/* unknown {tname} */ void *"


def c_ptr(ctype: str) -> str:
    """Pointer to ctype, spelled like the rest of the generated code."""
    return ctype + ("*" if ctype.endswith("*") else " *")


def is_varying_bytes(f: Field, tname: str) -> bool:
    """[size_is(m), length_is(l)] uint8 *: a struct dcerpc_varying_bytes."""
    if attr_arg(f.attrs, "length_is") is None:
        return False
    if tname not in ("uint8", "uint8_t") or attr_arg(f.attrs, "size_is") is None:
        raise SystemExit(f"error: length_is is only supported for "
                         f"[size_is] uint8_t arrays ({f.name})")
    return True


def nullable_ptr_field(env: TypeEnv, f: Field) -> Optional[str]:
    """
    Pointee type name for a [unique] T *field that is a real, nullable C
    pointer: a pointer to a struct, a libdcerpc built-in type or a scalar
    (not strings, arrays, blobs or varying byte buffers).
    """
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    if stars < 1 or attr_arg(f.attrs, "size_is") is not None:
        return None
    if blob_type(f) is not None or env.is_string_type(f.type_name, f.stars, f.attrs):
        return None
    if tname in env.string_aliases:
        return None
    if env.extern(tname) is not None or tname in BUILTINS:
        return tname
    if tname in env.types and env.types[tname].kind in ("struct", "enum"):
        return tname
    return None


def is_full_ptr(env: TypeEnv, type_name: str, attrs) -> bool:
    """
    A full pointer ([ptr]): declared so, or of a "typedef [ptr] T *name"
    type (epm's twr_p_t). libdcerpc codes it as PTR_FULL: numbered
    referent ids, and the data after every one, as Windows does.
    """
    if attr_has(attrs, "ptr"):
        return True
    td = env.types.get(type_name)
    return td is not None and td.kind == "alias" and attr_has(td.attrs, "ptr")


def full_ptr_pointees(env: TypeEnv) -> List[str]:
    """Types T with a "typedef [ptr] T *name": pointers to them are full."""
    return [t.base_type for t in env.iface.types
            if t.kind == "alias" and t.stars == 1 and attr_has(t.attrs, "ptr")]


def ptr_kind(env: TypeEnv, type_name: str, attrs) -> str:
    return "PTR_FULL" if is_full_ptr(env, type_name, attrs) else "PTR_UNIQUE"


def nullable_param(env: TypeEnv, p: Param) -> Optional[str]:
    """
    Pointee type name for a [unique] parameter that is a real, nullable C
    pointer: a pointer to a structure, a typedef'd pointer to an integer
    (PREGISTRY_SERVER_NAME), or [out] RPC_SID **. NULL encodes a NULL referent and decode
    allocates the pointee. Other [unique] pointers to integers and enums
    (ResumeHandle) are values that are always sent.
    """
    if attr_arg(p.attrs, "size_is") is not None:
        return None
    # [out] RPC_SID **: a [ref] pointer to a unique SID pointer, e.g.
    # SamrLookupDomainInSamServer's DomainId; NULL when the server sends
    # no SID
    if (p.stars == 2 and p.type_name == "RPC_SID" and
            not attr_has(p.attrs, "unique")):
        return p.type_name
    if not attr_has(p.attrs, "unique") and not attr_has(p.attrs, "ptr"):
        return None
    if env.is_string_type(p.type_name, p.stars, p.attrs):
        return None
    tname, stars = env.resolve_pointee(p.type_name, p.stars)
    if stars != 1:
        return None
    if tname in env.types and env.types[tname].kind == "struct":
        return tname
    if p.stars == 0 and p.type_name in env.scalar_ptr_aliases:
        return tname
    return None


def byte_array_param(env: TypeEnv, p: Param) -> bool:
    """
    [size_is(n)] uint8_t *: a byte array parameter, uint8_t * in C. With
    [length_is(l)] it is conformant-varying: n is the buffer size and l
    the number of bytes sent. YAML/JSON show the bytes as a hex string.
    """
    if attr_arg(p.attrs, "size_is") is None:
        return False
    tname, stars = env.resolve_pointee(p.type_name, p.stars)
    return tname in ("uint8", "uint8_t") and stars == 1


def pointee_ctype_coder(env: TypeEnv, tname: str) -> Tuple[str, str]:
    """C type and coder of a pointee/element type."""
    ext = env.extern(tname)
    if ext is not None:
        return ext[0], ext[1]
    if tname in BUILTINS:
        return BUILTINS[tname], (builtin_coder(tname) or "dcerpc_uint32_coder")
    td = env.types[tname]
    if td.kind == "struct":
        return env.c_struct_name(tname), env.struct_coder_name(tname)
    if td.kind == "enum":
        return env.c_enum_name(tname), env.coder_name(tname)
    raise SystemExit(f"error: unsupported pointee type {tname}")


def array_elem(env: TypeEnv, f) -> str:
    """
    Element key of a [size_is] array field or parameter: the element type
    name, or "T*" for an array of (nullable, unique) pointers to T.
    """
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    return tname + "*" if stars >= 2 else tname


def is_scalar_elem(env: TypeEnv, tname: str) -> bool:
    """
    Array elements that are plain values (integers, enums, strings, SIDs, or
    pointers to them): YAML/JSON show such arrays as bare lists, without
    per-element keys.
    """
    tname = tname.rstrip("*")
    if tname in BUILTINS or (tname in EXTERN_TYPES and
                             tname not in STRUCTURED_EXTERNS):
        return True
    td = env.types.get(tname)
    return td is not None and td.kind == "enum"


def const_literal(v: int, hexa: bool = False) -> str:
    """C literal for a constant; values above INT_MAX need an unsigned suffix."""
    if v < 0:
        return str(v)
    lit = f"0x{v:08x}" if hexa else str(v)
    return lit + ("U" if v > 0x7fffffff else "")


def gen_union_field_ctype(env: TypeEnv, f: Field) -> str:
    """Union arms that are LP* containers are embedded structs (libdcerpc style)."""
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    if env.is_string_type(f.type_name, f.stars, f.attrs) or tname in env.string_aliases:
        return "char *"
    if tname in env.types and env.types[tname].kind == "struct":
        return env.c_struct_name(tname)
    if tname in env.types and env.types[tname].kind == "union":
        return env.c_union_name(tname)
    if tname in env.types and env.types[tname].kind == "enum":
        return env.c_enum_name(tname) + (" *" if stars else "")
    if tname in BUILTINS:
        return BUILTINS[tname] + (" *" if stars else "")
    return env.c_struct_name(tname)


def gen_struct_defs(env: TypeEnv) -> str:
    lines: List[str] = []
    defined: Dict[str, int] = {}  # bitmap member → value, to define once
    # Forward-declare nothing; emit in IDL order (types may reference earlier ones)
    for t in env.iface.types:
        if t.kind == "alias":
            if t.name in env.string_aliases:
                lines.append(f"/* {t.name}: UTF-16 string handle → char * */")
            continue
        if t.kind == "const":
            lines.append(f"#define {env.const_name(t.name)} {const_literal(t.const_value, hexa=t.const_hex)}")
            lines.append("")
            continue
        if t.kind == "enum" and attr_has(t.attrs, "bitmap"):
            lines.append(f"/* {t.name}: bitmap, stored as uint32_t */")
            w = max(len(env.const_name(m.name)) for m in t.enum_members)
            for m in t.enum_members:
                # a flag may be shared between bitmaps (ACCESS_* in share
                # and file permissions): define it once
                prev = defined.get(m.name)
                if prev is not None:
                    if prev != m.value:
                        raise SystemExit(f"error: {m.name} redefined with a different value")
                    continue
                defined[m.name] = m.value
                lines.append(f"#define {env.const_name(m.name):<{w}} {const_literal(m.value, hexa=True)}")
            lines.append("")
            continue
        if t.kind == "enum":
            if env.is_u32_enum(t.name):
                lines.append(f"/* {t.name}: stored as uint32_t */")
            lines.append(f"enum {env.prefix}_{t.name} {{")
            for i, m in enumerate(t.enum_members):
                comma = "," if i + 1 < len(t.enum_members) else ""
                # Emit both name and value so C matches the IDL / wire values.
                lines.append(f"        {env.const_name(m.name)} = {m.value}{comma}")
            lines.append("};")
            lines.append("")
            continue
        if t.kind == "struct":
            lines.append(f"{env.c_struct_name(t.name)} {{")
            for f in t.fields:
                ctype = gen_c_type_for_field(env, f)
                dim = f"[{f.array_len}]" if f.array_len is not None else ""
                lines.append(f"        {ctype} {f.name}{dim};")
            lines.append("};")
            lines.append("")
        elif t.kind == "union":
            lines.append(f"{env.c_union_name(t.name)} {{")
            for f in t.fields:
                if f.array_len is not None:
                    raise SystemExit(f"error: fixed-size array {f.name} "
                                     f"as a union arm is not supported")
                ctype = gen_union_field_ctype(env, f)
                lines.append(f"        {ctype} {f.name};")
            lines.append("};")
            lines.append("")
    return "\n".join(lines)


def param_directions(p: Param) -> Tuple[bool, bool]:
    inn = attr_has(p.attrs, "in")
    out = attr_has(p.attrs, "out")
    if not inn and not out:
        inn = True
    return inn, out


def gen_req_rep_structs(env: TypeEnv) -> str:
    lines: List[str] = []
    for fn in env.iface.functions:
        # request
        lines.append(f"struct {env.prefix}_{fn.name}_req {{")
        for p in fn.params:
            inn, out = param_directions(p)
            if not inn:
                continue
            lines.append(f"        {c_param_field_type(env, p)} {p.name};")
        lines.append("};")
        lines.append("")
        # response
        lines.append(f"struct {env.prefix}_{fn.name}_rep {{")
        for p in fn.params:
            inn, out = param_directions(p)
            if not out:
                continue
            lines.append(f"        {c_param_field_type(env, p)} {p.name};")
        if fn.ret_type in STATUS_TYPES:
            lines.append("        uint32_t status;")
        lines.append("};")
        lines.append("")
    return "\n".join(lines)


def forward_size_fields(t: TypeDef) -> Dict[str, Field]:
    """
    Pointer fields whose [size_is] names a later field of the struct, as
    {pointer field name: size field}, e.g. LSAPR_POLICY_AUDIT_EVENTS_INFO's
    EventAuditingOptions sized by the MaximumAuditEventCount after it.
    """
    out: Dict[str, Field] = {}
    names = [f.name for f in t.fields]
    for i, f in enumerate(t.fields):
        sz = attr_arg(f.attrs, "size_is")
        if sz in names and names.index(sz) > i and \
                attr_arg(f.attrs, "length_is") is None:
            out[f.name] = t.fields[names.index(sz)]
    return out


def forward_size_helper_name(env: TypeEnv, t: TypeDef, f: Field) -> str:
    return f"{env.prefix}_{t.name}_{f.name}_deferred_coder"


def gen_forward_size_helpers(env: TypeEnv, t: TypeDef) -> List[str]:
    """
    For each forward-sized pointer field: the coder NDR queues for its
    referent. It gets the structure, not the field, as by the time NDR
    codes the deferred referent the size field after the pointer is known.
    """
    lines: List[str] = []
    for fname, szf in forward_size_fields(t).items():
        f = next(x for x in t.fields if x.name == fname)
        body = gen_field_coder_stmts(env, f, "s")
        # keep the size and allocation lines, then call the array coder on
        # the field itself instead of queueing it again
        cut = next(i for i, l in enumerate(body) if "dcerpc_ptr_coder" in l)
        elem = array_elem(env, f)
        lines.append(f"/* {f.name} is sized by the {szf.name} after it */")
        lines.append("static int")
        lines.append(
            f"{forward_size_helper_name(env, t, f)}(char *name, struct dcerpc_context *dce,\n"
            f"                struct dcerpc_pdu *pdu,\n"
            f"                struct dcerpc_iovec *iov,\n"
            f"                void *ptr)"
        )
        lines.append("{")
        lines.append(f"        {env.c_struct_name(t.name)} *s = ptr;")
        lines.append("")
        lines.extend(body[:cut])
        lines.append(
            f"        return {env.carray_coder_name(elem)}(name, dce, pdu, iov,\n"
            f"                s->{f.name} ? (void *)s->{f.name} : (void *)&s->{f.name});"
        )
        lines.append("}")
        lines.append("")
    return lines


def indent_lines(lines: List[str], extra: str) -> List[str]:
    return ["\n".join(extra + x if x else x for x in l.split("\n")) for l in lines]


def union_coder_fn(env: TypeEnv, union_name: str) -> str:
    """
    dcerpc_union_enum16_coder for a union whose switch_type is a plain
    enum (a 16-bit discriminant in NDR32), dcerpc_union_u32_coder for any
    other (32 bits in NDR32 and NDR64). Both align the arm to the largest
    alignment of the arms.
    """
    td = env.types.get(union_name)
    sw = attr_arg(td.attrs, "switch_type") if td is not None else None
    st = env.types.get(sw) if sw else None
    if st is not None and st.kind == "enum" and not env.is_u32_enum(sw):
        return "dcerpc_union_enum16_coder"
    return "dcerpc_union_u32_coder"


def param_double_ptr_union(env: TypeEnv, p: Param) -> Optional[str]:
    """
    For "[out,switch_is(x)] PUNION *Info" return the union type name. As
    with param_double_ptr the outer pointer is [ref] and the inner one
    unique; the C field holds the union by value.
    """
    if p.stars != 1 or p.type_name not in env.ptr_to_base:
        return None
    if attr_arg(p.attrs, "switch_is") is None:
        return None
    base = env.ptr_to_base[p.type_name]
    if base in env.types and env.types[base].kind == "union":
        return base
    return None


def param_double_ptr(env: TypeEnv, p: Param) -> Optional[str]:
    """
    For a parameter like "[out] LPSTAT_SERVER_0 *InfoStruct" return the
    struct type name. The outer top-level pointer is [ref] and not on the
    wire; the inner LP* pointer is unique (pointer_default). The C field
    holds the struct by value.
    """
    if p.stars != 1 or p.type_name not in env.ptr_to_base:
        return None
    base = env.ptr_to_base[p.type_name]
    if base in env.types and env.types[base].kind == "struct":
        return base
    return None


def c_param_field_type(env: TypeEnv, p: Param) -> str:
    """C type for a req/rep struct field (pointers often collapsed)."""
    dbl = param_double_ptr(env, p)
    if dbl is not None:
        return env.c_struct_name(dbl)
    dbl = param_double_ptr_union(env, p)
    if dbl is not None:
        return c_ptr(env.c_union_name(dbl))
    if byte_array_param(env, p):
        return "uint8_t *"
    pt = nullable_param(env, p)
    if pt is not None:
        return c_ptr(pointee_ctype_coder(env, pt)[0])
    tname, stars = env.resolve_pointee(p.type_name, p.stars)

    # [size_is] array parameter of structs, enums or pointers
    if (attr_arg(p.attrs, "size_is") is not None and tname in env.types and
            env.types[tname].kind in ("struct", "enum")) or (
            attr_arg(p.attrs, "size_is") is not None and stars >= 2):
        ctype = pointee_ctype_coder(env, tname)[0]
        return c_ptr(c_ptr(ctype)) if stars >= 2 else c_ptr(ctype)

    if env.is_string_type(p.type_name, p.stars, p.attrs) or tname in env.string_aliases:
        return "char *"

    ext = env.extern(tname)
    if ext is not None:
        # [size_is] array parameter, or the value (top-level ref pointer)
        return c_ptr(ext[0]) if attr_arg(p.attrs, "size_is") else ext[0]

    if tname in env.types:
        td = env.types[tname]
        if td.kind == "struct":
            return env.c_struct_name(tname)
        if td.kind == "union":
            return env.c_union_name(tname)
        if td.kind == "enum":
            return env.c_enum_name(tname)

    if tname in BUILTINS:
        return BUILTINS[tname]

    return "void *"


def fn_opnum(fn: Function, index: int) -> int:
    """
    Resolve the wire opnum for a function.
    Prefer explicit [opnum(N)]; otherwise use declaration order (0, 1, 2, …).
    """
    explicit = attr_int(fn.attrs, "opnum")
    if explicit is not None:
        return explicit
    return index


def fn_opnum_macro(env: TypeEnv, fn: Function) -> str:
    """e.g. SRVSVC_NETRSHAREENUM — matches libdcerpc header style."""
    return f"{env.prefix.upper()}_{fn.name.upper()}"


def gen_server_decls(env: TypeEnv) -> str:
    """
    Server-only declarations (the <name>_server.h header): registration
    strings for dcerpcd serviced, <iface>_find_proc(), the stub table and
    the stub prototypes.
    """
    lines: List[str] = []
    uuid = attr_arg(env.iface.attrs, "uuid") or "00000000-0000-0000-0000-000000000000"
    vers = attr_arg(env.iface.attrs, "version") or "1.0"
    # helpstring (MIDL) or annotation — used by dcerpcd serviced registration YAML
    annotation = (
        attr_unquoted(env.iface.attrs, "helpstring")
        or attr_unquoted(env.iface.attrs, "annotation")
        or env.iface.name
    )
    #
    # String macros for dcerpcd external-service registration (serviced.c).
    # Named <iface>_UUID_STR / _VERSION_STR / _ANNOTATION / _PIPE_NAME so they
    # paste from -DSERVICE=<iface> via SERVICE_PASTE(SERVICE, _UUID_STR), etc.
    # <iface>_PIPE_NAME is in the coder header: clients need it too.
    #
    lines.append("/* Registration strings for dcerpcd serviced (from IDL attrs) */")
    lines.append(f"#define {env.prefix}_UUID_STR    {c_string_literal(uuid)}")
    lines.append(f"#define {env.prefix}_VERSION_STR {c_string_literal(vers)}")
    lines.append(f"#define {env.prefix}_ANNOTATION  {c_string_literal(annotation)}")
    lines.append("")

    lines.append(
        f"/* Look up a procedure by wire opnum; NULL if unknown. */\n"
        f"static inline const struct dcerpc_procedure *\n"
        f"{env.prefix}_find_proc(int opnum)\n"
        f"{{\n"
        f"        const struct dcerpc_procedure *p;\n"
        f"\n"
        f"        for (p = {env.prefix}_procs; p->name != NULL; p++) {{\n"
        f"                if (p->opnum == opnum) {{\n"
        f"                        return p;\n"
        f"                }}\n"
        f"        }}\n"
        f"        return NULL;\n"
        f"}}"
    )
    lines.append("")
    #
    # Stub / implementation table: defined in the stubs .c (not the coder)
    # so clients can link coders without pulling server implementations.
    # Uses struct dcerpc_stub from dcerpc.h; served with
    # dcerpc_server_add_interface() from <dcerpc/server.h>.
    #
    lines.append(
        f"/*\n"
        f" * Server-side implementation table (struct dcerpc_stub from dcerpc.h).\n"
        f" * Defined in the stubs .c together with the *_stub functions — not\n"
        f" * in the coder, so clients can link coders alone.\n"
        f" * Each fn: int stub(dce, pdu, void *req, void *rep);\n"
        f" *   req  — decoded request (size proc->req_size)\n"
        f" *   rep  — zeroed response to fill (size proc->rep_size)\n"
        f" *   pdu  — use dcerpc_alloc_data(pdu, …) for nested allocations\n"
        f" * Return 0 to send rep, a DCERPC_FAULT_* status to send that\n"
        f" * instead, or -1 for DCERPC_FAULT_OTHER.\n"
        f" * Serve with dcerpc_server_add_interface() (<dcerpc/server.h>).\n"
        f" */\n"
        f"extern struct dcerpc_stub {env.prefix}_stubs[];"
    )
    lines.append("")

    # Stub prototypes (implemented in the stubs .c with the dispatch table)
    lines.append("/* Implementation stubs (define in the stubs .c with the table) */")
    for i, fn in enumerate(env.iface.functions):
        lines.append(
            f"int {env.prefix}_{fn.name}_stub(struct dcerpc_context *dce,\n"
            f"                struct dcerpc_pdu *pdu,\n"
            f"                void *req, void *rep);"
        )
    lines.append("")
    return "\n".join(lines)


def gen_prototypes(env: TypeEnv) -> str:
    lines: List[str] = []
    has_iface = env.iface.has_interface

    if has_iface:
        # interface
        uuid = attr_arg(env.iface.attrs, "uuid") or "00000000-0000-0000-0000-000000000000"
        vers = attr_arg(env.iface.attrs, "version") or "1.0"
        lines.append(f"/* interface {env.iface.name} uuid({uuid}) version({vers}) */")
        lines.append(f"extern p_syntax_id_t {env.prefix}_interface;")
        lines.append("")
        # wire pipe base from the endpoint attribute (e.g. "srvsvc")
        endpoint = attr_unquoted(env.iface.attrs, "endpoint")
        pipe_name = pipe_base_from_endpoint(endpoint) or env.iface.name
        lines.append("/* Named pipe (from the IDL endpoint) */")
        lines.append(f"#define {env.prefix}_PIPE_NAME {c_string_literal(pipe_name)}")
        lines.append("")

        # Opnum constants (same role as SRVSVC_NETRSHAREENUM in dcerpc/srvsvc.h)
        lines.append("/* Operation numbers (wire opnum) */")
        w = max((len(fn_opnum_macro(env, fn)) for fn in env.iface.functions), default=0)
        for i, fn in enumerate(env.iface.functions):
            op = fn_opnum(fn, i)
            lines.append(f"#define {fn_opnum_macro(env, fn):<{w}} 0x{op:02x}")
        lines.append("")

        #
        # Procedure table: maps opnum → request/response coders and struct sizes.
        # Same layout as libdcerpc's srvsvc_procs[] / epm_procs[]:
        #   { opnum, name, req_coder, req_size, rep_coder, rep_size }
        # Terminated by { -1, NULL, NULL, 0, NULL, 0 }.
        #
        lines.append(
            f"/* Opnum → request/response coders, terminated by opnum -1 */\n"
            f"extern struct dcerpc_procedure {env.prefix}_procs[];"
        )
        lines.append("")

    else:
        lines.append(
            f"/* Data-only IDL (prefix {env.prefix}): types and coders, no interface */"
        )
        lines.append("")

    for t in env.iface.types:
        if t.kind in ("struct", "union", "enum"):
            lines.append(
                f"int {env.coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                f"                void *ptr);"
            )
            if t.kind == "struct":
                lines.append(
                    f"int {env.struct_coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
                    f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                    f"                void *ptr);"
                )
            if t.kind == "union" and t.name in switched_param_unions(env):
                lines.append(
                    f"int {env.prefix}_{t.name}_switch_coder(char *name, struct dcerpc_context *dce,\n"
                    f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                    f"                void *ptr);"
                )
            if t.kind == "union" and t.name in double_ptr_unions(env):
                lines.append(
                    f"int {env.prefix}_{t.name}_switch_ptr_coder(char *name, struct dcerpc_context *dce,\n"
                    f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                    f"                void *ptr);"
                )
            lines.append("")

    if has_iface:
        for i, fn in enumerate(env.iface.functions):
            op = fn_opnum(fn, i)
            lines.append(f"/* {fn.name} opnum 0x{op:02x} ({fn_opnum_macro(env, fn)}) */")
            lines.append(
                f"int {env.prefix}_{fn.name}_req_coder(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                f"                void *ptr);"
            )
            lines.append(
                f"int {env.prefix}_{fn.name}_rep_coder(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                f"                void *ptr);"
            )
            lines.append("")
    return "\n".join(lines)


def needs_carray(env: TypeEnv, t: TypeDef) -> List[str]:
    """Element type names that need a carray coder because of size_is fields."""
    out: List[str] = []
    if t.kind != "struct":
        return out
    for f in t.fields:
        if attr_arg(f.attrs, "size_is") is None or blob_type(f) is not None:
            continue
        et, _ = env.resolve_pointee(f.type_name, f.stars)
        if is_varying_bytes(f, et):
            continue
        et = array_elem(env, f)
        if et not in out:
            out.append(et)
    return out


def param_carrays(env: TypeEnv, varying: bool = False) -> List[str]:
    """
    Element types of [size_is] array parameters; with varying, of the
    conformant-varying ones ([size_is, length_is]) instead.
    """
    out: List[str] = []
    for fn in env.iface.functions:
        for p in fn.params:
            if attr_arg(p.attrs, "size_is") is None or byte_array_param(env, p):
                continue
            if (attr_arg(p.attrs, "length_is") is not None) != varying:
                continue
            et = array_elem(env, p)
            if et not in out:
                out.append(et)
    return out


def param_value(fn, name: str, var: str) -> str:
    """
    C expression for the value of parameter name, as size_is/length_is use
    it: from the reply if it is [out], else from the request (coding the
    reply, an [in]-only size comes from the request). A number is a
    constant size, e.g. SamrLookupNamesInDomain's size_is(1000).
    """
    name = name.lstrip("*")
    if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", name):
        return name
    src = next((q for q in fn.params if q.name == name), None)
    if src is None:
        raise SystemExit(f"error: {fn.name}: {name} is not a parameter")
    s_in, s_out = param_directions(src)
    if var == "rep" and not s_out:
        return f"req->{name}"
    if var == "req" and not s_in:
        raise SystemExit(f"error: {fn.name}: [in] array sized by [out]-only {name}")
    return f"{var}->{name}"


def nullable_ptr_types(env: TypeEnv) -> List[str]:
    """Pointee types of nullable [unique] T * struct fields."""
    out: List[str] = []
    for t in env.iface.types:
        if t.kind != "struct":
            continue
        for f in t.fields:
            pt = nullable_ptr_field(env, f)
            if pt is not None and pt not in out:
                out.append(pt)
    for t in env.iface.types:
        for et in needs_carray(env, t):
            if et.endswith("*") and et[:-1] not in out:
                out.append(et[:-1])
    for et in param_carrays(env) + param_carrays(env, varying=True):
        if et.endswith("*") and et[:-1] not in out:
            out.append(et[:-1])
    for fn in env.iface.functions:
        for p in fn.params:
            pt = nullable_param(env, p)
            if pt is not None and pt not in out:
                out.append(pt)
    return out


# ---------------------------------------------------------------------------
# NDR alignment
#
# The (NDR32, NDR64) alignment of what libdcerpc codes inline for a field,
# a union or a structure. A structure is aligned to its largest member, and
# NDR64 also pads it at the end to that alignment ([MS-RPCE] 2.2.5.3.4.1);
# the generated <T>_struct_coder passes these values to
# dcerpc_aligned_struct_coder(), which also applies them to embedded
# structures.
# ---------------------------------------------------------------------------

PTR_ALIGN = (4, 8)            # referent id: 32/64-bit
BUILTIN_ALIGN = {"uint8_t": (1, 1), "uint16_t": (2, 2), "uint32_t": (4, 4),
                 "int32_t": (4, 4), "uint64_t": (8, 8)}
# RPC_UNICODE_STRING: uint16 Length, uint16 MaximumLength, pointer Buffer
EXTERN_ALIGN = {"RPC_UNICODE_STRING": PTR_ALIGN,
                "RPC_UNICODE_STRINGz": PTR_ALIGN,
                "RRP_UNICODE_STRING": PTR_ALIGN,
                # uint32, uint16, uint16, uint8[8]
                "uuid_t": (4, 4),
                # tower_length and the bytes; the hoisted max_count is not
                # a member
                "twr_t": (4, 4),
                # offset and actual_count (32/64-bit), then the characters
                "EPM_ANNOTATION": PTR_ALIGN}
# struct dcerpc_context_handle: uint32 attributes + 16-byte uuid
CONTEXT_HANDLE_ALIGN = (4, 4)


def max_align(*aligns: Tuple[int, int]) -> Tuple[int, int]:
    return (max([1] + [a[0] for a in aligns]), max([1] + [a[1] for a in aligns]))


def enum_align(env: "TypeEnv", tname: str) -> Tuple[int, int]:
    """[v1_enum]/bitmap: 32 bits; other enums: 16 bits (NDR32), 32 (NDR64)."""
    return (4, 4) if env.is_u32_enum(tname) else (2, 4)


def union_arm_align(env: "TypeEnv", f: "Field") -> Tuple[int, int]:
    """Mirrors gen_union_case_stmts."""
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    if tname in env.types and env.types[tname].kind == "struct":
        # an arm that is a structure itself, or a pointer to one
        return struct_align(env, tname) if stars == 0 else PTR_ALIGN
    if env.is_string_type(f.type_name, f.stars, f.attrs):
        return PTR_ALIGN
    if env.is_enum(tname):
        return enum_align(env, tname)
    if tname in BUILTINS:
        return BUILTIN_ALIGN.get(BUILTINS[tname], (4, 4))
    raise SystemExit(f"error: no NDR alignment for union arm {f.name}")


def union_arms_align(env: "TypeEnv", uname: str) -> Tuple[int, int]:
    """
    The largest alignment of the arms of a union: what NDR64 aligns the
    arm to ([MS-RPCE] 2.2.5.3.4.4). NDR32 aligns the arm to its own
    alignment instead ([C706] 14.3.2).
    """
    t = env.types[uname]
    return max_align(*[union_arm_align(env, f) for f in t.fields])


def union_align(env: "TypeEnv", uname: str) -> Tuple[int, int]:
    """
    The discriminant, then the arm: a 32-bit discriminant, or a plain
    enum one (dcerpc_union_enum16_coder) that is 16 bits in NDR32. This is
    the union's alignment as a member of a structure, the largest of the
    discriminant and all the arms ([C706] 14.3.2), not the alignment of
    the arm that is sent.
    """
    t = env.types[uname]
    if union_coder_fn(env, uname) == "dcerpc_union_enum16_coder":
        return max_align(enum_align(env, attr_arg(t.attrs, "switch_type")),
                         union_arms_align(env, uname))
    return max_align((4, 4), union_arms_align(env, uname))


def union_coder_args(env: "TypeEnv", uname: str) -> str:
    """Extra arguments of the union coder for uname: the arm alignment."""
    a32, a64 = union_arms_align(env, uname)
    return f", {a32}, {a64}"


def field_align(env: "TypeEnv", f: "Field") -> Tuple[int, int]:
    """Mirrors the struct coder: blob fields, then gen_field_coder_stmts."""
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    size_is = attr_arg(f.attrs, "size_is")
    if blob_type(f) is not None:
        return PTR_ALIGN
    if f.array_len is not None:
        return BUILTIN_ALIGN["uint8_t"]
    if env.is_string_type(f.type_name, f.stars, f.attrs) or tname in env.string_aliases:
        return PTR_ALIGN
    if is_varying_bytes(f, tname):
        return PTR_ALIGN
    ext = env.extern(tname)
    if ext is not None and stars == 0 and size_is is None:
        if tname in env.context_handles:
            return CONTEXT_HANDLE_ALIGN
        if tname in EXTERN_ALIGN:
            return EXTERN_ALIGN[tname]
        raise SystemExit(f"error: no NDR alignment for {tname} field {f.name}")
    if stars > 0 or size_is is not None:
        return PTR_ALIGN
    if attr_arg(f.attrs, "switch_is") is not None:
        return union_align(env, tname)
    if tname in BUILTINS:
        return BUILTIN_ALIGN[BUILTINS[tname]]
    if env.is_enum(tname):
        return enum_align(env, tname)
    if tname in env.types and env.types[tname].kind == "struct":
        return struct_align(env, tname)
    raise SystemExit(f"error: no NDR alignment for field {f.name} type {f.type_name}")


def struct_align(env: "TypeEnv", tname: str) -> Tuple[int, int]:
    """(NDR32, NDR64) alignment of a structure: that of its largest member."""
    t = env.types[tname]
    return max_align(*[field_align(env, f) for f in t.fields])


def gen_field_coder_stmts(
    env: TypeEnv,
    f: Field,
    var: str,
    indent: str = "        ",
) -> List[str]:
    """Emit coder statements for one struct field."""
    lines: List[str] = []
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    size_is = attr_arg(f.attrs, "size_is")
    switch_is = attr_arg(f.attrs, "switch_is")
    disp = f.name

    # uint8_t name[N]: the bytes inline, hex in YAML/JSON
    if f.array_len is not None:
        lines.append(
            f'{indent}if (dcerpc_fixed_bytes_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                             {var}->{f.name}, {f.array_len})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # string
    if env.is_string_type(f.type_name, f.stars, f.attrs) or tname in env.string_aliases:
        lines.extend(unique_string_field_lines(indent, disp, var, f.name))
        return lines

    # [size_is(m), length_is(l)] uint8 *: unique pointer to a varying byte
    # array; NULL when there is no data
    if is_varying_bytes(f, tname):
        # a constant size_is (SAMPR_LOGON_HOURS' 1260) is the max_count
        # whatever the caller set: encode a copy with it, so the input is
        # not written, and on decode it is what text encodings, which
        # carry only the bytes, cannot give
        lines.extend(varying_bytes_sizes_lines(f, var, indent))
        if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", size_is):
            lines.append(
                f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
                f"{indent}    {var}->{f.name}.data != NULL) {{\n"
                f"{indent}        struct dcerpc_varying_bytes *vb;\n"
                f"\n"
                f"{indent}        vb = dcerpc_alloc_data(pdu, sizeof(*vb));\n"
                f"{indent}        if (vb == NULL) {{\n"
                f"{indent}                return -1;\n"
                f"{indent}        }}\n"
                f"{indent}        *vb = {var}->{f.name};\n"
                f"{indent}        vb->max_count = {size_is};\n"
                f'{indent}        if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, vb,\n'
                f"{indent}                             PTR_UNIQUE, dcerpc_varying_bytes_checked_coder)) {{\n"
                f"{indent}                return -1;\n"
                f"{indent}        }}\n"
                f"{indent}}} else {{\n"
                f'{indent}        if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
                f"{indent}                             (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) ? NULL : &{var}->{f.name},\n"
                f"{indent}                             PTR_UNIQUE, dcerpc_varying_bytes_checked_coder)) {{\n"
                f"{indent}                return -1;\n"
                f"{indent}        }}\n"
                f"{indent}        /* NDR decodes the deferred bytes, and max_count, later */\n"
                f"{indent}        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {{\n"
                f"{indent}                {var}->{f.name}.max_count = {size_is};\n"
                f"{indent}        }}\n"
                f"{indent}}}"
            )
            return lines
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                     (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
            f"{indent}                      {var}->{f.name}.data == NULL) ? NULL : &{var}->{f.name},\n"
            f"{indent}                     PTR_UNIQUE, dcerpc_varying_bytes_checked_coder)) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # libdcerpc built-in type by value (RPC_UNICODE_STRING, ...)
    ext = env.extern(tname)
    if ext is not None and stars == 0 and size_is is None:
        lines.append(
            f'{indent}if ({ext[1]}("{disp}", dce, pdu, iov, &{var}->{f.name})) {{\n'
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # nullable [unique] T *: NULL encodes a NULL referent; decode allocates
    pt = nullable_ptr_field(env, f)
    if pt is not None:
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                     (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
            f"{indent}                      {var}->{f.name} == NULL) ? NULL : &{var}->{f.name},\n"
            f"{indent}                     {ptr_kind(env, f.type_name, f.attrs)}, {env.ptr_helper_name(pt)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # size_is conformant array (unique pointer to array)
    if size_is is not None:
        elem = array_elem(env, f)
        lines.append(f"{indent}dcerpc_set_size_is(pdu, {var}->{size_is});")
        lines.append(
            f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && {var}->{size_is}) {{"
        )
        lines.append(f"{indent}        if ({var}->{f.name} == NULL) {{")
        if elem.endswith("*"):
            esize = f"sizeof({c_ptr(pointee_ctype_coder(env, elem[:-1])[0])})"
        elif env.extern(elem) is not None:
            esize = f"sizeof({env.extern(elem)[0]})"
        elif elem in env.types and env.types[elem].kind == "struct":
            esize = f"sizeof({env.c_struct_name(elem)})"
        elif elem in BUILTINS:
            esize = f"sizeof({BUILTINS[elem]})"
        else:
            esize = f"sizeof({env.c_struct_name(elem)})"
        lines.append(
            f"{indent}                {var}->{f.name} = dcerpc_alloc_array(pdu, iov,\n"
            f"{indent}                        {var}->{size_is}, {esize});\n"
            f"{indent}                if ({var}->{f.name} == NULL) {{\n"
            f"{indent}                        return -1;\n"
            f"{indent}                }}"
        )
        lines.append(f"{indent}        }}")
        lines.append(f"{indent}}}")
        # A sender may point at an empty array instead of sending NULL;
        # decode that into the (unchanged, NULL) field itself.
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                     (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&\n"
            f"{indent}                      {var}->{f.name} == NULL) ? (void *)&{var}->{f.name} : (void *){var}->{f.name},\n"
            f"{indent}                     PTR_UNIQUE, {env.carray_coder_name(elem)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # switch_is union field
    if switch_is is not None:
        ut = tname
        ufn = union_coder_fn(env, ut)
        pad = " " * (len(ufn) + 5)
        lines.append(
            f'{indent}if ({ufn}("{disp}", dce, pdu, iov,\n'
            f"{indent}{pad}&{var}->{switch_is}, &{var}->{f.name},\n"
            f"{indent}{pad}{env.coder_name(ut)}{union_coder_args(env, ut)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # builtin scalar
    if tname in BUILTINS and stars == 0:
        coder = builtin_coder(tname)
        if coder:
            lines.append(
                f'{indent}if ({coder}("{disp}", dce, pdu, iov, &{var}->{f.name})) {{\n'
                f"{indent}        return -1;\n"
                f"{indent}}}"
            )
            lines.extend(range_check_lines(f.attrs, f"{var}->{f.name}", indent))
            return lines

    # enum (NDR uint16/uint32 + pretty names for YAML)
    if tname in env.types and env.types[tname].kind == "enum" and stars == 0:
        lines.append(
            f'{indent}if ({env.coder_name(tname)}("{disp}", dce, pdu, iov, &{var}->{f.name})) {{\n'
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # embedded struct: its own key in YAML/JSON, aligned (and in NDR64
    # padded) as a structure in NDR
    if tname in env.types and env.types[tname].kind == "struct" and stars == 0:
        lines.append(
            f'{indent}if ({env.struct_coder_name(tname)}("{disp}", dce, pdu, iov, &{var}->{f.name})) {{\n'
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    lines.append(f"{indent}/* TODO: unhandled field {f.name} type {f.type_name} */")
    lines.append(f"{indent}(void){var};")
    return lines


def gen_union_case_stmts(env: TypeEnv, f: Field, var: str, indent: str) -> List[str]:
    lines: List[str] = []
    tname, stars = env.resolve_pointee(f.type_name, f.stars)
    disp = f.name
    # union arms that are a structure (not a pointer to one) are coded in
    # place, e.g. LSAPR_POLICY_INFORMATION
    if tname in env.types and env.types[tname].kind == "struct" and stars == 0:
        lines.append(
            f'{indent}if ({env.struct_coder_name(tname)}("{disp}", dce, pdu, iov,\n'
            f"{indent}        &{var}->{f.name})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines
    # union arms that are LP* containers: unique pointer to embedded struct.
    # The _struct_coder wrapper gives the arm its own key in YAML/JSON
    # (ShareInfo: Level0: ...), which the union readers expect; NDR is the
    # same either way.
    if tname in env.types and env.types[tname].kind == "struct":
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{f.name},\n'
            f"{indent}                     PTR_UNIQUE, {env.struct_coder_name(tname)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines
    if env.is_string_type(f.type_name, f.stars, f.attrs):
        lines.extend(unique_string_field_lines(indent, disp, var, f.name))
        return lines
    if tname in env.types and env.types[tname].kind == "enum":
        lines.append(
            f'{indent}if ({env.coder_name(tname)}("{disp}", dce, pdu, iov, &{var}->{f.name})) {{\n'
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines
    if tname in BUILTINS:
        coder = builtin_coder(tname) or "dcerpc_uint32_coder"
        lines.append(
            f'{indent}if ({coder}("{disp}", dce, pdu, iov, &{var}->{f.name})) {{\n'
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines
    lines.append(f"{indent}/* TODO union arm {f.name} */")
    return lines


def enum_is_v1(t: TypeDef) -> bool:
    """
    MIDL/NDR: plain enum is 16-bit on the wire; [v1_enum] is 32-bit.
    """
    return attr_has(t.attrs, "v1_enum")


def gen_u32_enum_coder(env: TypeEnv, t: TypeDef) -> str:
    """
    [v1_enum] enum or bitmap: a uint32_t on the wire and in C, coded with
    dcerpc_uint32_coder_pp so YAML/JSON show the member names.

    enum members match exactly. Bitmap members match when
    (value & mask) == member, where mask is [mask(m)] or the member value
    itself; a zero member without [mask] would always match and is left
    out of the pretty printer.
    """
    pp = env.enum_pp_name(t.name)
    bitmap = attr_has(t.attrs, "bitmap")
    lines: List[str] = []
    lines.append(f"/* {t.name}: NDR uint32; YAML/JSON show the {'flag' if bitmap else 'value'} names */")
    lines.append(f"static struct dcerpc_uint32_pretty_printer {pp} = {{")
    lines.append(f'        .fmt = "{"0x%08x" if bitmap else "%u"}",')
    lines.append("        .bitfields = {")
    for m in t.enum_members:
        cn = env.const_name(m.name)
        if not bitmap:
            mask = "0xffffffff"
        elif m.mask is not None:
            mask = f"0x{m.mask:08x}"
        elif m.value == 0:
            continue
        else:
            mask = cn
        lines.append(f'                {{ "{m.name}", {mask}, {cn} }},')
    lines.append("                { NULL, 0, 0 },")
    lines.append("        },")
    lines.append("};")
    lines.append("")
    lines.append("int")
    lines.append(
        f"{env.coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
        f"                struct dcerpc_pdu *pdu,\n"
        f"                struct dcerpc_iovec *iov,\n"
        f"                void *ptr)"
    )
    lines.append("{")
    lines.append(f"        return dcerpc_uint32_coder_pp(name, dce, pdu, iov, ptr,")
    lines.append(f"                                      &{pp});")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def gen_enum_coder(env: TypeEnv, t: TypeDef) -> str:
    """
    Enum wire size follows IDL attributes:
      default     → uint16 in NDR32, uint32 in NDR64 (dcerpc_enum16_coder)
      [v1_enum]   → uint32 (dcerpc_uint32_coder_pp)

    Both use a pretty printer so YAML shows the named value.

    C enum storage may be wider than the wire type, so encode/decode always
    goes through a temporary of the correct width.
    """
    lines: List[str] = []
    etype = env.c_enum_name(t.name)
    pp = env.enum_pp_name(t.name)
    if env.is_u32_enum(t.name):
        return gen_u32_enum_coder(env, t)
    if enum_is_v1(t):
        wtype, coder, mask = "uint32_t", "dcerpc_uint32_coder_pp", "0xffffffff"
        lines.append(
            f"/* enum {t.name}: [v1_enum] → NDR uint32; named YAML values */"
        )
    else:
        wtype, coder, mask = "uint16_t", "dcerpc_enum16_coder", "0xffff"
        lines.append(
            f"/* enum {t.name}: not [v1_enum], so 16 bits in NDR32 and 32 in NDR64; named YAML values */"
        )

    lines.append(f"static struct dcerpc_uint32_pretty_printer {pp} = {{")
    lines.append('        .fmt = "%u",')
    lines.append("        .bitfields = {")
    for m in t.enum_members:
        # Exclusive match (same pattern as PLATFORM_ID_* in srvsvc/srvsvc_coder.c).
        lines.append(
            f'                {{ "{m.name}", {mask}, ({wtype}){env.const_name(m.name)} }},'
        )
    lines.append("                { NULL, 0, 0 },")
    lines.append("        },")
    lines.append("};")
    lines.append("")

    lines.append("int")
    lines.append(
        f"{env.coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
        f"                struct dcerpc_pdu *pdu,\n"
        f"                struct dcerpc_iovec *iov,\n"
        f"                void *ptr)"
    )
    lines.append("{")
    lines.append(f"        {etype} *e = ptr;")
    lines.append(f"        {wtype} tmp = 0;")
    lines.append("")
    lines.append("        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {")
    lines.append(f"                tmp = ({wtype})*e;")
    lines.append("        }")
    lines.append(
        f"        if ({coder}(name, dce, pdu, iov, &tmp,\n"
        f"                                   &{pp})) {{"
    )
    lines.append("                return -1;")
    lines.append("        }")
    lines.append("        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {")
    lines.append(f"                *e = ({etype})tmp;")
    lines.append("        }")
    lines.append("        return 0;")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def gen_type_coders(env: TypeEnv) -> str:
    lines: List[str] = []

    # carray helpers first (static) for element types that need them
    needed_carrays: List[str] = []
    for t in env.iface.types:
        for et in needs_carray(env, t):
            if et not in needed_carrays:
                needed_carrays.append(et)
    for et in param_carrays(env):
        if et not in needed_carrays:
            needed_carrays.append(et)
    needed_cvarrays = param_carrays(env, varying=True)
    # struct element types: coded through an aligned element wrapper
    elem_structs = [et for et in needed_carrays + needed_cvarrays
                    if et in env.types and env.types[et].kind == "struct"]
    elem_structs = list(dict.fromkeys(elem_structs))

    # Forward-declare the static helpers, which use each other
    for pt in nullable_ptr_types(env):
        lines.append(
            f"static int {env.ptr_helper_name(pt)}(char *name, struct dcerpc_context *dce,\n"
            f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
            f"                void *ptr);"
        )
    for et in list(dict.fromkeys(needed_carrays + needed_cvarrays)):
        if et.endswith("*"):
            lines.append(
                f"static int {env.pelem_coder_name(et[:-1])}(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                f"                void *ptr);"
            )

    # Forward-declare element coders used by carray helpers defined above them
    if needed_carrays or needed_cvarrays:
        for et in list(dict.fromkeys(needed_carrays + needed_cvarrays)):
            if et in BUILTINS or env.extern(et) is not None or et.endswith("*"):
                continue  # element coder is a dcerpc_*_coder builtin or static
            lines.append(
                f"int {env.coder_name(et)}(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,\n"
                f"                void *ptr);"
            )
        lines.append("")

    # a structure as an array element: aligned, and in NDR64 padded, as a
    # structure; its members directly in YAML/JSON
    for et in elem_structs:
        a32, a64 = struct_align(env, et)
        lines.append("static int")
        lines.append(
            f"{env.elem_coder_name(et)}(char *name, struct dcerpc_context *dce,\n"
            f"                     struct dcerpc_pdu *pdu,\n"
            f"                     struct dcerpc_iovec *iov,\n"
            f"                     void *ptr)"
        )
        lines.append("{")
        lines.append(
            f"        return dcerpc_aligned_element_coder(name, dce, pdu, iov, ptr,\n"
            f"                                            {env.coder_name(et)}, {a32}, {a64});"
        )
        lines.append("}")
        lines.append("")

    for et, varying in ([(e, False) for e in needed_carrays] +
                        [(e, True) for e in needed_cvarrays]):
        cname = (env.cvarray_coder_name(et) if varying
                 else env.carray_coder_name(et))
        if et.endswith("*"):
            esize = f"sizeof({c_ptr(pointee_ctype_coder(env, et[:-1])[0])})"
            ecoder = env.pelem_coder_name(et[:-1])
        elif env.extern(et) is not None:
            esize = f"sizeof({env.extern(et)[0]})"
            ecoder = env.extern(et)[1]
        elif et in env.types and env.types[et].kind == "struct":
            esize = f"sizeof({env.c_struct_name(et)})"
            ecoder = env.elem_coder_name(et)
        elif et in env.types and env.types[et].kind == "enum":
            esize = f"sizeof({env.c_enum_name(et)})"
            ecoder = env.coder_name(et)
        elif et in BUILTINS:
            esize = f"sizeof({BUILTINS[et]})"
            ecoder = builtin_coder(et) or "dcerpc_uint32_coder"
        else:
            esize = f"sizeof({env.c_struct_name(et)})"
            ecoder = env.coder_name(et)
        lines.append("static int")
        lines.append(
            f"{cname}(char *name, struct dcerpc_context *dce,\n"
            f"                     struct dcerpc_pdu *pdu,\n"
            f"                     struct dcerpc_iovec *iov,\n"
            f"                     void *ptr)"
        )
        lines.append("{")
        # Key the array by its field name (passed in by dcerpc_ptr_coder),
        # like every other field, so YAML/JSON readers find it again.
        # Plain values are a bare YAML/JSON list (scalar_carray_coder).
        if varying:
            cvarray = ("dcerpc_scalar_cvarray_coder" if is_scalar_elem(env, et)
                       else "dcerpc_cvarray_coder")
            lines.append(
                f'        return {cvarray}(name, dce, pdu, iov,\n'
                f"                                    dcerpc_get_size_is(pdu),\n"
                f"                                    dcerpc_get_length_is(pdu), ptr,\n"
                f"                                    {esize},\n"
                f"                                    {ecoder});"
            )
        else:
            carray = ("dcerpc_scalar_carray_coder" if is_scalar_elem(env, et)
                      else "dcerpc_carray_coder")
            lines.append(
                f'        return {carray}(name, dce, pdu, iov,\n'
                f"                                   dcerpc_get_size_is(pdu), ptr,\n"
                f"                                   {esize},\n"
                f"                                   {ecoder});"
            )
        lines.append("}")
        lines.append("")

    # nullable [unique] T * fields: allocate the pointee on decode
    for pt in nullable_ptr_types(env):
        ctype, coder = pointee_ctype_coder(env, pt)
        lines.append("static int")
        lines.append(
            f"{env.ptr_helper_name(pt)}(char *name, struct dcerpc_context *dce,\n"
            f"                     struct dcerpc_pdu *pdu,\n"
            f"                     struct dcerpc_iovec *iov,\n"
            f"                     void *ptr)"
        )
        lines.append("{")
        lines.append(f"        {c_ptr(c_ptr(ctype))}pp = ptr;")
        lines.append("")
        lines.append("        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && *pp == NULL) {")
        lines.append("                *pp = dcerpc_alloc_data(pdu, sizeof(**pp));")
        lines.append("                if (*pp == NULL) {")
        lines.append("                        return -1;")
        lines.append("                }")
        lines.append("        }")
        lines.append(f"        return {coder}(name, dce, pdu, iov, *pp);")
        lines.append("}")
        lines.append("")

    # element of an array of nullable pointers: a unique pointer per element
    for et in list(dict.fromkeys(needed_carrays + needed_cvarrays)):
        if not et.endswith("*"):
            continue
        pt = et[:-1]
        lines.append("static int")
        lines.append(
            f"{env.pelem_coder_name(pt)}(char *name, struct dcerpc_context *dce,\n"
            f"                     struct dcerpc_pdu *pdu,\n"
            f"                     struct dcerpc_iovec *iov,\n"
            f"                     void *ptr)"
        )
        lines.append("{")
        lines.append(f"        {c_ptr(c_ptr(pointee_ctype_coder(env, pt)[0]))}pp = ptr;")
        lines.append("")
        lines.append("        return dcerpc_ptr_coder(name, dce, pdu, iov,")
        lines.append("                                (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&")
        lines.append("                                 *pp == NULL) ? NULL : (void *)pp,")
        kind = "PTR_FULL" if pt in full_ptr_pointees(env) else "PTR_UNIQUE"
        lines.append(f"                                {kind}, {env.ptr_helper_name(pt)});")
        lines.append("}")
        lines.append("")

    # context handle parameters nest under the parameter name in YAML/JSON
    for ch in env.context_handles:
        lines.append("static int")
        lines.append(
            f"{env.prefix}_{ch}_param_coder(char *name, struct dcerpc_context *dce,\n"
            f"                     struct dcerpc_pdu *pdu,\n"
            f"                     struct dcerpc_iovec *iov,\n"
            f"                     void *ptr)"
        )
        lines.append("{")
        a32, a64 = CONTEXT_HANDLE_ALIGN
        lines.append(f"        return dcerpc_aligned_struct_coder(name, dce, pdu, iov, ptr,")
        lines.append(f"                                           {CONTEXT_HANDLE[1]}, {a32}, {a64});")
        lines.append("}")
        lines.append("")

    for t in env.iface.types:
        if t.kind == "enum":
            lines.append(gen_enum_coder(env, t))
            continue
        if t.kind == "struct":
            fwd = forward_size_fields(t)
            fwd_sizes = {szf.name for szf in fwd.values()}
            lines.extend(gen_forward_size_helpers(env, t))
            lines.append("int")
            lines.append(
                f"{env.coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu,\n"
                f"                struct dcerpc_iovec *iov,\n"
                f"                void *ptr)"
            )
            lines.append("{")
            lines.append(f"        {env.c_struct_name(t.name)} *s = ptr;")
            lines.append("")
            lines.append("        (void)name;")
            blob_lens = blob_len_fields(t)
            for f in t.fields:
                bt = blob_type(f)
                if bt is not None:
                    ln = attr_arg(f.attrs, "size_is")
                    lines.append(
                        f'        if (dcerpc_blob_coder("{f.name}", dce, pdu, iov,\n'
                        f"                              s->{ln}, &s->{f.name},\n"
                        f"                              sizeof({bt[0]}),\n"
                        f"                              {bt[1]})) {{\n"
                        f"                return -1;\n"
                        f"        }}"
                    )
                elif f.name in blob_lens:
                    bf = blob_lens[f.name]
                    lines.append(
                        f'        if (dcerpc_blob_len_coder("{f.name}", dce, pdu, iov,\n'
                        f"                                  &s->{f.name}, s->{bf.name},\n"
                        f"                                  {blob_type(bf)[1]})) {{\n"
                        f"                return -1;\n"
                        f"        }}"
                    )
                elif f.name in fwd:
                    # YAML/JSON need the size before the list; NDR keeps
                    # the wire order and codes the referent later
                    szf = fwd[f.name]
                    lines.append("        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {")
                    lines.extend(indent_lines(gen_field_coder_stmts(env, szf, "s"), "        "))
                    lines.extend(indent_lines(gen_field_coder_stmts(env, f, "s"), "        "))
                    lines.append(
                        f'        }} else if (dcerpc_ptr_coder("{f.name}", dce, pdu, iov,\n'
                        f"                         (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
                        f"                          s->{f.name} == NULL) ? NULL : (void *)s,\n"
                        f"                         PTR_UNIQUE, {forward_size_helper_name(env, t, f)})) {{\n"
                        f"                return -1;\n"
                        f"        }}"
                    )
                elif f.name in fwd_sizes:
                    lines.append("        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {")
                    lines.extend(indent_lines(gen_field_coder_stmts(env, f, "s"), "        "))
                    lines.append("        }")
                else:
                    lines.extend(gen_field_coder_stmts(env, f, "s"))
            lines.append("")
            lines.append("        return 0;")
            lines.append("}")
            lines.append("")
            # struct wrapper: YAML/JSON nesting, NDR alignment and padding
            a32, a64 = struct_align(env, t.name)
            lines.append("int")
            lines.append(
                f"{env.struct_coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu,\n"
                f"                struct dcerpc_iovec *iov,\n"
                f"                void *ptr)"
            )
            lines.append("{")
            lines.append(
                f"        /* NDR alignment: {a32} (NDR32), {a64} (NDR64) */\n"
                f"        return dcerpc_aligned_struct_coder(name, dce, pdu, iov, ptr,\n"
                f"                                           {env.coder_name(t.name)}, {a32}, {a64});"
            )
            lines.append("}")
            lines.append("")

        elif t.kind == "union" and t.name in switched_param_unions(env):
            lines.extend(gen_union_coder(env, t))
            lines.append("/* The union as a [switch_is] parameter: discriminant from switch_is */")
            lines.append("int")
            lines.append(
                f"{env.prefix}_{t.name}_switch_coder(char *name, struct dcerpc_context *dce,\n"
                f"                struct dcerpc_pdu *pdu,\n"
                f"                struct dcerpc_iovec *iov,\n"
                f"                void *ptr)"
            )
            lines.append("{")
            lines.append("        uint32_t level = dcerpc_get_switch_is(pdu);")
            lines.append("")
            ufn = union_coder_fn(env, t.name)
            lines.append(
                f"        return {ufn}(name, dce, pdu, iov, &level, ptr,\n"
                f"                {' ' * len(ufn)}{env.coder_name(t.name)}"
                f"{union_coder_args(env, t.name)});"
            )
            lines.append("}")
            lines.append("")
            if t.name in double_ptr_unions(env):
                lines.append("/* A unique pointer to the union: NULL encodes a NULL referent */")
                lines.append("int")
                lines.append(
                    f"{env.prefix}_{t.name}_switch_ptr_coder(char *name, struct dcerpc_context *dce,\n"
                    f"                struct dcerpc_pdu *pdu,\n"
                    f"                struct dcerpc_iovec *iov,\n"
                    f"                void *ptr)"
                )
                lines.append("{")
                lines.append(f"        {env.c_union_name(t.name)} **pp = ptr;")
                lines.append("")
                lines.append("        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && *pp == NULL) {")
                lines.append("                *pp = dcerpc_alloc_data(pdu, sizeof(**pp));")
                lines.append("                if (*pp == NULL) {")
                lines.append("                        return -1;")
                lines.append("                }")
                lines.append("        }")
                lines.append(f"        return {env.prefix}_{t.name}_switch_coder(name, dce, pdu, iov, *pp);")
                lines.append("}")
                lines.append("")
        elif t.kind == "union":
            lines.extend(gen_union_coder(env, t))

    return "\n".join(lines)


def gen_union_coder(env: TypeEnv, t: TypeDef) -> List[str]:
    lines: List[str] = []
    lines.append("int")
    lines.append(
        f"{env.coder_name(t.name)}(char *name, struct dcerpc_context *dce,\n"
        f"                struct dcerpc_pdu *pdu,\n"
        f"                struct dcerpc_iovec *iov,\n"
        f"                void *ptr)"
    )
    lines.append("{")
    lines.append(f"        {env.c_union_name(t.name)} *u = ptr;")
    lines.append("")
    lines.append("        (void)name;")
    lines.append("        switch (dcerpc_get_switch_is(pdu)) {")
    for f in t.fields:
        case_n = env.case_value(f)
        if case_n is None:
            continue
        lines.append(f"        case {case_n}:")
        case_lines = gen_union_case_stmts(env, f, "u", "                ")
        lines.extend(case_lines)
        lines.append("                break;")
    lines.append("        default:")
    lines.append("                /* NDR conformance pass: the discriminant is not read yet */")
    lines.append("                if (dcerpc_pdu_is_conformance_run(pdu)) {")
    lines.append("                        return 0;")
    lines.append("                }")
    lines.append("                return -1;")
    lines.append("        }")
    lines.append("")
    lines.append("        return 0;")
    lines.append("}")
    lines.append("")

    return lines


def ptr_type_for_param(p: Param) -> str:
    if attr_has(p.attrs, "ptr"):
        return "PTR_FULL"
    if attr_has(p.attrs, "unique"):
        return "PTR_UNIQUE"
    if attr_has(p.attrs, "ref"):
        return "PTR_REF"
    # pointer_default(unique) for pointer-ish params
    if p.stars > 0 or p.type_name.startswith("LP"):
        return "PTR_UNIQUE"
    # top-level scalars: treat as REF (matches existing hand-written coders)
    return "PTR_REF"


def switched_param_unions(env: TypeEnv) -> List[str]:
    """Union types used as [switch_is] function parameters."""
    out: List[str] = []
    for fn in env.iface.functions:
        for p in fn.params:
            tname, _ = env.resolve_pointee(p.type_name, p.stars)
            dbl = param_double_ptr_union(env, p)
            if dbl is not None:
                tname = dbl
            if (tname in env.types and env.types[tname].kind == "union" and
                    attr_arg(p.attrs, "switch_is") is not None and
                    tname not in out):
                out.append(tname)
    return out


def double_ptr_unions(env: TypeEnv) -> List[str]:
    """Unions behind an [out,switch_is] PUNION * parameter."""
    out: List[str] = []
    for fn in env.iface.functions:
        for p in fn.params:
            dbl = param_double_ptr_union(env, p)
            if dbl is not None and dbl not in out:
                out.append(dbl)
    return out


def switch_source(fn, p: Param, var: str) -> str:
    """C expression for the discriminant of a [switch_is] union parameter."""
    sw = attr_arg(p.attrs, "switch_is")
    src = next((q for q in fn.params if q.name == sw), None)
    if src is None:
        raise SystemExit(f"error: {fn.name}: switch_is({sw}) is not a parameter")
    p_in, p_out = param_directions(p)
    s_in, s_out = param_directions(src)
    # coding the reply: use the reply field if the discriminant is [out]
    if var == "rep" and not s_out:
        return f"req->{sw}"
    if var == "req" and not s_in:
        raise SystemExit(f"error: {fn.name}: [in] {p.name} switched by "
                         f"[out]-only {sw}")
    return f"{var}->{sw}"


def gen_param_coder(env: TypeEnv, p: Param, var: str, indent: str = "        ",
                    fn=None) -> List[str]:
    lines: List[str] = []
    tname, stars = env.resolve_pointee(p.type_name, p.stars)
    disp = p.name
    ptype = ptr_type_for_param(p)

    # [ref] pointer to a unique LP* struct pointer: only the inner one is
    # on the wire
    dbl = param_double_ptr(env, p)
    if dbl is not None:
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{p.name},\n'
            f"{indent}                     PTR_UNIQUE, {env.struct_coder_name(dbl)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # [ref] pointer to a unique pointer to a switched union
    dbl = param_double_ptr_union(env, p)
    if dbl is not None:
        if fn is None:
            raise SystemExit(f"error: union parameter {p.name} needs switch_is")
        lines.append(f"{indent}dcerpc_set_switch_is(pdu, {switch_source(fn, p, var)});")
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                     (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
            f"{indent}                      {var}->{p.name} == NULL) ? NULL : &{var}->{p.name},\n"
            f"{indent}                     PTR_UNIQUE, {env.prefix}_{dbl}_switch_ptr_coder)) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    size_is = attr_arg(p.attrs, "size_is")
    if byte_array_param(env, p):
        length_is = attr_arg(p.attrs, "length_is")
        lines.append(f"{indent}{{")
        if length_is is None:
            # top-level [ref] conformant byte array
            lines.append(
                f"{indent}        struct dcerpc_bytes bytes;\n"
                f"\n"
                f"{indent}        bytes.len = {var}->{size_is};\n"
                f"{indent}        bytes.data = {var}->{p.name};\n"
                f'{indent}        if (dcerpc_bytes_coder("{disp}", dce, pdu, iov, &bytes)) {{\n'
                f"{indent}                return -1;\n"
                f"{indent}        }}\n"
                f"{indent}        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {{\n"
                f"{indent}                {var}->{p.name} = bytes.data;\n"
                f"{indent}                {p.name}_wire_max = bytes.len;\n"
                f"{indent}        }}"
            )
        else:
            # size_is/length_is name the parameters holding the buffer
            # size and the byte count; the pointer is always sent
            lines.append(
                f"{indent}        struct dcerpc_varying_bytes vb;\n"
                f"\n"
                f"{indent}        vb.max_count = {var}->{size_is};\n"
                f"{indent}        vb.len = {var}->{length_is};\n"
                f"{indent}        vb.data = {var}->{p.name};\n"
                f"{indent}        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {{\n"
                f"{indent}                /* left as is by a NULL referent */\n"
                f"{indent}                vb.max_count = vb.len = UINT32_MAX;\n"
                f"{indent}        }}\n"
                f'{indent}        if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &vb,\n'
                f"{indent}                             {ptype}, dcerpc_varying_bytes_coder)) {{\n"
                f"{indent}                return -1;\n"
                f"{indent}        }}\n"
                f"{indent}        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {{\n"
                f"{indent}                {var}->{p.name} = vb.data;\n"
                f"{indent}                {p.name}_wire_max = vb.max_count;\n"
                f"{indent}                {p.name}_wire_len = vb.len;\n"
                f"{indent}        }}"
            )
        lines.append(f"{indent}}}")
        return lines

    # nullable [unique] T *: NULL encodes a NULL referent; decode allocates
    pt = nullable_param(env, p)
    if pt is not None:
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                     (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
            f"{indent}                      {var}->{p.name} == NULL) ? NULL : &{var}->{p.name},\n"
            f"{indent}                     {ptr_kind(env, p.type_name, p.attrs)}, {env.ptr_helper_name(pt)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # [size_is(n)] array parameter: a top-level [ref] conformant array; with
    # [length_is(l)] conformant-varying. Coding the reply, a size from an
    # [in]-only parameter comes from the request.
    if size_is is not None:
        ctype, _ = pointee_ctype_coder(env, tname)
        if stars >= 2:
            ctype = c_ptr(ctype)
        size = param_value(fn, size_is, var) if fn is not None else f"{var}->{size_is}"
        length_is = attr_arg(p.attrs, "length_is")
        lines.append(f"{indent}dcerpc_set_size_is(pdu, {size});")
        # A conformant-varying array has only length_is elements on the
        # wire, and decoding writes no more (the wire's size must still be
        # size_is): allocate those, so a large size_is (samr's 1000 Names)
        # is neither allocated nor refused as more than the PDU can hold.
        count = size
        if length_is is not None:
            count = param_value(fn, length_is, var)
            lines.append(f"{indent}dcerpc_set_length_is(pdu, {count});")
        lines.append(
            f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && {size} &&\n"
            f"{indent}    {var}->{p.name} == NULL) {{\n"
            f"{indent}        {var}->{p.name} = dcerpc_alloc_array(pdu, iov,\n"
            f"{indent}                {count}, sizeof({ctype}));\n"
            f"{indent}        if ({var}->{p.name} == NULL) {{\n"
            f"{indent}                return -1;\n"
            f"{indent}        }}\n"
            f"{indent}}}"
        )
        helper = (env.cvarray_coder_name(array_elem(env, p)) if length_is is not None
                  else env.carray_coder_name(array_elem(env, p)))
        # an empty array is never dereferenced, but the pointer must not be NULL
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov,\n'
            f"{indent}                     {var}->{p.name} ? (void *){var}->{p.name} : (void *)&{var}->{p.name},\n"
            f"{indent}                     PTR_REF, {helper})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # libdcerpc built-in type (context handle, RPC_SID, ...): top-level
    # [ref], or [unique] (always sent) when declared so or behind a second
    # pointer ([out] RPC_UNICODE_STRING **)
    ext = env.extern(tname)
    if ext is not None:
        coder = (f"{env.prefix}_{tname}_param_coder"
                 if tname in env.context_handles else ext[1])
        uptype = ("PTR_UNIQUE" if attr_has(p.attrs, "unique") or stars >= 2
                  else "PTR_REF")
        # [max_length(n)]: the RPC_UNICODE_STRING's MaximumLength is at
        # least n bytes, the size of the receive buffer it announces
        max_length = attr_arg(p.attrs, "max_length")
        if max_length is not None:
            lines.append(f"{indent}dcerpc_set_unicode_max_length(pdu, {max_length});")
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{p.name},\n'
            f"{indent}                     {uptype}, {coder})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    # union parameter, discriminant from another parameter
    if tname in env.types and env.types[tname].kind == "union":
        if attr_arg(p.attrs, "switch_is") is None or fn is None:
            raise SystemExit(f"error: union parameter {p.name} needs switch_is")
        # top-level pointers are [ref] unless declared [unique]
        uptype = "PTR_UNIQUE" if attr_has(p.attrs, "unique") else "PTR_REF"
        lines.append(f"{indent}dcerpc_set_switch_is(pdu, {switch_source(fn, p, var)});")
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{p.name},\n'
            f"{indent}                     {uptype}, {env.prefix}_{tname}_switch_coder)) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    if env.is_string_type(p.type_name, p.stars, p.attrs) or tname in env.string_aliases:
        target = f"&{var}->{p.name}"
        if ptype == "PTR_UNIQUE":
            # an unset [unique] string is a NULL pointer, not ""
            lines.append(
                f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&\n"
                f"{indent}    {var}->{p.name} == NULL) {{\n"
                f'{indent}        if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, NULL,\n'
                f"{indent}                             PTR_UNIQUE, dcerpc_utf16z_coder)) {{\n"
                f"{indent}                return -1;\n"
                f"{indent}        }}\n"
                f"{indent}}} else if (dcerpc_ptr_coder(\"{disp}\", dce, pdu, iov, {target},\n"
                f"{indent}                            PTR_UNIQUE, dcerpc_utf16z_coder)) {{\n"
                f"{indent}        return -1;\n"
                f"{indent}}}"
            )
            return lines
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, {target},\n'
            f"{indent}                     {ptype}, dcerpc_utf16z_coder)) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    if tname in env.types and env.types[tname].kind == "struct":
        # top-level ref/unique struct: use _struct_coder for nesting
        coder = env.struct_coder_name(tname)
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{p.name},\n'
            f"{indent}                     {ptype}, {coder})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    if tname in env.types and env.types[tname].kind == "enum":
        lines.append(
            f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{p.name},\n'
            f"{indent}                     {ptype}, {env.coder_name(tname)})) {{\n"
            f"{indent}        return -1;\n"
            f"{indent}}}"
        )
        return lines

    if tname in BUILTINS:
        coder = builtin_coder(tname)
        if coder:
            # PreferedMaximumLength etc.: top-level via ptr_coder
            lines.append(
                f'{indent}if (dcerpc_ptr_coder("{disp}", dce, pdu, iov, &{var}->{p.name},\n'
                f"{indent}                     {ptype}, {coder})) {{\n"
                f"{indent}        return -1;\n"
                f"{indent}}}"
            )
            lines.extend(range_check_lines(p.attrs, f"{var}->{p.name}", indent))
            return lines

    lines.append(f"{indent}/* TODO param {p.name} */")
    return lines


def byte_array_wire_decls(env: TypeEnv, params: List[Param], indent: str = "        ") -> List[str]:
    """
    Locals that keep the lengths a byte array parameter had on the wire.
    UINT32_MAX means not sent (a NULL referent) or not decoded.
    """
    lines: List[str] = []
    for p in params:
        if not byte_array_param(env, p):
            continue
        lines.append(f"{indent}uint32_t {p.name}_wire_max = UINT32_MAX;")
        if attr_arg(p.attrs, "length_is") is not None:
            lines.append(f"{indent}uint32_t {p.name}_wire_len = UINT32_MAX;")
    return lines


def byte_array_wire_checks(env: TypeEnv, params: List[Param], var: str,
                           indent: str = "        ") -> List[str]:
    """
    A byte array parameter's size_is/length_is name other parameters, which
    the peer sends separately from the array and often after it (MS-RRP
    puts lpcbData/lpcbLen after lpData). Once everything is decoded, the
    array must be exactly as long as those parameters say, or a caller
    using them as the length of the data reads past it. YAML/JSON carry
    only the bytes, not a separate buffer size, so there only length_is
    is checked.
    """
    lines: List[str] = []
    for p in params:
        if not byte_array_param(env, p):
            continue
        size_is = attr_arg(p.attrs, "size_is")
        length_is = attr_arg(p.attrs, "length_is")
        if length_is is None:
            lines.append(
                f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&\n"
                f"{indent}    {p.name}_wire_max != UINT32_MAX &&\n"
                f"{indent}    {p.name}_wire_max != {var}->{size_is}) {{\n"
                f"{indent}        return -1;\n"
                f"{indent}}}"
            )
        else:
            lines.append(
                f"{indent}if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&\n"
                f"{indent}    {p.name}_wire_max != UINT32_MAX &&\n"
                f"{indent}    ({p.name}_wire_len != {var}->{length_is} ||\n"
                f"{indent}     (dcerpc_pdu_encoding(pdu) == ENCODING_NDR &&\n"
                f"{indent}      {p.name}_wire_max != {var}->{size_is}))) {{\n"
                f"{indent}        return -1;\n"
                f"{indent}}}"
            )
    return lines


def gen_function_coders(env: TypeEnv) -> str:
    lines: List[str] = []
    for i, fn in enumerate(env.iface.functions):
        op = fn_opnum(fn, i)
        op_s = f"0x{op:02x}"
        lines.append(f"/*****************")
        lines.append(f" * Function: {op_s}  {fn.name}  ({fn_opnum_macro(env, fn)})")
        lines.append(f" *****************/")

        # request
        lines.append("int")
        lines.append(
            f"{env.prefix}_{fn.name}_req_coder(char *name, struct dcerpc_context *dce,\n"
            f"                struct dcerpc_pdu *pdu,\n"
            f"                struct dcerpc_iovec *iov,\n"
            f"                void *ptr)"
        )
        lines.append("{")
        lines.append(f"        struct {env.prefix}_{fn.name}_req *req = ptr;")
        in_params = [p for p in fn.params if param_directions(p)[0]]
        lines.extend(byte_array_wire_decls(env, in_params))
        lines.append("")
        lines.append("        (void)name;")
        for p in in_params:
            lines.extend(gen_param_coder(env, p, "req", fn=fn))
        lines.extend(byte_array_wire_checks(env, in_params, "req"))
        lines.append("")
        lines.append("        return 0;")
        lines.append("}")
        lines.append("")

        # response
        lines.append("int")
        lines.append(
            f"{env.prefix}_{fn.name}_rep_coder(char *name, struct dcerpc_context *dce,\n"
            f"                struct dcerpc_pdu *pdu,\n"
            f"                struct dcerpc_iovec *iov,\n"
            f"                void *ptr)"
        )
        lines.append("{")
        lines.append(f"        struct {env.prefix}_{fn.name}_rep *rep = ptr;")
        needs_req = any(
            param_directions(p)[1] and attr_arg(p.attrs, "switch_is") and
            switch_source(fn, p, "rep").startswith("req->")
            for p in fn.params) or any(
            param_directions(p)[1] and attr_arg(p.attrs, a) and
            param_value(fn, attr_arg(p.attrs, a), "rep").startswith("req->")
            for p in fn.params for a in ("size_is", "length_is"))
        if needs_req:
            lines.append("        /* the request holds an [in] value the reply depends on */")
            lines.append(f"        struct {env.prefix}_{fn.name}_req *req = dcerpc_get_request(pdu);")
        out_params = [p for p in fn.params if param_directions(p)[1]]
        lines.extend(byte_array_wire_decls(env, out_params))
        lines.append("")
        lines.append("        (void)name;")
        if needs_req:
            lines.append("        if (req == NULL) {")
            lines.append("                return -1;")
            lines.append("        }")
        for p in out_params:
            lines.extend(gen_param_coder(env, p, "rep", fn=fn))
        lines.extend(byte_array_wire_checks(env, out_params, "rep"))
        if fn.ret_type in STATUS_TYPES:
            lines.append(
                '        if (dcerpc_uint32_coder("Status", dce, pdu, iov, &rep->status)) {\n'
                "                return -1;\n"
                "        }"
            )
        lines.append("")
        lines.append("        return 0;")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def uuid_to_c_parts(uuid: str) -> Tuple[str, str, str, str]:
    """
    uuid 4b324fc8-1670-01d3-1278-5a47bf6ee188
    → 0x4b324fc8, 0x1670, 0x01d3, {0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88}
    """
    u = uuid.strip().replace("{", "").replace("}", "")
    parts = u.split("-")
    if len(parts) != 5:
        raise ValueError(f"bad uuid: {uuid}")
    p1 = f"0x{parts[0]}"
    p2 = f"0x{parts[1]}"
    p3 = f"0x{parts[2]}"
    rest = parts[3] + parts[4]
    if len(rest) != 16:
        raise ValueError(f"bad uuid rest: {uuid}")
    bytes_ = [f"0x{rest[i:i+2]}" for i in range(0, 16, 2)]
    return p1, p2, p3, ", ".join(bytes_)


def gen_interface_uuid(env: TypeEnv) -> str:
    """Interface UUID / version object at the top of the .c file."""
    lines: List[str] = []
    uuid = attr_arg(env.iface.attrs, "uuid") or "00000000-0000-0000-0000-000000000000"
    vers = attr_arg(env.iface.attrs, "version") or "1.0"
    major, _, minor = vers.partition(".")
    if not minor:
        minor = "0"
    p1, p2, p3, p4 = uuid_to_c_parts(uuid)

    lines.append(
        f"#define {env.prefix.upper()}_UUID    {p1}, {p2}, {p3}, {{{p4}}}"
    )
    lines.append("")
    lines.append(f"p_syntax_id_t {env.prefix}_interface = {{")
    lines.append(f"        {{{env.prefix.upper()}_UUID}}, {major}, {minor}")
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def gen_procs_table(env: TypeEnv) -> str:
    """
    Generate struct dcerpc_procedure <iface>_procs[] like libdcerpc:

        { opnum, "Name",
          Name_req_coder, sizeof(struct Name_req),
          Name_rep_coder, sizeof(struct Name_rep),
        },
        { -1, NULL, NULL, 0, NULL, 0 }

    <iface>_find_proc(opnum) is a static inline in the server header.
    """
    lines: List[str] = []

    lines.append("/* Procedure table: opnum → request/response coders and sizes */")
    lines.append(f"struct dcerpc_procedure {env.prefix}_procs[] = {{")
    for i, fn in enumerate(env.iface.functions):
        op_macro = fn_opnum_macro(env, fn)
        lines.append(f"        {{{op_macro}, \"{fn.name}\",")
        lines.append(
            f"         {env.prefix}_{fn.name}_req_coder, "
            f"sizeof(struct {env.prefix}_{fn.name}_req),"
        )
        lines.append(
            f"         {env.prefix}_{fn.name}_rep_coder, "
            f"sizeof(struct {env.prefix}_{fn.name}_rep),"
        )
        lines.append("        },")
    lines.append("        {-1, NULL, NULL, 0, NULL, 0}")
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def gen_stubs_table(env: TypeEnv) -> str:
    """
    Generate struct dcerpc_stub <iface>_stubs[] for the stubs .c file.
    Kept out of the coder so clients do not need server stub symbols.
    """
    lines: List[str] = []
    lines.append("/*********************************************************************")
    lines.append(f" * Stub table: opnum → server implementation")
    lines.append(f" *")
    lines.append(f" * Lives in the stubs .c (with the *_stub functions), not the")
    lines.append(f" * generated coder, so clients can link coders alone.")
    lines.append(f" * Served with dcerpc_server_add_interface() (<dcerpc/server.h>).")
    lines.append(f" *********************************************************************/")
    lines.append("")
    lines.append(f"struct dcerpc_stub {env.prefix}_stubs[] = {{")
    for i, fn in enumerate(env.iface.functions):
        op_macro = fn_opnum_macro(env, fn)
        lines.append(
            f"        {{{op_macro}, \"{fn.name}\", {env.prefix}_{fn.name}_stub}},"
        )
    lines.append("        {-1, NULL, NULL}")
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def idl_license(src: str) -> str:
    """The IDL's SPDX-License-Identifier, as a C comment line ("" if none)."""
    m = re.search(r"SPDX-License-Identifier:\s*([^\s*]+)", src[:2000])
    return f"/* SPDX-License-Identifier: {m.group(1)} */\n" if m else ""


def exported_symbols(env: TypeEnv, c_src: str) -> List[str]:
    """Non-static functions and data the generated coder .c defines."""
    funcs = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(", c_src, flags=re.M))
    static = set(re.findall(r"^static [^\n]*\n([A-Za-z_][A-Za-z0-9_]*)\(",
                            c_src, flags=re.M))
    syms = (funcs - static) | set(
        re.findall(r"^(?:p_syntax_id_t|struct dcerpc_procedure) "
                   r"([A-Za-z_][A-Za-z0-9_]*)", c_src, flags=re.M))
    return sorted(syms, key=lambda x: x.lower())


def update_syms(path: Path, prefix: str, syms: List[str]) -> None:
    """
    Replace the <prefix>_* lines of a libtool -export-symbols list with syms,
    keeping the file's case-insensitive order.
    """
    lines = path.read_text(encoding="utf-8").split("\n")
    mine = [i for i, l in enumerate(lines) if l.startswith(prefix + "_")]
    rest = [l for l in lines if not l.startswith(prefix + "_")]
    if mine:
        at = mine[0]
    else:
        at = next((i for i, l in enumerate(rest)
                   if l and l.lower() > syms[0].lower()), len(rest))
    path.write_text("\n".join(rest[:at] + syms + rest[at:]), encoding="utf-8")


def generate(iface: Interface, idl_name: str, header_name: str,
             license: str = "", libdcerpc: bool = False,
             server_header_name: Optional[str] = None) -> Tuple[str, str, Optional[str]]:
    """
    Returns (header, coder .c, server header or None).
    libdcerpc: the coder is a libdcerpc source file (libdcerpc include set,
    public header included as <dcerpc/header_name>).
    """
    env = TypeEnv(iface)
    # A libdcerpc header is installed as <dcerpc/header_name>; include the
    # directory so the guard stays distinct (_DCERPC_SRVSVC_H_).
    guard_name = f"dcerpc/{header_name}" if libdcerpc else header_name
    guard = re.sub(r"[^A-Z0-9]", "_", guard_name.upper())

    h_body = []
    h_body.append(gen_struct_defs(env))
    if iface.has_interface:
        h_body.append(gen_req_rep_structs(env))
    h_body.append(gen_prototypes(env))
    includes = []
    for t in iface.types:
        for f in t.fields if t.kind == "struct" else []:
            bt = blob_type(f)
            if bt is not None and f"#include <{bt[2]}>" not in includes:
                includes.append(f"#include <{bt[2]}>")
            et, _ = env.resolve_pointee(f.type_name, f.stars)
            ext = env.extern(et)
            if ext is not None and ext[2] and f"#include <{ext[2]}>" not in includes:
                includes.append(f"#include <{ext[2]}>")
    # and the types of function parameters, e.g. [out] RPC_SID **
    for fn in iface.functions if iface.has_interface else []:
        for p in fn.params:
            et, _ = env.resolve_pointee(p.type_name, p.stars)
            ext = env.extern(et)
            if ext is not None and ext[2] and f"#include <{ext[2]}>" not in includes:
                includes.append(f"#include <{ext[2]}>")
    header = HEADER_TEMPLATE.format(
        idl_name=idl_name, guard=guard, body="\n".join(h_body),
        includes="\n".join(includes) + ("\n" if includes else ""),
        license=license,
    )

    # Order matches hand-written libdcerpc sources: interface UUID, type
    # coders, function coders, then the procedure table at the end.
    # Data-only IDL (no interface): type coders only.
    tmpl = C_HEADER_LIBDCERPC if libdcerpc else C_HEADER
    c_parts = [tmpl.format(idl_name=idl_name, header_name=header_name,
                           license=license)]
    if iface.has_interface:
        c_parts.append(gen_interface_uuid(env))
    c_parts.append(gen_type_coders(env))
    if iface.has_interface:
        c_parts.append(gen_function_coders(env))
        c_parts.append(gen_procs_table(env))
    c_src = "\n".join(c_parts)

    server = None
    if server_header_name and iface.has_interface:
        sguard = re.sub(r"[^A-Z0-9]", "_", server_header_name.upper())
        server = SERVER_HEADER_TEMPLATE.format(
            license=license, idl_name=idl_name, guard=sguard,
            coder_header=header_name,
            coder_include=(f"<dcerpc/{header_name}>" if libdcerpc
                           else f'"{header_name}"'),
            body=gen_server_decls(env).rstrip("\n"),
        )
    return header, c_src, server


def gen_stubs_skeleton(env: TypeEnv, idl_name: str, header_name: str) -> str:
    """
    Skeleton server stubs for each IDL operation.
    Bodies return -1 until filled in; safe starting point for a new interface.
    """
    lines: List[str] = []
    lines.append("/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */")
    lines.append("/*")
    lines.append(f" * AUTO-GENERATED skeleton by idlcomp.py --stubs from {idl_name}.")
    lines.append(" *")
    lines.append(" * Fill in each *_stub() implementation.  Re-running idlcomp with")
    lines.append(" * --stubs will refuse to overwrite this file unless --force-stubs")
    lines.append(" * is also given (so hand-filled logic is not lost on IDL recompile).")
    lines.append(" *")
    lines.append(f" * Also defines {env.prefix}_stubs[] (dispatch table). Keep the table")
    lines.append(" * in this file when editing by hand — not in the generated coder.")
    lines.append(" * req/rep are the decoded request and the response buffer to fill.")
    lines.append(" * Use dcerpc_alloc_data(pdu, …) for nested allocations on the response.")
    lines.append(" * Return 0 if rep is populated; non-zero on failure.")
    lines.append(" */")
    lines.append("/*")
    lines.append("   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>")
    lines.append("")
    lines.append(
        "Redistribution and use in source and binary forms, with or without "
        "modification, are permitted provided that the following conditions are met:"
    )
    lines.append("")
    lines.append(
        "1. Redistributions of source code must retain the above copyright notice, "
        "this list of conditions and the following disclaimer."
    )
    lines.append("")
    lines.append(
        "2. Redistributions in binary form must reproduce the above copyright notice, "
        "this list of conditions and the following disclaimer in the documentation "
        "and/or other materials provided with the distribution."
    )
    lines.append("")
    lines.append(
        'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" '
        "AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE "
        "IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE "
        "ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE "
        "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR "
        "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF "
        "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS "
        "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN "
        "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) "
        "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE "
        "POSSIBILITY OF SUCH DAMAGE."
    )
    lines.append("*/")
    lines.append("")
    lines.append("#include <stdio.h>")
    lines.append("#include <string.h>")
    lines.append("")
    lines.append(f'#include "{header_name}"')
    lines.append("")

    for fn in env.iface.functions:
        req_type = f"struct {env.prefix}_{fn.name}_req"
        rep_type = f"struct {env.prefix}_{fn.name}_rep"
        lines.append("int")
        lines.append(f"{env.prefix}_{fn.name}_stub(struct dcerpc_context *dce,")
        lines.append("                struct dcerpc_pdu *pdu,")
        lines.append("                void *reqv, void *repv)")
        lines.append("{")
        lines.append(f"        {req_type} *req = reqv;")
        lines.append(f"        {rep_type} *rep = repv;")
        lines.append("")
        lines.append("        (void)dce;")
        lines.append("        (void)pdu;")
        lines.append("        (void)req;")
        lines.append("")
        lines.append("        if (rep == NULL) {")
        lines.append("                return -1;")
        lines.append("        }")
        lines.append(f"        memset(rep, 0, sizeof(*rep));")
        lines.append("")
        lines.append(
            f'        fprintf(stderr, "{env.prefix}: {fn.name} stub not implemented\\n");'
        )
        lines.append("        return -1;")
        lines.append("}")
        lines.append("")

    lines.append(gen_stubs_table(env))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Compile IDL to libdcerpc coder C sources"
    )
    ap.add_argument("idl", type=Path, help="input .idl file")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output coder .c file (default: <idl>_coder.c)",
    )
    ap.add_argument(
        "--header",
        type=Path,
        help="output .h file (default: alongside .c)",
    )
    ap.add_argument(
        "--server-header",
        type=Path,
        help=("output server .h (registration strings, stub table and "
              "prototypes; default: <coder .h stem with _coder → _server>.h "
              "next to the header, none with --libdcerpc)"),
    )
    ap.add_argument(
        "--libdcerpc",
        action="store_true",
        help=("the coder is a libdcerpc source file: use libdcerpc's include "
              "set and include the header as <dcerpc/NAME.h>"),
    )
    ap.add_argument(
        "--update-syms",
        type=Path,
        metavar="FILE",
        help=("rewrite the <iface>_* lines of a libtool -export-symbols "
              "file (e.g. libdcerpc/libdcerpc.syms) from the generated coder"),
    )
    ap.add_argument(
        "--stubs",
        nargs="?",
        type=Path,
        const=Path(""),
        default=None,
        metavar="FILE",
        help=(
            "also write a skeleton stubs .c "
            "(default path: <iface>_stubs.c next to the coder .c)"
        ),
    )
    ap.add_argument(
        "--force-stubs",
        action="store_true",
        help="allow --stubs to overwrite an existing stubs file",
    )
    args = ap.parse_args(argv)

    idl_path: Path = args.idl
    src = idl_path.read_text(encoding="utf-8")
    try:
        toks = tokenize(src)
        iface = Parser(toks).parse()
    except SyntaxError as e:
        print(f"{idl_path}: {e}", file=sys.stderr)
        return 1

    # Data-only IDL has no interface name; use the file stem as C symbol prefix
    # (e.g. config.idl → config_CONFIG_coder, struct config_CONFIG).
    if not iface.has_interface:
        stem = idl_path.stem
        # Normalize to a C identifier (same characters TypeEnv uses as prefix).
        stem = re.sub(r"[^A-Za-z0-9_]", "_", stem)
        if not stem or stem[0].isdigit():
            stem = "idl_" + stem
        iface.name = stem

    if args.stubs is not None and not iface.has_interface:
        print(
            f"error: {idl_path} has no interface (data-only typedefs).\n"
            f"  Type coders can still be generated with -o / --header.\n"
            f"  --stubs requires a full interface with uuid/version and\n"
            f"  operations (there is nothing to stub).",
            file=sys.stderr,
        )
        return 1

    out_c = args.output or idl_path.with_name(idl_path.stem + "_coder.c")
    out_h = args.header or out_c.with_suffix(".h")

    out_sh = args.server_header
    if out_sh is None and iface.has_interface and not args.libdcerpc:
        stem = out_h.stem
        stem = stem[:-len("_coder")] if stem.endswith("_coder") else stem
        out_sh = out_h.with_name(stem + "_server.h")

    header, c_src, server = generate(
        iface, idl_path.name, out_h.name, license=idl_license(src),
        libdcerpc=args.libdcerpc,
        server_header_name=out_sh.name if out_sh else None)
    out_h.write_text(header, encoding="utf-8")
    out_c.write_text(c_src, encoding="utf-8")
    print(f"wrote {out_h}")
    print(f"wrote {out_c}")
    if server is not None:
        out_sh.write_text(server, encoding="utf-8")
        print(f"wrote {out_sh}")
    if args.update_syms:
        update_syms(args.update_syms, iface.name,
                    exported_symbols(TypeEnv(iface), c_src))
        print(f"updated {args.update_syms}")

    if args.stubs is not None:
        if args.stubs == Path(""):
            out_stubs = out_c.with_name(f"{iface.name}_stubs.c")
        else:
            out_stubs = args.stubs
        if out_stubs.exists() and not args.force_stubs:
            print(
                f"error: stubs file already exists: {out_stubs}\n"
                f"  Hand-written implementations are preserved by default.\n"
                f"  Pass --force-stubs only if you intend to replace the file\n"
                f"  with a fresh skeleton (you will lose existing stub code).",
                file=sys.stderr,
            )
            return 1
        env = TypeEnv(iface)
        stubs_src = gen_stubs_skeleton(env, idl_path.name,
                                       out_sh.name if out_sh else out_h.name)
        out_stubs.write_text(stubs_src, encoding="utf-8")
        print(f"wrote {out_stubs}" + (" (overwrote)" if args.force_stubs else ""))

    return 0


if __name__ == "__main__":
    sys.exit(main())
