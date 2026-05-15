#!/usr/bin/env python3
"""
nc_aamva_engine.py  — AAMVA Forensic Authentication Engine  v4.0
=================================================================
Production-grade NC driver license / ID barcode authentication.

Architecture:
  Layer 1 — Parser:        PDF417 raw bytes → structured AAMVA fields
  Layer 2 — NC Validator:  NC DMV-specific field rule enforcement
  Layer 3 — Forensic:      Multi-signal anomaly detection + confidence scoring
  Layer 4 — Classifier:    Weighted verdict: Authentic / Unauthentic / Inconclusive
  Layer 5 — Report:        Human-readable + JSON evidence output

Reference benchmark: NC IIN 636004, AAMVA v08, 32 fields, binary header.
Tilde-escape encoding is ALWAYS a hard FAIL (structural non-compliance).
"""

from __future__ import annotations
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────
# CONSTANTS & LOOKUP TABLES
# ─────────────────────────────────────────────────────────────

NC_IIN = "636004"

AAMVA_IIN_MAP: dict[str, str] = {
    "636000":"AAMVAtest","636001":"Alberta","636002":"British Columbia",
    "636003":"Manitoba","636004":"North Carolina","636005":"Saskatchewan",
    "636006":"Yukon","636007":"Ontario","636008":"Quebec",
    "636009":"New Brunswick","636010":"Florida","636011":"Hawaii",
    "636012":"Newfoundland","636013":"Nova Scotia","636014":"California",
    "636015":"Texas","636016":"Nebraska","636017":"Kansas",
    "636018":"West Virginia","636019":"Michigan","636020":"Colorado",
    "636021":"Ohio","636022":"Minnesota","636023":"New York",
    "636024":"Montana","636025":"Missouri","636026":"Tennessee",
    "636027":"Idaho","636028":"South Dakota","636029":"Oregon",
    "636030":"Wisconsin","636031":"Indiana","636032":"Maryland",
    "636033":"Washington","636034":"Connecticut","636035":"Iowa",
    "636036":"Delaware","636037":"Mississippi","636038":"Oklahoma",
    "636039":"New Hampshire","636040":"Illinois","636041":"Nevada",
    "636042":"Virginia","636043":"Arkansas","636044":"Georgia",
    "636045":"Pennsylvania","636046":"Arizona","636047":"Rhode Island",
    "636048":"Utah","636049":"New Mexico","636050":"Louisiana",
    "636051":"Kentucky","636052":"Wyoming","636053":"Massachusetts",
    "636054":"Vermont","636055":"New Jersey","636056":"Maine",
    "636057":"South Carolina","636058":"North Dakota","636059":"DC",
    "636060":"Alaska","636061":"Alabama","636062":"Prince Edward Island",
    "636063":"American Samoa","636064":"Guam","636065":"US Virgin Islands",
    "636066":"Puerto Rico","636067":"Northwest Territories",
    "636068":"Nunavut","636069":"Mexico","636070":"US State Dept",
    "636071":"AAMVA National",
}

AAMVA_MANDATORY: dict[int, list[str]] = {
    1:["DAQ","DCS","DAC","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK"],
    2:["DAQ","DCS","DAC","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK"],
    3:["DAQ","DCS","DAC","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK"],
    4:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK"],
    5:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK",
       "DCA","DCB","DCD","DCF","DCG","DDE","DDF","DDG"],
    6:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK",
       "DCA","DCB","DCD","DCF","DCG","DDA","DDE","DDF","DDG"],
    7:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK",
       "DCA","DCB","DCD","DCF","DCG","DDA","DDE","DDF","DDG"],
    8:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK",
       "DCA","DCB","DCD","DCF","DCG","DDA","DDE","DDF","DDG"],
    9:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK",
       "DCA","DCB","DCD","DCF","DCG","DDA","DDE","DDF","DDG"],
    10:["DAQ","DCS","DAC","DAD","DBB","DBA","DBD","DBC","DAU","DAY","DAG","DAI","DAJ","DAK",
        "DCA","DCB","DCD","DCF","DCG","DDA","DDE","DDF","DDG"],
}

VALID_TRUNCATION  = {"N","T","U"}
VALID_SEX         = {"1","2","9"}
VALID_COMPLIANCE  = {"F","N","U"}
VALID_EYE         = {"BLK","BLU","BRO","GRY","GRN","HAZ","MAR","PNK","DIC","UNK"}
VALID_HAIR        = {"BAL","BLK","BLN","BRO","GRY","RED","SDY","WHI","UNK"}
VALID_ORGAN_DONOR = {"0","1"}
VALID_VETERAN     = {"1","2","9",""}
VALID_RACE        = {"AI","AP","BK","H","O","U","W"}
VALID_COUNTRIES   = {"USA","CAN","MEX"}

DCK_VENDOR_MAP = {
    "TL":"Idemia/L1","DL":"Digimarc","HO":"HID Global",
    "DM":"DataCard","PC":"Polaroid","DE":"De La Rue",
    "AM":"American Banknote","GP":"Giesecke+Devrient",
}

FIELD_LABELS: dict[str, str] = {
    "DAQ":"DL/ID Number","DCS":"Last Name","DAC":"First Name",
    "DAD":"Middle Name","DBB":"Date of Birth","DBA":"Expiry Date",
    "DBD":"Issue Date","DDB":"Card Revision Date","DDH":"Under-18 Until",
    "DDI":"Under-19 Until","DDJ":"Under-21 Until","DBC":"Sex",
    "DAU":"Height","DAY":"Eye Color","DAZ":"Hair Color",
    "DAW":"Weight (lbs)","DAX":"Weight Range","DAG":"Street Address",
    "DAH":"Address Line 2","DAI":"City","DAJ":"State",
    "DAK":"ZIP Code","DCG":"Country","DCA":"Vehicle Class",
    "DCB":"Restrictions","DCD":"Endorsements","DCF":"Doc Discriminator",
    "DCK":"Audit/Inventory Number","DCL":"Race/Ethnicity","DDA":"Compliance",
    "DDE":"Last Name Truncation","DDF":"First Name Truncation",
    "DDG":"Middle Name Truncation","DDK":"Organ Donor","DDL":"Veteran",
    "DCU":"Name Suffix","ZNA":"NC Replacement","ZNB":"NC Limited-Term",
    "ZNC":"NC Under-21","ZND":"NC Non-Resident CDL","ZNE":"NC Selective Service",
    "ZNF":"NC Veteran","ZNG":"NC Medical","ZNH":"NC Volunteer","ZNI":"NC Non-Compliant Reason",
    "ZNJ":"NC Audit Suffix","ZNK":"NC Customer Sequence",
}

# Weights for scoring — critical signals carry more weight
# Format: (weight_on_fail, is_hard_fail)
SIGNAL_WEIGHTS: dict[str, tuple[float, bool]] = {
    "encoding_binary":          (30.0,  True),   # tilde = instant FAIL
    "iin_registered":           (15.0,  True),   # unknown IIN = FAIL
    "iin_is_nc":                (10.0,  False),  # non-NC loses points only
    "iin_matches_daj":          (8.0,   False),
    "aamva_version_valid":      (5.0,   False),
    "dl_subfile_found":         (10.0,  True),   # no DL subfile = FAIL
    "offsets_valid":            (5.0,   False),
    "mandatory_fields_present": (12.0,  False),
    "nc_dl_number_format":      (10.0,  False),  # NC: exactly 12 digits
    "sex_code_valid":           (5.0,   False),
    "eye_code_valid":           (4.0,   False),
    "hair_code_valid":          (3.0,   False),
    "height_format":            (4.0,   False),
    "dob_valid":                (8.0,   False),
    "dob_age_reasonable":       (10.0,  False),  # age 16-99 for DL
    "dob_age_matches_under21":  (6.0,   False),
    "expiry_future":            (8.0,   False),
    "expiry_birthday_linked":   (4.0,   False),  # NC DLs expire on birthday
    "issue_before_expiry":      (6.0,   False),
    "issue_term_reasonable":    (4.0,   False),  # 4-8 yrs normal
    "zip_format":               (5.0,   False),
    "country_valid":            (4.0,   False),
    "dcf_present":              (5.0,   False),
    "dck_format":               (4.0,   False),
    "dck_matches_daq":          (8.0,   False),
    "dck_vendor_known":         (3.0,   False),
    "compliance_valid":         (3.0,   False),
    "truncation_flags_valid":   (3.0,   False),
    "dcl_format":               (2.0,   False),
    "zn_subfile_present":       (5.0,   False),  # NC always has ZN subfile
    "organ_donor_valid":        (2.0,   False),
}

# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────

@dataclass
class SignalResult:
    signal:      str
    passed:      bool
    weight:      float
    is_hard_fail: bool
    detail:      str = ""

@dataclass
class ForensicReport:
    scan_time:        str = ""
    encoding_mode:    str = "unknown"
    raw_preview:      str = ""
    iin:              str = ""
    state_name:       str = ""
    aamva_ver:        int = 0
    juris_ver:        int = 0
    num_subfiles:     int = 0
    dl_subfile_found: bool = False
    offsets_valid:    bool = False
    fields:           dict = field(default_factory=dict)
    subfiles:         list = field(default_factory=list)
    signals:          list = field(default_factory=list)
    score:            float = 0.0
    max_score:        float = 0.0
    confidence:       float = 0.0
    verdict:          str = "INCONCLUSIVE"
    hard_fail_reason: str = ""
    anomalies:        list = field(default_factory=list)
    missing_mandatory: list = field(default_factory=list)
    parsed_dates:     dict = field(default_factory=dict)
    error:            str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signals"] = [asdict(s) for s in self.signals]
        return d

# ─────────────────────────────────────────────────────────────
# LAYER 1 — PARSER
# ─────────────────────────────────────────────────────────────

def detect_encoding_mode(raw: str) -> str:
    """
    FORENSIC RATIONALE: AAMVA spec §2.3 mandates raw binary control bytes.
    Any tilde-escape (~0a/~1e/~0d) means the encoder substituted ASCII
    representations for binary bytes — this is structural non-compliance
    and a known fingerprint of fake-ID barcode generators (bwip-js default).
    Must be called on ORIGINAL bytes — never on unescape()d string.
    """
    if len(raw) < 4:
        return "unknown"
    b = [ord(raw[i]) for i in range(4)]
    if b == [0x40, 0x0A, 0x1E, 0x0D]:
        return "binary"
    if re.match(r"^@~[0-9a-fA-F]{2}~[0-9a-fA-F]{2}~[0-9a-fA-F]{2}", raw):
        return "tilde_escape"
    return "unknown"

def unescape_tilde(s: str) -> str:
    return re.sub(r"~([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)

def _parse_fields(text: str) -> dict[str, str]:
    """
    Parse AAMVA field tags from a subfile block.
    FIX: Strip 2-char subfile designator before parsing so DL/ZN prefix
    doesn't corrupt the first field tag (DLDAQ -> DAQ not DLD).
    FIX: Preserve trailing spaces — DAK (ZIP) is fixed 11 chars.
    """
    fields: dict[str, str] = {}
    if len(text) >= 5 and re.match(r"^[A-Z]{2}[A-Z]{2}[A-Z0-9]", text):
        text = text[2:]
    for line in re.split(r"[\n\r\x1c\x1d\x1e]", text):
        line = line.lstrip("\x00").rstrip("\r\n")
        if len(line) >= 3:
            tag = line[:3]
            val = line[3:]
            if re.match(r"^[A-Z]{2}[A-Z0-9]$", tag):
                fields[tag] = val
    return fields

def parse_barcode(raw: str) -> dict:
    """Full AAMVA barcode parse. Input must be the normalised (unescape()d) string."""
    result = {
        "header_match": None, "iin": "", "aamva_ver": 0, "juris_ver": 0,
        "num_subfiles": 0, "subfiles": [], "fields": {},
        "offsets_valid": True, "dl_subfile_found": False,
    }
    m = re.search(r"ANSI (\d{6})(\d{2})(\d{2})(\d{2})((?:[A-Z]{2}\d{4}\d{4})+)", raw)
    if m:
        result.update({
            "header_match": m.group(0), "iin": m.group(1),
            "aamva_ver": int(m.group(2)), "juris_ver": int(m.group(3)),
            "num_subfiles": int(m.group(4)),
        })
        entries = re.findall(r"([A-Z]{2})(\d{4})(\d{4})", m.group(5))
        hend = m.end(0)
        for sf_id, sf_off, sf_len in entries:
            off = int(sf_off); length = int(sf_len)
            actual = raw.find(sf_id, hend)
            in_rng = abs(actual - off) <= 5 if actual != -1 else False
            text   = raw[actual:actual + length] if actual != -1 else ""
            fields = _parse_fields(text)
            result["subfiles"].append({
                "id": sf_id, "declared_offset": off, "declared_length": length,
                "actual_start": actual, "offset_valid": in_rng, "fields": fields,
            })
            result["fields"].update(fields)
            if sf_id == "DL":
                result["dl_subfile_found"] = True
            if not in_rng:
                result["offsets_valid"] = False
    else:
        m4 = re.search(r"ANSI (\d{6})(\d{2})(\d{2})", raw)
        if m4:
            result.update({
                "header_match": m4.group(0), "iin": m4.group(1),
                "aamva_ver": int(m4.group(2)), "juris_ver": int(m4.group(3)),
            })
        result["fields"] = _parse_fields(raw)
        result["dl_subfile_found"] = "DAQ" in result["fields"]
    return result

def _parse_date(val: str) -> Optional[datetime]:
    for fmt in ("%m%d%Y", "%Y%m%d", "%m%Y"):
        try:
            return datetime.strptime(val.strip(), fmt)
        except ValueError:
            pass
    return None

# ─────────────────────────────────────────────────────────────
# LAYER 2 + 3 — NC VALIDATOR + FORENSIC ANALYSIS
# ─────────────────────────────────────────────────────────────

def run_signals(raw_original: str, parsed: dict, fields: dict) -> tuple[list[SignalResult], list[str], dict]:
    """
    Execute all forensic signals. Returns (signals, anomalies, parsed_dates).
    Each signal has forensic rationale in comments.
    """
    S = SIGNAL_WEIGHTS
    results: list[SignalResult] = []
    anomalies: list[str] = []
    dates: dict = {}
    today = datetime.today()

    def sig(name: str, passed: bool, detail: str = "") -> SignalResult:
        w, hf = S.get(name, (1.0, False))
        s = SignalResult(signal=name, passed=passed, weight=w, is_hard_fail=hf, detail=detail)
        results.append(s)
        if not passed:
            anomalies.append(f"[{name}] {detail or 'FAIL'}")
        return s

    # SIGNAL 1: Encoding mode
    enc_mode = detect_encoding_mode(raw_original)
    sig("encoding_binary", enc_mode == "binary",
        f"mode={enc_mode} — {'raw binary OK' if enc_mode=='binary' else 'tilde-escape is NOT authentic AAMVA encoding'}")

    iin = parsed.get("iin", "")
    ver = parsed.get("aamva_ver", 0)

    # SIGNAL 2: IIN registered
    iin_known = iin in AAMVA_IIN_MAP
    sig("iin_registered", iin_known, f"IIN={iin} -> {AAMVA_IIN_MAP.get(iin,'UNKNOWN')}")

    # SIGNAL 3: IIN is NC
    is_nc = (iin == NC_IIN)
    daj = fields.get("DAJ", "").strip().upper()
    if daj == "NC":
        sig("iin_is_nc", is_nc, f"DAJ=NC requires IIN=636004, got {iin}")
    else:
        sig("iin_is_nc", True, f"Non-NC state {daj}, IIN check skipped")

    # SIGNAL 4: IIN state matches DAJ
    state_name = AAMVA_IIN_MAP.get(iin, "")
    state_from_abbr = _abbr_to_name(daj)
    iin_matches = (state_name.lower() == state_from_abbr.lower()) if daj else False
    sig("iin_matches_daj", iin_matches, f"IIN->{state_name} vs DAJ->{state_from_abbr}")

    # SIGNAL 5: AAMVA version
    ver_ok = 1 <= ver <= 10
    sig("aamva_version_valid", ver_ok, f"v{ver:02d} {'OK' if ver_ok else 'out of range 01-10'}")

    # SIGNAL 6: DL subfile
    sig("dl_subfile_found", parsed.get("dl_subfile_found", False), "DL subfile designator in barcode")

    # SIGNAL 7: Subfile byte offsets
    sig("offsets_valid", parsed.get("offsets_valid", False), "Declared offsets match actual field positions")

    # SIGNAL 8: Mandatory fields
    v_clamped = min(max(ver, 1), 10)
    mandatory = AAMVA_MANDATORY.get(v_clamped, AAMVA_MANDATORY[8])
    missing = [t for t in mandatory if t not in fields]
    sig("mandatory_fields_present", len(missing) == 0,
        f"Missing: {missing}" if missing else "All mandatory fields present")

    # SIGNAL 9: NC DL number format
    daq = fields.get("DAQ", "").strip()
    nc_dl_ok = bool(re.match(r"^\d{12}$", daq)) if daq else False
    sig("nc_dl_number_format", nc_dl_ok,
        f"DAQ={repr(daq)} — NC requires exactly 12 digits" if not nc_dl_ok else f"DAQ={daq} ok")

    # SIGNAL 10: Sex code
    dbc = fields.get("DBC", "").strip()
    sig("sex_code_valid", dbc in VALID_SEX if dbc else True,
        f"DBC={repr(dbc)} valid={VALID_SEX}" if dbc not in VALID_SEX else f"DBC={dbc} ok")

    # SIGNAL 11: Eye color
    day_eye = fields.get("DAY", "").strip()
    sig("eye_code_valid", day_eye in VALID_EYE if day_eye else True,
        f"DAY={repr(day_eye)}" if day_eye not in VALID_EYE else f"DAY={day_eye} ok")

    # SIGNAL 12: Hair color
    daz = fields.get("DAZ", "").strip()
    sig("hair_code_valid", daz in VALID_HAIR if daz else True,
        f"DAZ={repr(daz)}" if daz not in VALID_HAIR else f"DAZ={daz} ok")

    # SIGNAL 13: Height format
    dau = fields.get("DAU", "").strip()
    h_ok = bool(re.match(r"^\d{3} (in|cm)$", dau)) if dau else True
    sig("height_format", h_ok, f"DAU={repr(dau)}" if not h_ok else f"DAU={dau} ok")

    # SIGNAL 14: DOB parseable
    dob_val = fields.get("DBB", "")
    dob_dt = _parse_date(dob_val) if dob_val else None
    sig("dob_valid", dob_dt is not None if dob_val else True,
        f"DBB={repr(dob_val)} not parseable" if dob_val and dob_dt is None else "DOB parsed OK")
    if dob_dt:
        dates["dob"] = dob_dt

    # SIGNAL 15: DOB age reasonable
    if dob_dt:
        age = (today - dob_dt).days / 365.25
        age_ok = 15 <= age <= 110
        sig("dob_age_reasonable", age_ok,
            f"Computed age {age:.0f} {'OK' if age_ok else 'IMPOSSIBLE for DL holder'}")
        if not age_ok:
            anomalies.append(f"DOB gives impossible age {age:.0f} for a DL holder")
    else:
        sig("dob_age_reasonable", True, "No DOB to check")

    # SIGNAL 16: Age-under-21 field consistency
    ddj_val = fields.get("DDJ", "")
    dbd_val = fields.get("DBD", "")
    if ddj_val and dob_dt and dbd_val:
        issue_dt = _parse_date(dbd_val)
        ddj_dt   = _parse_date(ddj_val)
        if issue_dt and ddj_dt:
            age_at_issue = (issue_dt - dob_dt).days / 365.25
            ddj_ok = age_at_issue < 21
            sig("dob_age_matches_under21", ddj_ok,
                f"DDJ set but age at issue was {age_at_issue:.0f} ({'under 21' if ddj_ok else 'OVER 21 — inconsistent'})")
        else:
            sig("dob_age_matches_under21", True, "Date parse failed, skipped")
    else:
        sig("dob_age_matches_under21", True, "DDJ not present or DOB missing")

    # SIGNAL 17: Expiry date in future
    exp_val = fields.get("DBA", "")
    exp_dt  = _parse_date(exp_val) if exp_val else None
    if exp_dt:
        dates["expiry"] = exp_dt
    exp_ok = (exp_dt is not None and exp_dt > today) if exp_val else False
    sig("expiry_future", exp_ok,
        f"DBA={exp_dt.strftime('%Y-%m-%d') if exp_dt else repr(exp_val)} {'future' if exp_ok else 'EXPIRED or unparseable'}")

    # SIGNAL 18: NC birthday-linked expiry
    if dob_dt and exp_dt and exp_val and dob_val:
        dob_md = dob_val.strip()[:4]   # MMDD
        exp_md = exp_val.strip()[:4]   # MMDD
        bday_linked = (dob_md == exp_md)
        sig("expiry_birthday_linked", bday_linked,
            f"DOB MMDD={dob_md} vs Expiry MMDD={exp_md} {'match ok' if bday_linked else 'MISMATCH — NC DLs expire on birthday'}")
    else:
        sig("expiry_birthday_linked", True, "Cannot check: missing DOB or expiry")

    # SIGNAL 19: Issue before expiry
    iss_val = fields.get("DBD", "")
    iss_dt  = _parse_date(iss_val) if iss_val else None
    if iss_dt:
        dates["issue"] = iss_dt
    if iss_dt and exp_dt:
        sig("issue_before_expiry", iss_dt < exp_dt,
            f"Issue={iss_dt.date()} Expiry={exp_dt.date()} {'OK' if iss_dt < exp_dt else 'ISSUE AFTER EXPIRY'}")
    else:
        sig("issue_before_expiry", True, "Cannot check: missing issue or expiry date")

    # SIGNAL 20: Issue term reasonable
    if iss_dt and exp_dt:
        term_yrs = (exp_dt - iss_dt).days / 365.25
        term_ok = 4 <= term_yrs <= 9
        sig("issue_term_reasonable", term_ok,
            f"Term {term_yrs:.1f} yrs {'OK' if term_ok else 'UNUSUAL (NC issues 5 or 8 yr terms)'}")
    else:
        sig("issue_term_reasonable", True, "Cannot check: missing dates")

    # SIGNAL 21: ZIP format
    dak = fields.get("DAK", "")
    zip_ok = bool(re.match(r"^\d{9}[\s0]{2}$", dak)) if dak else True
    sig("zip_format", zip_ok,
        f"DAK={repr(dak)} len={len(dak)} {'OK' if zip_ok else 'expected 9 digits + 2 spaces'}")

    # SIGNAL 22: Country code
    dcg = fields.get("DCG", "").strip()
    sig("country_valid", dcg in VALID_COUNTRIES if dcg else True,
        f"DCG={repr(dcg)}")

    # SIGNAL 23: Document discriminator
    dcf = fields.get("DCF", "").strip()
    sig("dcf_present", bool(dcf), f"DCF={repr(dcf)}")

    # SIGNAL 24: DCK format
    dck = fields.get("DCK", "").strip()
    sig("dck_format", len(dck) == 20 if dck else True,
        f"DCK len={len(dck)} {'OK' if len(dck)==20 else 'expected 20 chars'}")

    # SIGNAL 25: DCK prefix matches DAQ
    if dck and daq:
        dck_prefix = dck[:12].lstrip("0")
        daq_clean  = daq.lstrip("0")
        dck_match  = (dck_prefix == daq_clean)
        sig("dck_matches_daq", dck_match,
            f"DCK[0:12]={dck[:12]} vs DAQ={daq} {'match ok' if dck_match else 'MISMATCH — possible data edit'}")
    else:
        sig("dck_matches_daq", True, "DCK or DAQ missing")

    # SIGNAL 26: DCK vendor known
    if dck and len(dck) >= 18:
        vendor = dck[16:18]
        vendor_name = DCK_VENDOR_MAP.get(vendor)
        sig("dck_vendor_known", vendor_name is not None,
            f"Vendor code {repr(vendor)} = {vendor_name or 'UNKNOWN'}")
    else:
        sig("dck_vendor_known", True, "DCK too short or absent")

    # SIGNAL 27: Compliance type
    dda = fields.get("DDA", "").strip()
    sig("compliance_valid", dda in VALID_COMPLIANCE if dda else True,
        f"DDA={repr(dda)}")

    # SIGNAL 28: Truncation flags
    trunc_errs = []
    for t in ("DDE","DDF","DDG"):
        v = fields.get(t, "").strip()
        if v and v not in VALID_TRUNCATION:
            trunc_errs.append(f"{t}={repr(v)}")
    sig("truncation_flags_valid", len(trunc_errs) == 0,
        f"Invalid: {trunc_errs}" if trunc_errs else "All truncation flags valid")

    # SIGNAL 29: DCL race 3-char fixed-width
    dcl = fields.get("DCL", "")
    if dcl:
        dcl_ok = (len(dcl) == 3 and dcl.strip() in VALID_RACE)
        sig("dcl_format", dcl_ok, f"DCL={repr(dcl)} len={len(dcl)}")
    else:
        sig("dcl_format", True, "DCL absent")

    # SIGNAL 30: NC ZN subfile
    has_zn = any(k.startswith("ZN") for k in fields)
    if is_nc:
        sig("zn_subfile_present", has_zn,
            "ZN subfile found ok" if has_zn else "NC barcode MISSING ZN jurisdiction subfile")
    else:
        sig("zn_subfile_present", True, "Non-NC, ZN not required")

    # SIGNAL 31: Organ donor
    ddk = fields.get("DDK", "").strip()
    sig("organ_donor_valid", ddk in VALID_ORGAN_DONOR if ddk else True,
        f"DDK={repr(ddk)}")

    return results, anomalies, dates

# ─────────────────────────────────────────────────────────────
# LAYER 4 — CLASSIFICATION ENGINE
# ─────────────────────────────────────────────────────────────

def classify(signals: list[SignalResult]) -> tuple[str, float, float, str]:
    """
    Weighted scoring classification.
    Returns (verdict, score, confidence, hard_fail_reason).

    Verdict rules:
      - Any hard_fail signal that fails -> "UNAUTHENTIC" immediately
      - score >= 85% of max -> "AUTHENTIC"
      - score 60-84%        -> "INCONCLUSIVE"
      - score < 60%         -> "UNAUTHENTIC"
    """
    hard_fail_reason = ""
    for s in signals:
        if s.is_hard_fail and not s.passed:
            hard_fail_reason = f"{s.signal}: {s.detail}"
            return "UNAUTHENTIC", 0.0, 100.0, hard_fail_reason

    max_score = sum(s.weight for s in signals)
    score     = sum(s.weight for s in signals if s.passed)
    confidence = (score / max_score * 100) if max_score > 0 else 0.0

    if confidence >= 85:
        verdict = "AUTHENTIC"
    elif confidence >= 60:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "UNAUTHENTIC"

    return verdict, score, confidence, hard_fail_reason

# ─────────────────────────────────────────────────────────────
# LAYER 5 — MAIN ANALYSIS ENTRY POINT
# ─────────────────────────────────────────────────────────────

def analyse(raw: str) -> ForensicReport:
    """
    Full forensic analysis pipeline.
    Input: raw barcode string (original bytes from decoder, not pre-escaped).
    Returns: ForensicReport with verdict, confidence, and all signal details.
    """
    report = ForensicReport(scan_time=datetime.utcnow().isoformat() + "Z")

    if not raw or len(raw) < 20:
        report.verdict = "INCONCLUSIVE"
        report.error = "Barcode string too short or empty"
        return report

    # Encoding check on ORIGINAL (pre-unescape) bytes
    report.encoding_mode = detect_encoding_mode(raw)
    report.raw_preview   = repr(raw[:300])

    # Normalise for field parsing only
    normalised = unescape_tilde(raw) if "~" in raw else raw

    parsed = parse_barcode(normalised)
    report.iin             = parsed.get("iin", "")
    report.state_name      = AAMVA_IIN_MAP.get(report.iin, "Unknown")
    report.aamva_ver       = parsed.get("aamva_ver", 0)
    report.juris_ver       = parsed.get("juris_ver", 0)
    report.num_subfiles    = parsed.get("num_subfiles", 0)
    report.dl_subfile_found= parsed.get("dl_subfile_found", False)
    report.offsets_valid   = parsed.get("offsets_valid", False)
    report.subfiles        = [{"id":s["id"],"offset":s["declared_offset"],
                                "length":s["declared_length"],"valid":s["offset_valid"]}
                               for s in parsed.get("subfiles", [])]

    fields = parsed.get("fields", {})
    report.fields = {k: {"val": v, "label": FIELD_LABELS.get(k, "")}
                     for k, v in sorted(fields.items())}

    v_clamped = min(max(report.aamva_ver, 1), 10)
    mandatory = AAMVA_MANDATORY.get(v_clamped, AAMVA_MANDATORY[8])
    report.missing_mandatory = [t for t in mandatory if t not in fields]

    signals, anomalies, dates = run_signals(raw, parsed, fields)
    report.signals   = signals
    report.anomalies = anomalies
    report.parsed_dates = {k: v.isoformat() for k, v in dates.items()}

    verdict, score, confidence, hfr = classify(signals)
    report.verdict          = verdict
    report.score            = round(score, 2)
    report.max_score        = round(sum(s.weight for s in signals), 2)
    report.confidence       = round(confidence, 1)
    report.hard_fail_reason = hfr

    return report

# ─────────────────────────────────────────────────────────────
# IMAGE DECODE HELPERS
# ─────────────────────────────────────────────────────────────

def _ensure_zbar():
    if subprocess.run(["which","zbarimg"], capture_output=True).returncode != 0:
        subprocess.run("apt-get install -y zbar-tools libzbar0 -qq",
                       shell=True, capture_output=True)

def _ensure_pdf417():
    try:
        import pdf417decoder  # noqa
    except ImportError:
        subprocess.run([sys.executable,"-m","pip","install","pdf417decoder","-q"])

def decode_image(path: str) -> Optional[str]:
    import os
    if not os.path.exists(path):
        return None
    _ensure_zbar()
    r = subprocess.run(["zbarimg","--raw","-q",path], capture_output=True)
    if r.returncode == 0 and r.stdout:
        return r.stdout.decode("latin-1")
    # Preprocessing fallback
    try:
        from PIL import Image, ImageEnhance, ImageFilter
        import numpy as np
        img = Image.open(path).convert("L")
        w, h = img.size; scale = max(1, 1200 // w)
        up  = img.resize((w*scale, h*scale), Image.LANCZOS)
        arr = np.array(up)
        for name, proc in [
            ("thresh", Image.fromarray(((arr>arr.mean())*255).astype("uint8"))),
            ("enh",    ImageEnhance.Contrast(img).enhance(3.0).filter(ImageFilter.SHARPEN)),
            ("inv",    Image.fromarray(255-arr)),
        ]:
            p = f"/tmp/aamva_{name}.png"; proc.save(p)
            r2 = subprocess.run(["zbarimg","--raw","-q","--set","pdf417.enable=1",p],
                                 capture_output=True)
            if r2.returncode == 0 and r2.stdout:
                return r2.stdout.decode("latin-1")
    except Exception:
        pass
    # pdf417decoder fallback
    _ensure_pdf417()
    try:
        from pdf417decoder import PDF417Decoder
        from PIL import Image
        dec = PDF417Decoder(Image.open(path))
        if dec.decode() > 0:
            try:    return dec.barcode_data_index_to_string(0)
            except: return dec.barcodes_data[0].decode("latin-1")
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _abbr_to_name(abbr: str) -> str:
    _map = {
        "AL":"Alabama","AK":"Alaska","AZ":"Arizona","AR":"Arkansas","CA":"California",
        "CO":"Colorado","CT":"Connecticut","DC":"DC","DE":"Delaware","FL":"Florida",
        "GA":"Georgia","HI":"Hawaii","ID":"Idaho","IL":"Illinois","IN":"Indiana",
        "IA":"Iowa","KS":"Kansas","KY":"Kentucky","LA":"Louisiana","ME":"Maine",
        "MD":"Maryland","MA":"Massachusetts","MI":"Michigan","MN":"Minnesota",
        "MS":"Mississippi","MO":"Missouri","MT":"Montana","NE":"Nebraska","NV":"Nevada",
        "NH":"New Hampshire","NJ":"New Jersey","NM":"New Mexico","NY":"New York",
        "NC":"North Carolina","ND":"North Dakota","OH":"Ohio","OK":"Oklahoma",
        "OR":"Oregon","PA":"Pennsylvania","RI":"Rhode Island","SC":"South Carolina",
        "SD":"South Dakota","TN":"Tennessee","TX":"Texas","UT":"Utah","VT":"Vermont",
        "VA":"Virginia","WA":"Washington","WV":"West Virginia","WI":"Wisconsin","WY":"Wyoming",
    }
    return _map.get(abbr.upper(), "")
