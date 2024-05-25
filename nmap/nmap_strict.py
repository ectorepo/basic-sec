from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class AttrBool(Enum):
    TRUE = "true"
    FALSE = "false"


class AttrType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"


@dataclass
class Cpe:
    class Meta:
        name = "cpe"

    value: str = field(
        default="",
        metadata={
            "required": True,
        }
    )


@dataclass
class Debugging:
    class Meta:
        name = "debugging"

    level: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Distance:
    class Meta:
        name = "distance"

    value: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Elem:
    class Meta:
        name = "elem"

    key: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    content: List[object] = field(
        default_factory=list,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        }
    )


class FinishedExit(Enum):
    ERROR = "error"
    SUCCESS = "success"


@dataclass
class Hop:
    class Meta:
        name = "hop"

    ttl: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    rtt: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    ipaddr: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    host: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


class HostStates(Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class HostnameTypes(Enum):
    USER = "user"
    PTR = "PTR"


@dataclass
class Hosts:
    class Meta:
        name = "hosts"

    up: str = field(
        default="0",
        metadata={
            "type": "Attribute",
        }
    )
    down: str = field(
        default="0",
        metadata={
            "type": "Attribute",
        }
    )
    total: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Ipidsequence:
    class Meta:
        name = "ipidsequence"

    class_value: Optional[object] = field(
        default=None,
        metadata={
            "name": "class",
            "type": "Attribute",
            "required": True,
        }
    )
    values: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


class NmaprunScanner(Enum):
    NMAP = "nmap"


@dataclass
class Osclass:
    class Meta:
        name = "osclass"

    cpe: List[str] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    vendor: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    osgen: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    type_value: Optional[object] = field(
        default=None,
        metadata={
            "name": "type",
            "type": "Attribute",
        }
    )
    accuracy: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    osfamily: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Osfingerprint:
    class Meta:
        name = "osfingerprint"

    fingerprint: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


class OutputType(Enum):
    INTERACTIVE = "interactive"


@dataclass
class Owner:
    class Meta:
        name = "owner"

    name: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


class PortProtocols(Enum):
    IP = "ip"
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class ScanTypes(Enum):
    SYN = "syn"
    ACK = "ack"
    BOUNCE = "bounce"
    CONNECT = "connect"
    NULL = "null"
    XMAS = "xmas"
    WINDOW = "window"
    MAIMON = "maimon"
    FIN = "fin"
    UDP = "udp"
    SCTPINIT = "sctpinit"
    SCTPCOOKIEECHO = "sctpcookieecho"
    IPPROTO = "ipproto"


class ServiceConfs(Enum):
    VALUE_0 = "0"
    VALUE_1 = "1"
    VALUE_2 = "2"
    VALUE_3 = "3"
    VALUE_4 = "4"
    VALUE_5 = "5"
    VALUE_6 = "6"
    VALUE_7 = "7"
    VALUE_8 = "8"
    VALUE_9 = "9"
    VALUE_10 = "10"


class ServiceMethod(Enum):
    TABLE = "table"
    PROBED = "probed"


class ServiceProto(Enum):
    RPC = "rpc"


class ServiceTunnel(Enum):
    SSL = "ssl"


@dataclass
class Smurf:
    class Meta:
        name = "smurf"

    responses: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class State:
    class Meta:
        name = "state"

    state: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    reason: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    reason_ttl: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    reason_ip: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


class TargetReason(Enum):
    INVALID = "invalid"


class TargetStatus(Enum):
    SKIPPED = "skipped"


@dataclass
class Taskbegin:
    class Meta:
        name = "taskbegin"

    task: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    time: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    extrainfo: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Taskend:
    class Meta:
        name = "taskend"

    task: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    time: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    extrainfo: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Taskprogress:
    class Meta:
        name = "taskprogress"

    task: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    time: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    percent: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    remaining: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    etc: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Tcpsequence:
    class Meta:
        name = "tcpsequence"

    index: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    difficulty: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    values: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Tcptssequence:
    class Meta:
        name = "tcptssequence"

    class_value: Optional[object] = field(
        default=None,
        metadata={
            "name": "class",
            "type": "Attribute",
            "required": True,
        }
    )
    values: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Times:
    class Meta:
        name = "times"

    srtt: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    rttvar: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    to: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Uptime:
    class Meta:
        name = "uptime"

    seconds: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    lastboot: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Verbose:
    class Meta:
        name = "verbose"

    level: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Address:
    class Meta:
        name = "address"

    addr: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    addrtype: AttrType = field(
        default=AttrType.IPV4,
        metadata={
            "type": "Attribute",
        }
    )
    vendor: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Extrareasons:
    class Meta:
        name = "extrareasons"

    reason: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    count: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    proto: Optional[PortProtocols] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    ports: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Finished:
    class Meta:
        name = "finished"

    time: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    timestr: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    elapsed: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    summary: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    exit: Optional[FinishedExit] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    errormsg: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Hostname:
    class Meta:
        name = "hostname"

    name: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    type_value: Optional[HostnameTypes] = field(
        default=None,
        metadata={
            "name": "type",
            "type": "Attribute",
        }
    )


@dataclass
class Osmatch:
    class Meta:
        name = "osmatch"

    osclass: List[Osclass] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    name: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    accuracy: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    line: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Output:
    class Meta:
        name = "output"

    type_value: Optional[OutputType] = field(
        default=None,
        metadata={
            "name": "type",
            "type": "Attribute",
        }
    )
    content: List[object] = field(
        default_factory=list,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        }
    )


@dataclass
class Portused:
    class Meta:
        name = "portused"

    state: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    proto: Optional[PortProtocols] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    portid: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Scaninfo:
    class Meta:
        name = "scaninfo"

    type_value: Optional[ScanTypes] = field(
        default=None,
        metadata={
            "name": "type",
            "type": "Attribute",
            "required": True,
        }
    )
    scanflags: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    protocol: Optional[PortProtocols] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    numservices: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    services: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Service:
    class Meta:
        name = "service"

    cpe: List[str] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    name: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    conf: Optional[ServiceConfs] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    method: Optional[ServiceMethod] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    version: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    product: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    extrainfo: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    tunnel: Optional[ServiceTunnel] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    proto: Optional[ServiceProto] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    rpcnum: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    lowver: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    highver: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    hostname: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    ostype: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    devicetype: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    servicefp: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Status:
    class Meta:
        name = "status"

    state: Optional[HostStates] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    reason: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    reason_ttl: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Table:
    class Meta:
        name = "table"

    table: List["Table"] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    elem: List[Elem] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    key: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Target:
    class Meta:
        name = "target"

    specification: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    status: Optional[TargetStatus] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    reason: Optional[TargetReason] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Trace:
    class Meta:
        name = "trace"

    hop: List[Hop] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    proto: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    port: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Extraports:
    class Meta:
        name = "extraports"

    extrareasons: List[Extrareasons] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    state: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    count: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Hostnames:
    class Meta:
        name = "hostnames"

    hostname: List[Hostname] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Os:
    class Meta:
        name = "os"

    portused: List[Portused] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    osmatch: List[Osmatch] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    osfingerprint: List[Osfingerprint] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Runstats:
    class Meta:
        name = "runstats"

    finished: Optional[Finished] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    hosts: Optional[Hosts] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )


@dataclass
class Script:
    class Meta:
        name = "script"

    id: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    output: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    content: List[object] = field(
        default_factory=list,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
            "choices": (
                {
                    "name": "table",
                    "type": Table,
                },
                {
                    "name": "elem",
                    "type": Elem,
                },
            ),
        }
    )


@dataclass
class Hosthint:
    class Meta:
        name = "hosthint"

    status: Optional[Status] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    address: List[Address] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "min_occurs": 1,
        }
    )
    hostnames: Optional[Hostnames] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Hostscript:
    class Meta:
        name = "hostscript"

    script: List[Script] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "min_occurs": 1,
        }
    )


@dataclass
class Port:
    class Meta:
        name = "port"

    state: Optional[State] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    owner: Optional[Owner] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    service: Optional[Service] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    script: List[Script] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    protocol: Optional[PortProtocols] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    portid: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )


@dataclass
class Postscript:
    class Meta:
        name = "postscript"

    script: List[Script] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "min_occurs": 1,
        }
    )


@dataclass
class Prescript:
    class Meta:
        name = "prescript"

    script: List[Script] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "min_occurs": 1,
        }
    )


@dataclass
class Ports:
    class Meta:
        name = "ports"

    extraports: List[Extraports] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    port: List[Port] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Host:
    class Meta:
        name = "host"

    status: Optional[Status] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    address: List[Address] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "min_occurs": 1,
            "sequence": 1,
        }
    )
    hostnames: List[Hostnames] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    smurf: List[Smurf] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    ports: List[Ports] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    os: List[Os] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    distance: List[Distance] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    uptime: List[Uptime] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    tcpsequence: List[Tcpsequence] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    ipidsequence: List[Ipidsequence] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    tcptssequence: List[Tcptssequence] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    hostscript: List[Hostscript] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    trace: List[Trace] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    times: Optional[Times] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    starttime: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    endtime: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    timedout: Optional[AttrBool] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    comment: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Nmaprun:
    class Meta:
        name = "nmaprun"

    scaninfo: List[Scaninfo] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    verbose: Optional[Verbose] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    debugging: Optional[Debugging] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    target: List[Target] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    taskbegin: List[Taskbegin] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    taskprogress: List[Taskprogress] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    taskend: List[Taskend] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    hosthint: List[Hosthint] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    prescript: List[Prescript] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    postscript: List[Postscript] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    host: List[Host] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    output: List[Output] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )
    runstats: Optional[Runstats] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        }
    )
    scanner: Optional[NmaprunScanner] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    args: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    start: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    startstr: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    version: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
    profile_name: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    xmloutputversion: Optional[object] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        }
    )
