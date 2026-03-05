"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         PURDUE MODEL OT/IT NETWORK SIMULATION ENGINE                        ║
║         Lean Automation — Industrial Cybersecurity Assessment Tool           ║
║         Scenarios: Normal · High Load · SloppyLemming Attack · Hybrid       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations
import random
import time
import collections
import statistics
import math
import copy
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

class Level(Enum):
    ENTERPRISE      = 5   # L4-5: IT, Email, ERP
    DMZ             = 4   # L3.5: IT/OT Boundary
    INDUSTRIAL      = 3   # L3:   SCADA, Historians, MES
    CONTROL         = 2   # L2:   HMIs, Engineering Workstations
    FIELD_DEVICE    = 1   # L1:   PLCs, RTUs, DCS
    PROCESS         = 0   # L0:   Sensors, Actuators, Physical Process

class PacketType(Enum):
    NORMAL_IT       = auto()   # Email, ERP, business traffic
    SCADA_POLL      = auto()   # SCADA polling OT devices
    HMI_COMMAND     = auto()   # Operator commands to PLCs
    SENSOR_DATA     = auto()   # Sensor telemetry upward
    PATCH_DEPLOY    = auto()   # Patching / software updates
    HISTORIAN       = auto()   # Historian data collection
    # Attack packets
    SPEAR_PHISH     = auto()   # Initial entry vector
    BURROWSHELL     = auto()   # C2 masquerading as Windows Update
    KEYLOGGER_EXFIL = auto()   # Keylogger data exfiltration
    LATERAL_MOVE    = auto()   # East-West pivot attempt
    C2_BEACON       = auto()   # Command & Control heartbeat

ATTACK_PACKETS = {
    PacketType.SPEAR_PHISH,
    PacketType.BURROWSHELL,
    PacketType.KEYLOGGER_EXFIL,
    PacketType.LATERAL_MOVE,
    PacketType.C2_BEACON,
}

LEVEL_NAMES = {
    Level.ENTERPRISE:   "L4-5 Enterprise",
    Level.DMZ:          "L3.5 DMZ",
    Level.INDUSTRIAL:   "L3  Industrial",
    Level.CONTROL:      "L2  Control",
    Level.FIELD_DEVICE: "L1  Field Device",
    Level.PROCESS:      "L0  Process",
}

LEVEL_COLORS = {
    Level.ENTERPRISE:   "#3b82f6",
    Level.DMZ:          "#ef4444",
    Level.INDUSTRIAL:   "#f59e0b",
    Level.CONTROL:      "#f59e0b",
    Level.FIELD_DEVICE: "#10b981",
    Level.PROCESS:      "#10b981",
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Packet:
    id:          int
    ptype:       PacketType
    src_level:   Level
    dst_level:   Level
    src_node:    str
    dst_node:    str
    size_kb:     float          # packet payload size
    timestamp:   float          # simulation tick of creation
    ttl:         int = 8        # time-to-live hops
    is_attack:   bool = False

    def __post_init__(self):
        self.is_attack = self.ptype in ATTACK_PACKETS


@dataclass
class NodeMetrics:
    packets_received:  int   = 0
    packets_sent:      int   = 0
    packets_dropped:   int   = 0
    packets_blocked:   int   = 0
    attack_attempts:   int   = 0
    attack_blocked:    int   = 0
    attack_passed:     int   = 0
    queue_depths:      List  = field(default_factory=list)
    latencies:         List  = field(default_factory=list)
    cpu_loads:         List  = field(default_factory=list)
    bandwidth_used:    List  = field(default_factory=list)


@dataclass
class LinkMetrics:
    packets_forwarded: int   = 0
    bytes_forwarded:   float = 0.0
    congestion_events: int   = 0
    latencies:         List  = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK NODE
# ─────────────────────────────────────────────────────────────────────────────

class NetworkNode:
    """
    Represents a network node at a given Purdue level.
    Each node has a queue, CPU capacity, bandwidth limit, and security policy.
    """

    def __init__(
        self,
        name: str,
        level: Level,
        max_queue:     int   = 200,
        cpu_capacity:  float = 100.0,   # % total
        bandwidth_mbps:float = 100.0,
        base_cpu_load: float = 20.0,    # background load %
    ):
        self.name           = name
        self.level          = level
        self.max_queue      = max_queue
        self.cpu_capacity   = cpu_capacity
        self.bandwidth_mbps = bandwidth_mbps
        self.base_cpu_load  = base_cpu_load

        self.queue: collections.deque = collections.deque()
        self.current_cpu:   float = base_cpu_load
        self.current_bw:    float = 0.0
        self.metrics        = NodeMetrics()
        self.compromised:   bool  = False
        self.compromise_tick: Optional[float] = None

    def enqueue(self, packet: Packet, tick: float) -> bool:
        if len(self.queue) >= self.max_queue:
            self.metrics.packets_dropped += 1
            return False
        self.queue.append((packet, tick))
        self.metrics.packets_received += 1
        return True

    def process_tick(self, tick: float, load_factor: float = 1.0) -> List[Packet]:
        """
        Process queued packets this tick.
        Returns list of packets ready for forwarding.
        """
        # Dynamic CPU load: base + queue pressure + load factor
        queue_pressure = (len(self.queue) / max(self.max_queue, 1)) * 40
        self.current_cpu = min(
            self.cpu_capacity,
            self.base_cpu_load * load_factor + queue_pressure + random.gauss(0, 2)
        )
        self.metrics.cpu_loads.append(self.current_cpu)
        self.metrics.queue_depths.append(len(self.queue))

        # How many packets we can process per tick (CPU-gated)
        available_cpu_pct = max(0, self.cpu_capacity - self.current_cpu)
        proc_slots = max(1, int(available_cpu_pct / 10))

        ready = []
        for _ in range(min(proc_slots, len(self.queue))):
            if self.queue:
                pkt, enqueue_time = self.queue.popleft()
                latency = tick - enqueue_time
                self.metrics.latencies.append(latency)
                self.metrics.packets_sent += 1
                self.current_bw += pkt.size_kb / 1024  # rough BW in MB/tick
                ready.append(pkt)

        bw_pct = (self.current_bw * 8) / self.bandwidth_mbps * 100
        self.metrics.bandwidth_used.append(min(bw_pct, 100))
        self.current_bw = 0.0
        return ready

    def __repr__(self):
        return f"Node({self.name}, {self.level.name}, Q={len(self.queue)}, CPU={self.current_cpu:.1f}%)"


# ─────────────────────────────────────────────────────────────────────────────
# DMZ FIREWALL
# ─────────────────────────────────────────────────────────────────────────────

class DMZFirewall:
    """
    Enforces Purdue Model segmentation at the IT/OT boundary.
    Implements: stateful firewall, AI anomaly detection, Zero Trust checks.
    """

    def __init__(self, ai_enabled: bool = True, strict_mode: bool = True):
        self.ai_enabled     = ai_enabled
        self.strict_mode    = strict_mode
        self.metrics        = NodeMetrics()
        self.blocked_log:   List[Dict] = []
        self.passed_log:    List[Dict] = []

        # Allowed traffic crossing the DMZ (IT→OT direction)
        self.allowed_down: set = {
            PacketType.PATCH_DEPLOY,
            PacketType.HISTORIAN,
            PacketType.SCADA_POLL,
        }
        # Allowed traffic crossing DMZ (OT→IT direction)
        self.allowed_up: set = {
            PacketType.SENSOR_DATA,
            PacketType.HISTORIAN,
        }

        # AI behavioral baseline: tracks packet rates per type
        self._baseline: Dict[PacketType, float] = {}
        self._rate_window: collections.deque = collections.deque(maxlen=20)
        self._anomaly_threshold = 2.5   # std-dev multiplier

    def _update_baseline(self, ptype: PacketType):
        self._rate_window.append(ptype)
        type_counts = collections.Counter(self._rate_window)
        for pt, count in type_counts.items():
            self._baseline[pt] = count / len(self._rate_window)

    def _ai_anomaly_score(self, packet: Packet) -> float:
        """
        Returns anomaly score 0-1. High = suspicious.
        Checks: rate deviation, C2 masquerade patterns, unusual directions.
        """
        if not self.ai_enabled:
            return 0.0

        score = 0.0

        # Attack packets always score high
        if packet.is_attack:
            score += 0.8

        # BurrowShell masquerades as PATCH_DEPLOY — detect via rate anomaly
        if packet.ptype == PacketType.PATCH_DEPLOY:
            expected = self._baseline.get(PacketType.PATCH_DEPLOY, 0.05)
            actual   = collections.Counter(self._rate_window).get(PacketType.PATCH_DEPLOY, 0) / max(len(self._rate_window), 1)
            if expected > 0 and actual > expected * self._anomaly_threshold:
                score += 0.5   # burst of "patch" traffic is suspicious

        # Lateral movement from enterprise trying to reach process level
        if (packet.src_level == Level.ENTERPRISE and
                packet.dst_level in {Level.FIELD_DEVICE, Level.PROCESS}):
            score += 0.7

        return min(score, 1.0)

    def inspect(self, packet: Packet, tick: float) -> Tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        """
        self.metrics.packets_received += 1
        self._update_baseline(packet.ptype)

        going_down = packet.dst_level.value < packet.src_level.value
        going_up   = packet.dst_level.value > packet.src_level.value

        # ── Rule 1: Hard block all known attack packets ──
        if packet.is_attack:
            self.metrics.attack_attempts += 1
            self.metrics.attack_blocked  += 1
            self.metrics.packets_blocked += 1
            self._log_block(packet, tick, "RULE: Known attack packet type")
            return False, "blocked:attack_signature"

        # ── Rule 2: Check allowed direction/type ──
        if going_down and packet.ptype not in self.allowed_down:
            if self.strict_mode:
                self.metrics.packets_blocked += 1
                self._log_block(packet, tick, "RULE: Packet type not permitted IT→OT")
                return False, "blocked:policy_violation_down"

        if going_up and packet.ptype not in self.allowed_up:
            if self.strict_mode:
                self.metrics.packets_blocked += 1
                self._log_block(packet, tick, "RULE: Packet type not permitted OT→IT")
                return False, "blocked:policy_violation_up"

        # ── Rule 3: AI anomaly detection ──
        anomaly = self._ai_anomaly_score(packet)
        if anomaly >= 0.6:
            self.metrics.packets_blocked += 1
            self.metrics.attack_blocked  += 1
            self._log_block(packet, tick, f"AI: Anomaly score {anomaly:.2f}")
            return False, f"blocked:ai_anomaly:{anomaly:.2f}"

        # ── Passed ──
        self.metrics.packets_sent += 1
        self._log_pass(packet, tick)
        return True, "allowed"

    def _log_block(self, p: Packet, tick: float, reason: str):
        self.blocked_log.append({
            "tick": tick, "pkt_id": p.id, "type": p.ptype.name,
            "src": p.src_node, "dst": p.dst_node, "reason": reason
        })

    def _log_pass(self, p: Packet, tick: float):
        self.passed_log.append({
            "tick": tick, "pkt_id": p.id, "type": p.ptype.name,
            "src": p.src_node, "dst": p.dst_node
        })


# ─────────────────────────────────────────────────────────────────────────────
# MICRO-SEGMENTATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class MicroSegmentEngine:
    """
    Enforces East-West traffic controls within same Purdue level.
    Prevents lateral movement (SloppyLemming workcell pivot).
    """

    def __init__(self, enabled: bool = True):
        self.enabled        = enabled
        self.allowed_pairs: set = set()   # (src_node, dst_node) whitelist
        self.metrics        = NodeMetrics()

    def allow_pair(self, src: str, dst: str):
        self.allowed_pairs.add((src, dst))

    def check(self, packet: Packet, tick: float) -> Tuple[bool, str]:
        if not self.enabled:
            return True, "allowed:segmentation_disabled"

        if packet.is_attack and packet.ptype == PacketType.LATERAL_MOVE:
            self.metrics.attack_attempts += 1
            self.metrics.attack_blocked  += 1
            self.metrics.packets_blocked += 1
            return False, "blocked:lateral_movement_detected"

        pair = (packet.src_node, packet.dst_node)
        if pair not in self.allowed_pairs and packet.src_level == packet.dst_level:
            self.metrics.packets_blocked += 1
            return False, "blocked:east_west_not_whitelisted"

        return True, "allowed"


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK ENGINE — SloppyLemming Campaign
# ─────────────────────────────────────────────────────────────────────────────

class SloppyLemmingAttack:
    """
    Models the SloppyLemming kill chain:
    Spear-Phish → PDF Lure → ClickOnce → DLL Sideload
    → BurrowShell C2 → Keylogger → Lateral Movement
    """

    KILL_CHAIN = [
        (PacketType.SPEAR_PHISH,     "Initial spear-phishing email delivered"),
        (PacketType.BURROWSHELL,     "BurrowShell backdoor established (masq. as Windows Update)"),
        (PacketType.C2_BEACON,       "C2 beacon to 112 proxy domains"),
        (PacketType.KEYLOGGER_EXFIL, "Rust-based keylogger exfiltrating credentials"),
        (PacketType.LATERAL_MOVE,    "Lateral movement attempt toward OT network"),
        (PacketType.LATERAL_MOVE,    "Second pivot attempt — targeting SCADA historian"),
        (PacketType.LATERAL_MOVE,    "Deep pivot attempt — targeting PLC Engineering WS"),
    ]

    def __init__(self, start_tick: int, intensity: float = 1.0):
        self.start_tick     = start_tick
        self.intensity      = intensity  # 0-1 attack aggression
        self.stage          = 0
        self.active         = False
        self.completed      = False
        self.stage_log:     List[Dict] = []
        self._pkt_counter   = 0

    def tick(self, current_tick: float, nodes: Dict[str, NetworkNode]) -> List[Packet]:
        """Generate attack packets for this tick."""
        packets = []

        if current_tick < self.start_tick:
            return packets

        self.active = True

        if self.stage >= len(self.KILL_CHAIN):
            self.completed = True
            return packets

        ptype, description = self.KILL_CHAIN[self.stage]

        # Generate burst of attack packets scaled by intensity
        n_pkts = max(1, int(self.intensity * random.randint(1, 4)))
        for _ in range(n_pkts):
            self._pkt_counter += 1
            pkt = Packet(
                id         = 90000 + self._pkt_counter,
                ptype      = ptype,
                src_level  = Level.ENTERPRISE,
                dst_level  = Level.INDUSTRIAL if self.stage >= 4 else Level.ENTERPRISE,
                src_node   = "EXT_ATTACKER",
                dst_node   = random.choice(list(nodes.keys())),
                size_kb    = random.uniform(1, 50),
                timestamp  = current_tick,
            )
            packets.append(pkt)

        # Advance stage every few ticks
        if random.random() < 0.15 * self.intensity:
            if self.stage < len(self.KILL_CHAIN) - 1:
                self.stage_log.append({
                    "tick": current_tick,
                    "stage": self.stage,
                    "desc": description
                })
                self.stage += 1

        return packets


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    name:             str
    description:      str
    duration_ticks:   int
    load_factor:      float         # 1.0 = normal, 2.0 = double load
    load_profile:     str           # 'constant' | 'ramp' | 'spike' | 'wave'
    attack_enabled:   bool = False
    attack_start:     int  = 50
    attack_intensity: float= 0.8
    dmz_ai_enabled:   bool = True
    micro_seg_enabled:bool = True
    dmz_strict_mode:  bool = True
    extra_notes:      str  = ""


SCENARIOS = {
    "normal": Scenario(
        name             = "Normal Operations",
        description      = "Baseline steady-state OT/IT traffic. No attacks. Standard load.",
        duration_ticks   = 150,
        load_factor      = 1.0,
        load_profile     = "constant",
        attack_enabled   = False,
        extra_notes      = "Reference baseline for all comparisons."
    ),
    "high_load": Scenario(
        name             = "High Load — Production Surge",
        description      = "Simulates a production surge: 3x normal traffic volume with spike bursts.",
        duration_ticks   = 150,
        load_factor      = 3.0,
        load_profile     = "spike",
        attack_enabled   = False,
        extra_notes      = "Tests queue depth, CPU saturation, and latency degradation under load."
    ),
    "attack_defended": Scenario(
        name             = "SloppyLemming Attack — Defended (AI + Segmentation ON)",
        description      = "Full SloppyLemming kill chain with DMZ AI and micro-segmentation active.",
        duration_ticks   = 200,
        load_factor      = 1.0,
        load_profile     = "constant",
        attack_enabled   = True,
        attack_start     = 40,
        attack_intensity = 0.9,
        dmz_ai_enabled   = True,
        micro_seg_enabled= True,
        dmz_strict_mode  = True,
        extra_notes      = "Demonstrates Lean Automation defended posture."
    ),
    "attack_undefended": Scenario(
        name             = "SloppyLemming Attack — Undefended (No AI, No Segmentation)",
        description      = "Same attack with AI disabled and flat network (no micro-segmentation).",
        duration_ticks   = 200,
        load_factor      = 1.0,
        load_profile     = "constant",
        attack_enabled   = True,
        attack_start     = 40,
        attack_intensity = 0.9,
        dmz_ai_enabled   = False,
        micro_seg_enabled= False,
        dmz_strict_mode  = False,
        extra_notes      = "Demonstrates vulnerability of traditional flat OT networks."
    ),
    "hybrid": Scenario(
        name             = "Hybrid — Attack Under High Load",
        description      = "SloppyLemming attack during production surge. Worst-case scenario.",
        duration_ticks   = 200,
        load_factor      = 2.5,
        load_profile     = "wave",
        attack_enabled   = True,
        attack_start     = 60,
        attack_intensity = 1.0,
        dmz_ai_enabled   = True,
        micro_seg_enabled= True,
        dmz_strict_mode  = True,
        extra_notes      = "Tests resilience when defenses are stressed by legitimate traffic."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# TRAFFIC GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class TrafficGenerator:
    """
    Generates realistic OT/IT traffic across Purdue levels.
    """

    # (ptype, src_level, dst_level, rate_per_tick, size_kb_range)
    TRAFFIC_TEMPLATES = [
        (PacketType.NORMAL_IT,    Level.ENTERPRISE,   Level.ENTERPRISE,   6,  (10,  500)),
        (PacketType.SCADA_POLL,   Level.INDUSTRIAL,   Level.FIELD_DEVICE, 4,  (1,   10)),
        (PacketType.SCADA_POLL,   Level.INDUSTRIAL,   Level.CONTROL,      3,  (1,   8)),
        (PacketType.HMI_COMMAND,  Level.CONTROL,      Level.FIELD_DEVICE, 2,  (1,   5)),
        (PacketType.SENSOR_DATA,  Level.PROCESS,      Level.FIELD_DEVICE, 5,  (0.5, 5)),
        (PacketType.SENSOR_DATA,  Level.FIELD_DEVICE, Level.INDUSTRIAL,   4,  (0.5, 5)),
        (PacketType.HISTORIAN,    Level.INDUSTRIAL,   Level.DMZ,          2,  (50,  500)),
        (PacketType.PATCH_DEPLOY, Level.DMZ,          Level.INDUSTRIAL,   1,  (100, 2000)),
    ]

    def __init__(self, nodes: Dict[str, NetworkNode]):
        self.nodes    = nodes
        self._counter = 0
        self._nodes_by_level: Dict[Level, List[str]] = collections.defaultdict(list)
        for name, node in nodes.items():
            self._nodes_by_level[node.level].append(name)

    def _pick_node(self, level: Level) -> str:
        candidates = self._nodes_by_level.get(level, [])
        return random.choice(candidates) if candidates else "UNKNOWN"

    def generate(self, tick: float, load_factor: float, load_profile: str) -> List[Packet]:
        packets = []

        # Dynamic load factor
        effective_load = self._effective_load(tick, load_factor, load_profile)

        for ptype, src_lvl, dst_lvl, base_rate, (sz_lo, sz_hi) in self.TRAFFIC_TEMPLATES:
            n = max(0, int(base_rate * effective_load * random.uniform(0.6, 1.4)))
            for _ in range(n):
                self._counter += 1
                pkt = Packet(
                    id        = self._counter,
                    ptype     = ptype,
                    src_level = src_lvl,
                    dst_level = dst_lvl,
                    src_node  = self._pick_node(src_lvl),
                    dst_node  = self._pick_node(dst_lvl),
                    size_kb   = random.uniform(sz_lo, sz_hi),
                    timestamp = tick,
                )
                packets.append(pkt)
        return packets

    @staticmethod
    def _effective_load(tick: float, base: float, profile: str) -> float:
        if profile == "constant":
            return base
        elif profile == "ramp":
            return base * (0.5 + 0.5 * min(tick / 100, 1.0))
        elif profile == "spike":
            # Spikes every 30 ticks
            spike = 3.0 if (int(tick) % 30) < 8 else 1.0
            return base * spike * random.uniform(0.8, 1.2)
        elif profile == "wave":
            wave = 0.5 + 0.5 * math.sin(tick * math.pi / 25)
            return base * (0.5 + wave)
        return base


# ─────────────────────────────────────────────────────────────────────────────
# RESULT CONTAINER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SimulationResult:
    scenario:       Scenario
    duration:       float           # real time seconds
    ticks:          int

    # Per-node metrics
    node_metrics:   Dict[str, NodeMetrics]
    dmz_metrics:    NodeMetrics
    seg_metrics:    NodeMetrics

    # Time series
    throughput_ts:  List[float]     # packets/tick
    latency_ts:     List[float]     # avg latency/tick
    cpu_ts:         Dict[str, List[float]]
    queue_ts:       Dict[str, List[float]]
    attack_ts:      List[int]       # attack pkts/tick
    blocked_ts:     List[int]       # blocked pkts/tick

    # Attack progress
    attack_log:     List[Dict]
    breach_occurred: bool
    breach_tick:    Optional[float]
    kill_chain_stages_reached: int

    # Aggregate
    total_packets:       int
    total_attack_pkts:   int
    total_blocked:       int
    total_dropped:       int
    avg_latency_ms:      float
    avg_cpu_pct:         float
    dmz_block_rate:      float
    breach_rate:         float      # % of attacks that passed DMZ


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SIMULATOR
# ─────────────────────────────────────────────────────────────────────────────

class PurdueSimulator:
    """
    Discrete-event simulator for the Purdue Model OT/IT network.
    """

    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self._build_topology()

    def _build_topology(self):
        """Construct a representative Purdue-model network topology."""

        def add(name, level, **kw):
            self.nodes[name] = NetworkNode(name, level, **kw)

        # L4-5 Enterprise
        add("CORP_EMAIL",     Level.ENTERPRISE,   max_queue=300, cpu_capacity=100, bandwidth_mbps=1000, base_cpu_load=25)
        add("ERP_SERVER",     Level.ENTERPRISE,   max_queue=300, cpu_capacity=100, bandwidth_mbps=1000, base_cpu_load=30)
        add("WORKSTATION_A",  Level.ENTERPRISE,   max_queue=100, cpu_capacity=80,  bandwidth_mbps=100,  base_cpu_load=35)
        add("WORKSTATION_B",  Level.ENTERPRISE,   max_queue=100, cpu_capacity=80,  bandwidth_mbps=100,  base_cpu_load=30)

        # L3.5 DMZ
        add("HISTORIAN_DMZ",  Level.DMZ,          max_queue=150, cpu_capacity=90,  bandwidth_mbps=500,  base_cpu_load=20)
        add("PATCH_SERVER",   Level.DMZ,          max_queue=100, cpu_capacity=80,  bandwidth_mbps=200,  base_cpu_load=15)
        add("JUMP_HOST",      Level.DMZ,          max_queue=80,  cpu_capacity=70,  bandwidth_mbps=200,  base_cpu_load=10)

        # L3 Industrial
        add("SCADA_SERVER",   Level.INDUSTRIAL,   max_queue=200, cpu_capacity=90,  bandwidth_mbps=500,  base_cpu_load=40)
        add("MES_SERVER",     Level.INDUSTRIAL,   max_queue=150, cpu_capacity=85,  bandwidth_mbps=500,  base_cpu_load=35)
        add("OT_HISTORIAN",   Level.INDUSTRIAL,   max_queue=200, cpu_capacity=80,  bandwidth_mbps=500,  base_cpu_load=30)

        # L2 Control
        add("HMI_LINE_A",     Level.CONTROL,      max_queue=100, cpu_capacity=70,  bandwidth_mbps=100,  base_cpu_load=30)
        add("HMI_LINE_B",     Level.CONTROL,      max_queue=100, cpu_capacity=70,  bandwidth_mbps=100,  base_cpu_load=28)
        add("ENG_WS",         Level.CONTROL,      max_queue=80,  cpu_capacity=75,  bandwidth_mbps=100,  base_cpu_load=35)

        # L1 Field Device
        add("PLC_WELD",       Level.FIELD_DEVICE, max_queue=60,  cpu_capacity=60,  bandwidth_mbps=10,   base_cpu_load=50)
        add("PLC_PAINT",      Level.FIELD_DEVICE, max_queue=60,  cpu_capacity=60,  bandwidth_mbps=10,   base_cpu_load=48)
        add("RTU_FURNACE",    Level.FIELD_DEVICE, max_queue=50,  cpu_capacity=55,  bandwidth_mbps=10,   base_cpu_load=55)
        add("DCS_REACTOR",    Level.FIELD_DEVICE, max_queue=50,  cpu_capacity=60,  bandwidth_mbps=10,   base_cpu_load=52)

        # L0 Process
        add("SENSOR_TEMP",    Level.PROCESS,      max_queue=40,  cpu_capacity=40,  bandwidth_mbps=1,    base_cpu_load=60)
        add("SENSOR_PRESS",   Level.PROCESS,      max_queue=40,  cpu_capacity=40,  bandwidth_mbps=1,    base_cpu_load=58)
        add("ACTUATOR_VALVE", Level.PROCESS,      max_queue=30,  cpu_capacity=35,  bandwidth_mbps=1,    base_cpu_load=65)
        add("SAFETY_SIS",     Level.PROCESS,      max_queue=30,  cpu_capacity=50,  bandwidth_mbps=1,    base_cpu_load=70)

    def run(self, scenario: Scenario, verbose: bool = True) -> SimulationResult:
        """Execute the simulation for a given scenario."""

        print(f"\n{'═'*72}")
        print(f"  SCENARIO: {scenario.name}")
        print(f"  {scenario.description}")
        print(f"{'═'*72}")

        # Reset nodes
        for node in self.nodes.values():
            node.queue.clear()
            node.metrics = NodeMetrics()
            node.compromised = False
            node.compromise_tick = None

        # Build components
        dmz    = DMZFirewall(ai_enabled=scenario.dmz_ai_enabled,
                             strict_mode=scenario.dmz_strict_mode)
        seg    = MicroSegmentEngine(enabled=scenario.micro_seg_enabled)
        tgen   = TrafficGenerator(self.nodes)
        attack = (SloppyLemmingAttack(scenario.attack_start, scenario.attack_intensity)
                  if scenario.attack_enabled else None)

        # Whitelist legitimate East-West pairs
        seg.allow_pair("HMI_LINE_A", "HMI_LINE_B")
        seg.allow_pair("SCADA_SERVER", "OT_HISTORIAN")
        seg.allow_pair("PLC_WELD", "PLC_PAINT")

        # Time-series collectors
        throughput_ts, latency_ts = [], []
        attack_ts,     blocked_ts = [], []
        cpu_ts   = {n: [] for n in self.nodes}
        queue_ts = {n: [] for n in self.nodes}

        breach_occurred = False
        breach_tick     = None
        attack_log      = []
        total_attack    = 0
        total_blocked   = 0
        total_dropped   = 0
        total_packets   = 0

        start_wall = time.perf_counter()

        for tick in range(scenario.duration_ticks):
            tick_pkts_sent   = 0
            tick_attack_pkts = 0
            tick_blocked     = 0
            tick_latencies   = []

            # ── Generate legitimate traffic ──
            legit_packets = tgen.generate(tick, scenario.load_factor, scenario.load_profile)

            # ── Generate attack traffic ──
            attack_packets = attack.tick(tick, self.nodes) if attack else []

            all_packets = legit_packets + attack_packets

            for pkt in all_packets:
                total_packets += 1
                if pkt.is_attack:
                    tick_attack_pkts += 1
                    total_attack     += 1

                # ── DMZ Inspection (packets crossing L3.5) ──
                crosses_dmz = (
                    (pkt.src_level.value >= Level.DMZ.value and pkt.dst_level.value < Level.DMZ.value) or
                    (pkt.src_level.value < Level.DMZ.value  and pkt.dst_level.value >= Level.DMZ.value)
                )

                if crosses_dmz:
                    allowed, reason = dmz.inspect(pkt, tick)
                    if not allowed:
                        tick_blocked += 1
                        total_blocked += 1
                        continue

                # ── Micro-segmentation East-West check ──
                seg_ok, seg_reason = seg.check(pkt, tick)
                if not seg_ok:
                    tick_blocked += 1
                    total_blocked += 1
                    continue

                # ── Breach detection: attack pkt reached OT zone ──
                if pkt.is_attack and pkt.dst_level.value <= Level.INDUSTRIAL.value:
                    if not breach_occurred:
                        breach_occurred = True
                        breach_tick     = tick
                    # Mark node compromised
                    dst = pkt.dst_node
                    if dst in self.nodes:
                        self.nodes[dst].compromised      = True
                        self.nodes[dst].compromise_tick  = tick

                # ── Route packet to destination node ──
                dst_name = pkt.dst_node
                if dst_name in self.nodes:
                    dropped = not self.nodes[dst_name].enqueue(pkt, tick)
                    if dropped:
                        total_dropped += 1

            # ── Process each node this tick ──
            for name, node in self.nodes.items():
                ready = node.process_tick(tick, scenario.load_factor)
                tick_pkts_sent += len(ready)
                if node.metrics.latencies:
                    tick_latencies.extend(node.metrics.latencies[-len(ready):])
                cpu_ts[name].append(node.current_cpu)
                queue_ts[name].append(len(node.queue))

            # ── Collect attack stage log ──
            if attack and attack.stage_log:
                new_events = [e for e in attack.stage_log if e not in attack_log]
                attack_log.extend(new_events)

            # ── Time series ──
            throughput_ts.append(tick_pkts_sent)
            latency_ts.append(statistics.mean(tick_latencies) if tick_latencies else 0)
            attack_ts.append(tick_attack_pkts)
            blocked_ts.append(tick_blocked)

            # Progress
            if verbose and tick % 25 == 0:
                avg_cpu = statistics.mean(
                    n.current_cpu for n in self.nodes.values()
                )
                print(f"  [T={tick:>4}]  pkts/tick={tick_pkts_sent:>4}  "
                      f"attack={tick_attack_pkts:>3}  blocked={tick_blocked:>3}  "
                      f"avg_cpu={avg_cpu:>5.1f}%  "
                      f"breach={'YES ⚠' if breach_occurred else 'no'}")

        wall_time = time.perf_counter() - start_wall

        # ── Aggregate statistics ──
        all_latencies = [l for l in latency_ts if l > 0]
        all_cpus = []
        for lst in cpu_ts.values():
            all_cpus.extend(lst)

        dmz_total   = dmz.metrics.packets_received
        dmz_blocked = dmz.metrics.packets_blocked
        dmz_block_rate = dmz_blocked / max(dmz_total, 1)

        breach_rate = (dmz.metrics.attack_passed if hasattr(dmz.metrics, 'attack_passed') else 0)
        breach_rate_pct = breach_rate / max(total_attack, 1)

        result = SimulationResult(
            scenario        = scenario,
            duration        = wall_time,
            ticks           = scenario.duration_ticks,
            node_metrics    = {n: copy.deepcopy(node.metrics) for n, node in self.nodes.items()},
            dmz_metrics     = dmz.metrics,
            seg_metrics     = seg.metrics,
            throughput_ts   = throughput_ts,
            latency_ts      = latency_ts,
            cpu_ts          = cpu_ts,
            queue_ts        = queue_ts,
            attack_ts       = attack_ts,
            blocked_ts      = blocked_ts,
            attack_log      = attack_log,
            breach_occurred = breach_occurred,
            breach_tick     = breach_tick,
            kill_chain_stages_reached = attack.stage if attack else 0,
            total_packets   = total_packets,
            total_attack_pkts = total_attack,
            total_blocked   = total_blocked,
            total_dropped   = total_dropped,
            avg_latency_ms  = statistics.mean(all_latencies) * 10 if all_latencies else 0,
            avg_cpu_pct     = statistics.mean(all_cpus) if all_cpus else 0,
            dmz_block_rate  = dmz_block_rate,
            breach_rate     = breach_rate_pct,
        )

        self._print_summary(result)
        return result

    def _print_summary(self, r: SimulationResult):
        print(f"\n  {'─'*64}")
        print(f"  SIMULATION COMPLETE in {r.duration:.2f}s")
        print(f"  {'─'*64}")
        print(f"  Total Packets Generated : {r.total_packets:>8,}")
        print(f"  Attack Packets          : {r.total_attack_pkts:>8,}")
        print(f"  Total Blocked           : {r.total_blocked:>8,}")
        print(f"  Total Dropped (overload): {r.total_dropped:>8,}")
        print(f"  Avg Network Latency     : {r.avg_latency_ms:>8.2f} ms")
        print(f"  Avg CPU Load            : {r.avg_cpu_pct:>8.1f} %")
        print(f"  DMZ Block Rate          : {r.dmz_block_rate:>8.1%}")
        print(f"  OT Breach Occurred      : {'⚠  YES — tick ' + str(r.breach_tick) if r.breach_occurred else '✓  No breach'}")
        if r.attack_log:
            print(f"\n  KILL CHAIN STAGES OBSERVED:")
            for ev in r.attack_log:
                print(f"    T={ev['tick']:>4} | Stage {ev['stage']+1} | {ev['desc']}")
        print()
