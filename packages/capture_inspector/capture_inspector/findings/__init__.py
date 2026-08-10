"""Finding modules for the analyzer.

Each submodule owns one problem domain (dns, roaming, network/MTU, access type,
latency, interception, proxy/PAC, HAR). `analyze.py` imports the finding
functions from here and only orchestrates.
"""
from .base import (
    _is_private_ip, _is_loopback_ip, _flow_label, _pctl, _fmt_clock,
)
from .dns import _dns_findings, _is_local_dns_name, _swg_proxy_region_findings
from .roaming import (
    _roaming_findings, _roaming_report_findings, _ingress_health_findings,
)
from .network import (
    _detect_duplicate_capture, _duplicate_capture_findings,
    _suppress_dup_retransmission_findings, _icmp_pmtud_findings, _client_syn_mss,
    _detect_segmentation_offload, _segmentation_offload_findings,
    _suppress_offload_reordering_findings,
    _mss_clamp_findings, _sa_tunnel_mtu_findings, _network_health_findings,
    _asymmetric_routing_findings,
)
from .quality import _network_quality_findings
from .access import _private_access_findings, _internal_traffic_findings
from .latency import _latency_findings_har, _latency_findings_pcap, _geo_egress_latency_findings
from .bottleneck import _bottleneck_findings
from .steering import _steering_coverage_findings
from .interception import _ja3s_findings, _local_interception_findings
from .proxy_pac import _pac_wpad_findings
from .har_findings import (
    _har_findings, _block_finding, _parse_via_nodes, _har_proxy_findings,
)

__all__ = [
    "_is_private_ip", "_is_loopback_ip", "_flow_label", "_pctl", "_fmt_clock",
    "_dns_findings", "_is_local_dns_name", "_swg_proxy_region_findings",
    "_roaming_findings", "_roaming_report_findings", "_ingress_health_findings",
    "_detect_duplicate_capture", "_duplicate_capture_findings",
    "_suppress_dup_retransmission_findings", "_icmp_pmtud_findings", "_client_syn_mss",
    "_detect_segmentation_offload", "_segmentation_offload_findings",
    "_suppress_offload_reordering_findings",
    "_mss_clamp_findings", "_sa_tunnel_mtu_findings", "_network_health_findings",
    "_asymmetric_routing_findings",
    "_network_quality_findings",
    "_private_access_findings", "_internal_traffic_findings",
    "_latency_findings_har", "_latency_findings_pcap", "_geo_egress_latency_findings",
    "_bottleneck_findings",
    "_steering_coverage_findings",
    "_ja3s_findings", "_local_interception_findings",
    "_pac_wpad_findings",
    "_har_findings", "_block_finding", "_parse_via_nodes", "_har_proxy_findings",
]
