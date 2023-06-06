
feature_groups = ["broadcom"]

feature_names = [
    "drivshell",
    "confirm-reboot",
    "port-group",
    "bcmcmd",
    "system-status",
    "system-status-core",
    "intf-range",
    "vlan-range",
    "warm-reboot",
    "arp-clear-nowait",
    "strom-control",
    "dpb",
    "intf-alias",
    "klish",
    "radius",
    "ztp",
    "span-mirror-session",
    "crm-all-families",
    "interface-mtu",
    "threshold",
    "rest",
    "bgp-neighbotship-performance",
    "prevent-delete-vlans-with-members",
    "routing-mode-separated-by-default",
    "config-acl-table-delete-command",
    "config-acl-rule-delete-command",
    "crm-config-clear-command",
    "config-profiles-get-factory-command",
    "certgen-command",
    "show-interfaces-counters-clear-command",
    "show-interfaces-counters-interface-command",
    "show-interfaces-counters-detailed-command",
    "sonic-clear-logging-command",
    "show-mac-count-command",
    "sonic-clear-fdb-type-command",
    "config-mac-add-command",
    "config-mac-aging_time-command",
    "show-mac-aging_time-command",
    "config-ipv6-command",
    "config-loopback-add-command",
    "show-bgp-summary-click-command",
    "show-vrf-verbose-command",
    "vrf-needed-for-unbind",
    "show-kdump-status-command",
    "show-mac-aging-time-command",
    "config_mirror_session_add_erspan",
    "config_mirror_session_add_span",
    "config_mirror_session_add_type",
    "config_static_portchannel",
    "config_max_route_scale",
    "sai-removes-vlan-1",
    "nat-default-enabled",
    "sflow-default-enabled",
    "ip_vrf_exec_mgmt_ntpstat",
    "remove_qos_profile",
    "swss-copp-config",
    "scapy-lldp-default-enable",
    "tech-support-port-status-fail",
    "tech-support-function",
    "tech-support-testcase",
    "show-tech-support-since",
    "flex-dpb",
    "std-ext"
]

class Feature(object):
    def __init__(self, fgroup=None, fsupp=None, funsupp=None):
        fgroup = fgroup or feature_groups[0]
        if fgroup not in feature_groups:
            raise ValueError("unknown feature group {}".format(fgroup))
        self.supported = dict()
        self.init_broadcom()
        self.init_common()
        self.set_supported(fsupp)
        self.set_unsupported(funsupp)

    def set_supported_value(self, value, *args):
        for name in args:
            if name is None: continue
            if isinstance(name, list):
                for n in name:
                    self.supported[n] = value
            else:
                self.supported[name] = value

    def set_supported(self, *args):
        self.set_supported_value(True, *args)

    def set_unsupported(self, *args):
        self.set_supported_value(False, *args)

    def init_common(self):
        self.set_unsupported("tech-support-function")
        self.set_unsupported("tech-support-testcase")
        self.set_supported("tech-support-port-status-fail")
        self.set_unsupported("confirm-reboot")
        self.set_unsupported("rest")

    def init_broadcom(self):
        self.set_supported(feature_names)

    def is_supported(self, name, dut=None):
        if name not in self.supported:
            raise ValueError("unknown feature name {}".format(name))
        return self.supported[name]

    def get_all(self):
        return sorted(self.supported.items())

