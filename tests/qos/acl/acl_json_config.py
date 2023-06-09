acl_json_config_d1 = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    },
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    },
    "L2_MAC_INGRESS": {
      "type": "L2",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_INGRESS"
    },
    "L2_MAC_EGRESS": {
      "type": "L2",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.1/32",
      "DST_IP": "2.2.2.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT_RANGE": "10-20",
      "DSCP":62,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_INGRESS|rule2": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "5.5.5.5/32",
      "DST_IP": "9.9.9.9/32",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 17,
      "PRIORITY": 2000
    },
    "L3_IPV4_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "9.9.9.9/32",
      "DST_IP": "12.12.12.12/32",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV4_INGRESS|rule5": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "18.18.1.1/32",
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|rule6": {
      "PACKET_ACTION": "REDIRECT",
      "SRC_IP": "176.185.1.1/32",
      "DST_IP": "10.18.1.1/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|PermitAny7": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 100
    },
    "L3_IPV4_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "192.138.10.1/32",
      "DST_IP": "55.46.45.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "DSCP": 61,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "88.67.45.9/32",
      "DST_IP": "12.12.12.12/32",
      "IP_PROTOCOL": 17,
      "DSCP": 61,
      "PRIORITY": 4000
    },
    "L3_IPV4_EGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "181.182.1.1/32",
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_EGRESS|PermitAny4": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 100
    },
    "L3_IPV4_EGRESS|PermitAny5": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "IP_PROTOCOL": 17,
      "PRIORITY": 100
    },
    "L2_MAC_INGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "VLAN": "",
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_INGRESS|macrule2": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "VLAN": "",
      "PRIORITY": 900
    },
    "L2_MAC_EGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "VLAN": "",
      "PRIORITY": 2000
   },
    "L2_MAC_EGRESS|macrule4": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "VLAN": "",
      "PRIORITY": 9000
    },
    "L2_MAC_EGRESS|macrule5": {
      "PACKET_ACTION": "DROP",
      "VLAN": "",
      "ETHER_TYPE":0x0810,
      "PRIORITY": 90
    }
  }
}
acl_json_config_v4_switch = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    },
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.1/32",
      "DST_IP": "2.2.2.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT_RANGE": "10-20",
      "DSCP":62,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_INGRESS|rule2": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "5.5.5.5/32",
      "DST_IP": "9.9.9.9/32",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 17,
      "PRIORITY": 2000
    },
    "L3_IPV4_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "9.9.9.9/32",
      "DST_IP": "12.12.12.12/32",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV4_INGRESS|rule5": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "18.18.1.1/32",
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|rule6": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "176.185.1.1/32",
      "DST_IP": "10.18.1.1/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|PermitAny7": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 100
    },
    "L3_IPV4_INGRESS|PermitAny8": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "IP_PROTOCOL": 17,
      "PRIORITY": 100
    },
    "L3_IPV4_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "192.138.10.1/32",
      "DST_IP": "55.46.45.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "DSCP": 61,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "88.67.45.9/32",
      "DST_IP": "12.12.12.12/32",
      "IP_PROTOCOL": 17,
      "DSCP": 61,
      "PRIORITY": 4000
    },
    "L3_IPV4_EGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "181.182.1.1/32",
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_EGRESS|PermitAny4": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "IP_PROTOCOL": 17,
      "PRIORITY": 50
    },
    "L3_IPV4_EGRESS|PermitAny5": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 50
    }
  }
}
acl_json_config_switch_d3 = {
  "ACL_TABLE": {
    "L2_MAC_INGRESS": {
      "type": "L2",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_INGRESS"
    }
  },
  "ACL_RULE": {
    "L2_MAC_INGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_INGRESS|macrule2": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 900
    },
    "L2_MAC_INGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
    }
  }
}
acl_json_config_switch_d3_egress = {
  "ACL_TABLE": {
    "L2_MAC_EGRESS": {
      "type": "L2",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_EGRESS"
    }
  },
  "ACL_RULE": {
    "L2_MAC_EGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
   },
    "L2_MAC_EGRESS|macrule4": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 9000
    }
  }
}
acl_json_config_port_d3 = {
  "ACL_TABLE": {
    "L2_MAC_INGRESS": {
      "type": "L2",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_INGRESS"
    },
    "L2_MAC_EGRESS": {
      "type": "L2",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_EGRESS"
    }
  },
  "ACL_RULE": {
    "L2_MAC_INGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_INGRESS|macrule2": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "ETHER_TYPE": 0x0800,
      "PRIORITY": 900
    },
    "L2_MAC_INGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
    },
    "L2_MAC_EGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_EGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
   },
    "L2_MAC_EGRESS|macrule4": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 90
    }
  }
}
acl_json_config_vlan_d3 = {
  "ACL_TABLE": {
    "L2_MAC_INGRESS": {
      "type": "L2",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_INGRESS"
    },
    "L2_MAC_EGRESS": {
      "type": "L2",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_EGRESS"
    }
  },
  "ACL_RULE": {
    "L2_MAC_INGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_INGRESS|macrule2": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 900
    },
    "L2_MAC_INGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
    },
    "L2_MAC_INGRESS|macrule4": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
    },
    "L2_MAC_EGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_EGRESS|macrule3": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 2000
   },
    "L2_MAC_EGRESS|macrule4": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "PRIORITY": 90
    }
  }
}
acl_json_config_d2 = {
  "ACL_TABLE": {
    "L3_IPV6_INGRESS": {
      "type": "L3V6",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_INGRESS"
    },
    "L3_IPV6_EGRESS": {
      "type": "L3V6",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV6_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::10/128",
      "DST_IPV6": "3001::10/128",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV6_INGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "6001::10/128",
      "DST_IPV6": "7001::10/128",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV6_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "8001::10/128",
      "DST_IPV6": "9001::10/128",
      "L4_DST_PORT": 100,
      "IP_PROTOCOL": 17,
      "PRIORITY": 5000
    },
    "L3_IPV6_INGRESS|rule5": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv6any",
      "SRC_IPV6": "2001::2/128",
      "PRIORITY": 1000
    },
    "L3_IPV6_INGRESS|PermitAny6": {
          "PACKET_ACTION": "FORWARD",
          "IP_TYPE": "ipv6any",
          "PRIORITY": 100
    },
      "L3_IPV6_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::10/128",
      "DST_IPV6": "3001::10/128",
      "IP_PROTOCOL": 6,
      "L4_DST_PORT": 560,
      "PRIORITY": 1000
    },
    "L3_IPV6_EGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "8001::10/128",
      "DST_IPV6": "9001::10/128",
      "IP_PROTOCOL": 17,
      "L4_SRC_PORT": 560,
      "PRIORITY": 5000
    },
    # "L3_IPV6_EGRESS|DenyAny5": {
    #   "PACKET_ACTION": "DROP",
    #   "ETHER_TYPE":'0x086dd',
    #   "PRIORITY": 50
    # },
    "L3_IPV6_EGRESS|PermitAny6": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv6any",
      "PRIORITY": 100
    }
  }
}
acl_json_egress_configv4 = {
  "ACL_TABLE": {
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "192.138.10.1/32",
      "DST_IP": "55.46.45.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "DSCP":61,
      "PRIORITY": 1000
    },
    "L3_IPV4_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "88.67.45.9/32",
      "DST_IP": "12.12.12.12/32",
      "IP_PROTOCOL": 17,
      "DSCP": 61,
      "PRIORITY": 4000
    },
    "L3_IPV4_EGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "181.182.1.1/32",
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    }
    # "L3_IPV4_EGRESS|DenyAny4": {
    #   "PACKET_ACTION": "DROP",
    #   "IP_TYPE": "ipv4any",
    #   "PRIORITY": 50
    # }
  }
}
acl_json_ingress_configv4 = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.1/32",
      "DST_IP": "2.2.2.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT_RANGE": "10-20",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_INGRESS|rule2": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "5.5.5.5/32",
      "DST_IP": "9.9.9.9/32",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 17,
      "PRIORITY": 2000
    },
    "L3_IPV4_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "9.9.9.9/32",
      "DST_IP": "12.12.12.12/32",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV4_INGRESS|rule5": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "18.18.1.1/32",
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|rule6": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "176.185.1.1/32",
      "DST_IP": "10.18.1.1/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "PRIORITY": 5000
    },
   "L3_IPV4_INGRESS|rule7": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "5.5.5.5/32",
      "DST_IP": "9.9.9.9/32",
      "IP_PROTOCOL": 17,
      "PRIORITY": 2005
    }
    # "L3_IPV4_INGRESS|PermitAny7": {
    #   "PACKET_ACTION": "FORWARD",
    #   "IP_TYPE": "ipv4any",
    #   "PRIORITY":  500
    # }
  }
}
acl_json_config_v6_ingress_vlan = {
  "ACL_TABLE": {
    "L3_IPV6_INGRESS": {
      "type": "L3V6",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV6_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::10/128",
      "DST_IPV6": "3001::10/128",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    # "L3_IPV6_INGRESS|PermitAny2": {
    #   "PACKET_ACTION": "FORWARD",
    #   "IP_TYPE": "ipv6any",
    #   "PRIORITY": 100
    # },
    "L3_IPV6_INGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "6001::10/128",
      "DST_IPV6": "7001::10/128",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV6_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "8001::10/128",
      "DST_IPV6": "9001::10/128",
      "L4_DST_PORT": 100,
      "IP_PROTOCOL": 17,
      "PRIORITY": 5000
    },
    # "L3_IPV6_INGRESS|DenyAny6": {
    #   "PACKET_ACTION": "DROP",
    #   "ETHER_TYPE":'0x086dd',
    #   "PRIORITY": 50
    # },
    "L3_IPV6_INGRESS|rule5": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv6any",
      "SRC_IPV6": "2001::2/128",
      "PRIORITY": 1000
    }
  }
}
acl_json_config_v6_egress_vlan = {
  "ACL_TABLE": {
    "L3_IPV6_EGRESS": {
      "type": "L3V6",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV6_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::10/128",
      "DST_IPV6": "3001::10/128",
      "IP_PROTOCOL": 6,
      "L4_DST_PORT": 560,
      "PRIORITY": 1000
    },
    "L3_IPV6_EGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "8001::10/128",
      "DST_IPV6": "9001::10/128",
      "IP_PROTOCOL": 17,
      "L4_SRC_PORT": 560,
      "PRIORITY": 5000
    },
    "L3_IPV6_EGRESS|DenyAny5": {
      "PACKET_ACTION": "DROP",
      "ETHER_TYPE": '0x086dd',
      "PRIORITY": 50
    },
    "L3_IPV6_EGRESS|PermitAny6": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv6any",
      "PRIORITY": 100
    }
  }
}
acl_json_ingress_vlan_configv4 = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.1/32",
      "DST_IP": "2.2.2.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT_RANGE": "10-20",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_INGRESS|rule2": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "5.5.5.5/32",
      "DST_IP": "9.9.9.9/32",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 17,
      "PRIORITY": 2000
    },
    "L3_IPV4_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "9.9.9.9/32",
      "DST_IP": "12.12.12.12/32",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV4_INGRESS|rule5": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "18.18.1.1/32",
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|PermitAny7": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 100
    }
  }
}

acl_json_egress_vlan_configv4 = {
  "ACL_TABLE": {
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "192.138.10.1/32",
      "DST_IP": "55.46.45.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "DSCP": 61,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "88.67.45.9/32",
      "DST_IP": "12.12.12.12/32",
      "IP_PROTOCOL": 17,
      "DSCP": 61,
      "PRIORITY": 4000
    },
    "L3_IPV4_EGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "181.182.1.1/32",
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_EGRESS|PermitAny4": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 100
    }
  }
}
acl_json_config_portchannel_d3 = {
  "ACL_TABLE": {
    "L2_MAC_INGRESS": {
      "type": "L2",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_INGRESS"
    }
  },
  "ACL_RULE": {
    "L2_MAC_INGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
      "VLAN": [],
      # "PCP":4,
      # "DEI":1,
      "PRIORITY": 1000
    },
    "L2_MAC_INGRESS|macrule2": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
      "VLAN": [],
      "PRIORITY": 900
    }
  }
}

acl_json_config_portchannel_egress = {
      "ACL_TABLE": {
        "L2_MAC_EGRESS": {
          "type": "L2",
          "stage": "EGRESS",
          "ports": [],
          "policy_desc": "L2_MAC_EGRESS"
        }
      },
      "ACL_RULE": {
        "L2_MAC_EGRESS|macrule3": {
          "PACKET_ACTION": "FORWARD",
          "SRC_MAC": "00:0a:01:00:11:04/ff:ff:ff:ff:ff:ff",
          "DST_MAC": "00:0a:01:00:00:03/ff:ff:ff:ff:ff:ff",
          "VLAN": "",
          "PRIORITY": 2000
      },
       "L2_MAC_EGRESS|macrule4": {
          "PACKET_ACTION": "DROP",
          "SRC_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
          "DST_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
          "VLAN": "",
          "PRIORITY": 9000
      }
  }
}

acl_json_egress_configv4 = {
  "ACL_TABLE": {
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "192.138.10.1/32",
      "DST_IP": "55.46.45.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "88.67.45.9/32",
      "DST_IP": "12.12.12.12/32",
      "IP_PROTOCOL": 17,
      "DSCP": 61,
      "PRIORITY": 4000
    },
    "L3_IPV4_EGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "185.185.1.1/32",
      "DST_IP": "181.182.1.1/32",
      "L4_DST_PORT": 567,
      "IP_PROTOCOL": 6,
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    }
    # "L3_IPV4_EGRESS|DenyAny4": {
    #   "PACKET_ACTION": "DROP",
    #   "IP_TYPE": "ipv4any",
    #   "PRIORITY": 50
    # }
  }
}
acl_json_ingress_configv6 = {
  "ACL_TABLE": {
    "L3_IPV6_INGRESS": {
      "type": "L3V6",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV6_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::10/128",
      "DST_IPV6": "3001::10/128",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    # "L3_IPV6_INGRESS|PermitAny2": {
    #   "PACKET_ACTION": "FORWARD",
    #   "IP_TYPE": "ipv6any",
    #   "PRIORITY":  600
    # },
    "L3_IPV6_INGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "6001::10/128",
      "DST_IPV6": "7001::10/128",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV6_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "8001::10/128",
      "DST_IPV6": "9001::10/128",
      "IP_PROTOCOL": 17,
      "PRIORITY": 5000
    },
    # "L3_IPV6_INGRESS|DenyAny5": {
    #   "PACKET_ACTION": "DROP",
    #   "ETHER_TYPE":'0x086dd',
    #   "PRIORITY": 50
    # },
    # "L3_IPV6_INGRESS|PermitAny6": {
    #   "PACKET_ACTION": "FORWARD",
    #   "IP_TYPE": "ipv6any",
    #   "PRIORITY":  500
    # }
  }
}
acl_json_config_table = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    },
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    },
    "L3_IPV6_INGRESS": {
      "type": "L3V6",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_INGRESS"
    },
    "L3_IPV6_EGRESS": {
      "type": "L3V6",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_EGRESS"
    }
  }
}
acl_json_config_priority = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    },
    "L2_MAC_INGRESS": {
      "type": "L2",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.1/32",
      "DST_IP": "2.2.2.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT_RANGE": "10-20",
      "DSCP": 62,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "9.9.9.9/32",
      "DST_IP": "12.12.12.12/32",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L2_MAC_INGRESS|macrule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_MAC": "00:0a:01:00:00:01/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:11:02/ff:ff:ff:ff:ff:ff",
      "VLAN": "",
      "PRIORITY": 1000
    }
  }
}

acl_json_config_priority_egress = {
  "ACL_TABLE": {
    "L3_IPV4_EGRESS": {
      "type": "L3",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_EGRESS"
    },
    "L2_MAC_EGRESS": {
      "type": "L2",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L2_MAC_EGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "192.138.10.1/32",
      "DST_IP": "55.46.45.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT": 567,
      "DSCP": 61,
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "88.67.45.9/32",
      "DST_IP": "12.12.12.12/32",
      "IP_PROTOCOL": 17,
      "DSCP": 61,
      "PRIORITY": 4000
    },
    "L2_MAC_EGRESS|macrule1": {
      "PACKET_ACTION": "DROP",
      "SRC_MAC": "00:0a:01:00:11:02/ff:ff:ff:ff:ff:ff",
      "DST_MAC": "00:0a:01:00:00:01/ff:ff:ff:ff:ff:ff",
      "VLAN": "",
      "PRIORITY": 1000
    }
  }
}

acl_json_egress_configv6 = {
  "ACL_TABLE": {
    "L3_IPV6_EGRESS": {
      "type": "L3V6",
      "stage": "EGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_EGRESS"
    }
  },
  "ACL_RULE": {
     "L3_IPV6_EGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::10/128",
      "DST_IPV6": "3001::10/128",
      "IP_PROTOCOL": 6,
      "L4_DST_PORT": 560,
      "PRIORITY": 1000
    },
    "L3_IPV6_EGRESS|rule2": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "8001::10/128",
      "DST_IPV6": "9001::10/128",
      "IP_PROTOCOL": 17,
      "L4_SRC_PORT": 560,
      "PRIORITY": 5000
    },
    "L3_IPV6_EGRESS|DenyAny3": {
      "PACKET_ACTION": "DROP",
      "ETHER_TYPE":'0x086dd',
      "PRIORITY": 50
    }
  }
}
acl_json_config_v4_l3_traffic = {
  "ACL_TABLE": {
    "L3_IPV4_INGRESS": {
      "type": "L3",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV4_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV4_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.2/32",
      "DST_IP": "2.2.2.2/32",
      "L4_SRC_PORT": 43,
      "L4_DST_PORT_RANGE": "10-20",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV4_INGRESS|rule2": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IP": "1.1.1.4/32",
      "DST_IP": "2.2.2.4/32",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 17,
      "PRIORITY": 2000
    },
    "L3_IPV4_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "1.1.1.5/32",
      "DST_IP": "2.2.2.5/32",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV4_INGRESS|rule5": {
      "PACKET_ACTION": "DROP",
      "SRC_IP": "1.1.1.6/32",
      "DST_IP": "2.2.2.6/32",
      "TCP_FLAGS": "4/4",
      "PRIORITY": 5000
    },
    "L3_IPV4_INGRESS|PermitAny6": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv4any",
      "PRIORITY": 100
    }
  }
}
acl_json_config_v6_l3_traffic = {
  "ACL_TABLE": {
    "L3_IPV6_INGRESS": {
      "type": "L3V6",
      "stage": "INGRESS",
      "ports": [],
      "policy_desc": "L3_IPV6_INGRESS"
    }
  },
  "ACL_RULE": {
    "L3_IPV6_INGRESS|rule1": {
      "PACKET_ACTION": "FORWARD",
      "SRC_IPV6": "2001::2/128",
      "DST_IPV6": "1001::2/128",
      "L4_SRC_PORT_RANGE": "100-500",
      "IP_PROTOCOL": 6,
      "PRIORITY": 1000
    },
    "L3_IPV6_INGRESS|rule3": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "3001::2/128",
      "DST_IPV6": "4001::2/128",
      "L4_SRC_PORT": "100",
      "L4_DST_PORT_RANGE": "300-400",
      "IP_PROTOCOL": 6,
      "PRIORITY": 4000
    },
    "L3_IPV6_INGRESS|rule4": {
      "PACKET_ACTION": "DROP",
      "SRC_IPV6": "5001::2/128",
      "DST_IPV6": "6001::2/128",
      "L4_DST_PORT": 100,
      "IP_PROTOCOL": 17,
      "PRIORITY": 5000
    },
    "L3_IPV6_INGRESS|PermitAny5": {
      "PACKET_ACTION": "FORWARD",
      "IP_TYPE": "ipv6any",
      "PRIORITY": 100
    }
  }
}
acl_json_config_control_plane = {
  "ACL_TABLE":{
     "SNMP_SSH":{
        "services":[
           "SNMP",
           "SSH"
        ],
        "type":"CTRLPLANE",
        "policy_desc":"SNMP_SSH"
     },
     "V6_SSH_ONLY":{
        "services":[
           "SSH"
        ],
        "type":"CTRLPLANE",
        "policy_desc":"V6_SSH_ONLY"
     }
  },
  "ACL_RULE":{
     "SNMP_SSH|DEFAULT_RULE100":{
        "PRIORITY":"1",
        "PACKET_ACTION":"DROP",
        "L4_DST_PORT":"22",
        "ETHER_TYPE":"0x0800"
     },
    "SNMP_SSH|DEFAULT_RULE101":{
        "PRIORITY":"2",
        "PACKET_ACTION":"DROP",
        "L4_DST_PORT":"161",
        "IP_PROTOCOL":"17"
     },
     "SNMP_SSH|RULE_1":{
        "PRIORITY":"9997",
        "PACKET_ACTION":"ACCEPT",
        "SRC_IP":"",
        "IP_PROTOCOL":"17"
     },
     "SNMP_SSH|RULE_2":{
        "PRIORITY":"9999",
        "PACKET_ACTION":"ACCEPT",
        "SRC_IP":"",
        "IP_PROTOCOL":"6"
     },
     "SNMP_SSH|RULE_3":{
        "PRIORITY":"9998",
        "PACKET_ACTION":"ACCEPT",
        "SRC_IP":"",
        "L4_DST_PORT":"22",
        "IP_PROTOCOL":"6"
     },
     "V6_SSH_ONLY|DEFAULT_RULE100":{
        "PRIORITY":"3",
        "PACKET_ACTION":"DROP",
        "L4_DST_PORT":"22",
        "ETHER_TYPE":"0x86dd"
     },
     "V6_SSH_ONLY|RULE_1":{
        "IP_PROTOCOL":"6",
        "PACKET_ACTION":"ACCEPT",
        "PRIORITY":"9996",
        "L4_DST_PORT":"22",
        "SRC_IPV6":""
     }
  }
}


acl_json_config_control_plane_v2= {
	"ACL_TABLE": {
		"L3_IPV4_ICMP": {
			"ports": [
				"CtrlPlane"
			],
			"stage": "INGRESS",
			"type": "L3"
		},
        "L3_IPV6_ICMP": {
			"ports": [
				"CtrlPlane"
			],
			"stage": "INGRESS",
			"type": "L3V6"
		}
	},
	"ACL_RULE": {
		"L3_IPV4_ICMP|default_rule100": {
			"IP_PROTOCOL": "1",
			"PACKET_ACTION": "DROP",
			"PRIORITY": "100"
		},
        "L3_IPV4_ICMP|rule1": {
			"IP_PROTOCOL": "1",
			"PACKET_ACTION": "FORWARD",
            "SRC_IP": "12.12.12.12/32",
			"PRIORITY": "998"
		},
        "L3_IPV6_ICMP|default_rule100": {
			"IP_PROTOCOL": "58",
			"PACKET_ACTION": "DROP",
			"PRIORITY": "100"
		},
        "L3_IPV6_ICMP|rule1": {
			"IP_PROTOCOL": "58",
			"PACKET_ACTION": "FORWARD",
            "SRC_IPV6": "aaaa::aaaa/128",
			"PRIORITY": "998"
		}
	}
}