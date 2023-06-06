
multiple_acl_rules = {
	"acl": {
		"acl-sets": {
			"acl-set": {
				"L3_IPV4_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "192.138.10.1/32"

									}
								}
							},
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "12.12.12.12/16"

									}
								}
							}
						}
					}
				},
				"L3_IPV4_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "19.13.10.1/32"

									}
								}
							},
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "120.120.12.12/16"

									}
								}
							}
						}
					}
				},
				"L3_IPV6_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "2001::1/128"

									}
								}
							}
						}
					}
				},
				"L3_IPV6_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "6001::1/128"

									}
								}
							}
						}
					}
				}
			}
		}
	}
}
add_acl_rules = {
	"acl": {
		"acl-sets": {
			"acl-set": {
				"L3_IPV4_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"3": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 3
								},
								"ip": {
									"config": {
										"source-ip-address": "185.185.1.1/16",
										"destination-ip-address": "181.182.1.1/16"

									}
								}
							}

						}
					}
				},
				"L3_IPV4_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"3": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 3
								},
								"ip": {
									"config": {
										"source-ip-address": "10.185.10.1/16",
										"destination-ip-address": "11.12.10.1/16"

									}
								}
							}

						}
					}
				},
				"L3_IPV6_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "3001::1/128"

									}
								}
							}
						}
					}
				},
				"L3_IPV6_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "4001::1/128"

									}
								}
							}
						}
					}
				}
			}
		}
	}
}

mac_acl_rule = {
    "create_mac_acl|RULE_50": {
        "PACKET_ACTION": "FORWARD",
        "SRC_MAC": "00:0a:01:00:00:05/ff:ff:ff:ff:ff:ff",
        "DST_MAC": "00:0a:01:00:11:06/ff:ff:ff:ff:ff:ff",
        "PCP": 0,
        "DEI":0
    }
}

ip_acl_rule = {
    "ipacl|RULE_60": {
        "PACKET_ACTION": "FORWARD",
        "SRC_IP": "12.12.1.1/24",
        "DST_IP": "1.1.1.1/24",
        "IP_PROTOCOL": 6,
        "DSCP":0
    }
}

ipv6_acl_rule = {
    "ipv6acl|RULE_60": {
        "PACKET_ACTION": "FORWARD",
        "SRC_IPV6": "1212:01::01/64",
        "DST_IPV6": "1001::1/64",
        "IP_PROTOCOL": 6,
        "DSCP":0
    }
}