from datetime import timedelta

AUTOFOCUS_IP_RESPONSE_MOCK = {
    "indicator": {
        "indicatorValue": "103.110.84.196",
        "indicatorType": "IPV4_ADDRESS",
        "summaryGenerationTs": 1607951568568,
        "firstSeenTsGlobal": None,
        "lastSeenTsGlobal": None,
        "latestPanVerdicts": {
            "PAN_DB": "MALWARE"
        },
        "seenByDataSourceIds": [],
        "wildfireRelatedSampleVerdictCounts": {}
    },
    "tags": [],
    "bucketInfo": {
        "minutePoints": 200,
        "dailyPoints": 25000,
        "minuteBucketStart": "2020-11-20 05:02:52",
        "dailyBucketStart": "2020-11-20 04:52:40",
        "minutePointsRemaining": 196,
        "dailyPointsRemaining": 24980,
        "waitInSeconds": 0
    }
}

INTEGRATION_IP_RESPONSE_MOCK = {
    '/deliberate/observables': {"data": {}},
    '/observe/observables': {
        "data": {
            "judgements": {
                "count": 1,
                "docs": [
                    {
                        "confidence": "High",
                        "disposition": 2,
                        "disposition_name": "Malicious",
                        "observable": {
                            "type": "ip",
                            "value": "103.110.84.196"
                        },
                        "priority": 85,
                        "reason": "MALWARE in AutoFocus",
                        "schema_version": "1.0.22",
                        "severity": "High",
                        "source": "Palo Alto AutoFocus",
                        "source_uri": "https://autofocus.paloaltonetworks.com/"
                                      "#/search/indicator/ipv4_address/"
                                      "103.110.84.196",
                        "type": "judgement"
                    }
                ]
            },
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 2,
                        "disposition_name": "Malicious",
                        "observable": {
                            "type": "ip",
                            "value": "103.110.84.196"
                        },
                        "type": "verdict"
                    }
                ]
            }
        }
    },
    '/refer/observables': {
        'data': [
            {
                "categories": [
                    "Search",
                    "Palo Alto AutoFocus"
                ],
                "description": "Look up this IP on Palo Alto AutoFocus",
                "id": "ref-palo-alto-autofocus-search-ip-103.110.84.196",
                "title": "Search for this IP",
                "url": "https://autofocus.paloaltonetworks.com/#/search/"
                       "indicator/ipv4_address/103.110.84.196"
            }]
    }
}

AUTOFOCUS_IPV6_RESPONSE_MOCK = {
    "indicator": {
        "indicatorValue": "2001:db8:85a3:8d3:1319:8a2e:370:7348",
        "indicatorType": "IPV6_ADDRESS",
        "summaryGenerationTs": 1607953105326,
        "firstSeenTsGlobal": None,
        "lastSeenTsGlobal": None,
        "latestPanVerdicts": {
            "PAN_DB": "BENIGN"
        },
        "seenByDataSourceIds": [],
        "wildfireRelatedSampleVerdictCounts": {}
    },
    "tags": [],
    "bucketInfo": {
        "minutePoints": 200,
        "dailyPoints": 25000,
        "minuteBucketStart": "2020-11-20 05:02:52",
        "dailyBucketStart": "2020-11-20 04:52:40",
        "minutePointsRemaining": 196,
        "dailyPointsRemaining": 24980,
        "waitInSeconds": 0
    }
}

INTEGRATION_IPV6_RESPONSE_MOCK = {
    '/deliberate/observables': {"data": {}},
    '/observe/observables': {
        "data": {
            "judgements": {
                "count": 1,
                "docs": [
                    {
                        "confidence": "High",
                        "disposition": 1,
                        "disposition_name": "Clean",
                        "observable": {
                            "type": "ipv6",
                            "value": "2001:db8:85a3:8d3:1319:8a2e:370:7348"
                        },
                        "priority": 85,
                        "reason": "BENIGN in AutoFocus",
                        "schema_version": "1.0.22",
                        "severity": "High",
                        "source": "Palo Alto AutoFocus",
                        "source_uri": "https://autofocus.paloaltonetworks.com"
                                      "/#/search/indicator/ipv6_address/"
                                      "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                        "type": "judgement"
                    }
                ]
            },
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 1,
                        "disposition_name": "Clean",
                        "observable": {
                            "type": "ipv6",
                            "value": "2001:db8:85a3:8d3:1319:8a2e:370:7348"
                        },
                        "type": "verdict"
                    }
                ]
            }
        }
    },
    '/refer/observables': {
        'data': [
            {
                "categories": [
                    "Search",
                    "Palo Alto AutoFocus"
                ],
                "description": "Look up this IPv6 on Palo Alto AutoFocus",
                "id": "ref-palo-alto-autofocus-search-"
                      "ipv6-2001:db8:85a3:8d3:1319:8a2e:370:7348",
                "title": "Search for this IPv6",
                "url": "https://autofocus.paloaltonetworks.com/#/search"
                       "/indicator/ipv6_address/"
                       "2001:db8:85a3:8d3:1319:8a2e:370:7348"
            }
        ]
    }
}

AUTOFOCUS_DOMAIN_RESPONSE_MOCK = {
    "indicator": {
        "indicatorValue": "cisco.com",
        "indicatorType": "DOMAIN",
        "summaryGenerationTs": 1607953513675,
        "firstSeenTsGlobal": None,
        "lastSeenTsGlobal": None,
        "latestPanVerdicts": {
            "PAN_DB": "BENIGN"
        },
        "seenByDataSourceIds": [],
        "whoisAdminCountry": None,
        "whoisAdminEmail": None,
        "whoisAdminName": None,
        "whoisDomainCreationDate": "1987-05-14",
        "whoisDomainExpireDate": "2022-05-15",
        "whoisDomainUpdateDate": "2019-06-21",
        "whoisRegistrar": "MarkMonitor Inc.",
        "whoisRegistrarUrl": "http://www.markmonitor.com",
        "whoisRegistrant": None,
        "wildfireRelatedSampleVerdictCounts": {}
    },
    "tags": [],
    "bucketInfo": {
        "minutePoints": 200,
        "dailyPoints": 25000,
        "minuteBucketStart": "2020-11-20 05:02:52",
        "dailyBucketStart": "2020-11-20 04:52:40",
        "minutePointsRemaining": 196,
        "dailyPointsRemaining": 24980,
        "waitInSeconds": 0
    }
}

INTEGRATION_DOMAIN_RESPONSE_MOCK = {
    '/deliberate/observables': {"data": {}},
    '/observe/observables': {
        "data": {
            "judgements": {
                "count": 1,
                "docs": [
                    {
                        "confidence": "High",
                        "disposition": 1,
                        "disposition_name": "Clean",
                        "observable": {
                            "type": "domain",
                            "value": "cisco.com"
                        },
                        "priority": 85,
                        "reason": "BENIGN in AutoFocus",
                        "schema_version": "1.0.22",
                        "severity": "High",
                        "source": "Palo Alto AutoFocus",
                        "source_uri": "https://autofocus.paloaltonetworks.com"
                                      "/#/search/indicator/domain/cisco.com",
                        "type": "judgement"
                    }
                ]
            },
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 1,
                        "disposition_name": "Clean",
                        "observable": {
                            "type": "domain",
                            "value": "cisco.com"
                        },
                        "type": "verdict"
                    }
                ]
            }
        }
    },
    '/refer/observables': {
        'data': [
            {
                "categories": [
                    "Search",
                    "Palo Alto AutoFocus"
                ],
                "description": "Look up this domain on Palo Alto AutoFocus",
                "id": "ref-palo-alto-autofocus-search-domain-cisco.com",
                "title": "Search for this domain",
                "url": "https://autofocus.paloaltonetworks.com/#/search/"
                       "indicator/domain/cisco.com"
            }
        ]
    }
}

AUTOFOCUS_URL_RESPONSE_MOCK = {
    "indicator": {
        "indicatorValue": "http://0win365.com/wp-admin/sites/",
        "indicatorType": "URL",
        "summaryGenerationTs": 1607953838339,
        "firstSeenTsGlobal": None,
        "lastSeenTsGlobal": None,
        "latestPanVerdicts": {
            "PAN_DB": "MALWARE"
        },
        "seenByDataSourceIds": [],
        "wildfireRelatedSampleVerdictCounts": {}
    },
    "tags": [],
    "bucketInfo": {
        "minutePoints": 200,
        "dailyPoints": 25000,
        "minuteBucketStart": "2020-11-20 05:02:52",
        "dailyBucketStart": "2020-11-20 04:52:40",
        "minutePointsRemaining": 196,
        "dailyPointsRemaining": 24980,
        "waitInSeconds": 0
    }
}

INTEGRATION_URL_RESPONSE_MOCK = {
    '/deliberate/observables': {"data": {}},
    '/observe/observables': {
        "data": {
            "judgements": {
                "count": 1,
                "docs": [
                    {
                        "confidence": "High",
                        "disposition": 2,
                        "disposition_name": "Malicious",
                        "observable": {
                            "type": "url",
                            "value": "http://0win365.com/wp-admin/sites/"
                        },
                        "priority": 85,
                        "reason": "MALWARE in AutoFocus",
                        "schema_version": "1.0.22",
                        "severity": "High",
                        "source": "Palo Alto AutoFocus",
                        "source_uri": "https://autofocus.paloaltonetworks.com"
                                      "/#/search/indicator/url/"
                                      "http%3A%2F%2F0win365.com%2Fwp-admin%2"
                                      "Fsites%2F/summary",
                        "type": "judgement"
                    }
                ]
            },
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 2,
                        "disposition_name": "Malicious",
                        "observable": {
                            "type": "url",
                            "value": "http://0win365.com/wp-admin/sites/"
                        },
                        "type": "verdict"
                    }
                ]
            }
        }
    },
    '/refer/observables': {
        'data': [
            {
                "categories": [
                    "Search",
                    "Palo Alto AutoFocus"
                ],
                "description": "Look up this URL on Palo Alto AutoFocus",
                "id": "ref-palo-alto-autofocus-search-url-http://"
                      "0win365.com/wp-admin/sites/",
                "title": "Search for this URL",
                "url": "https://autofocus.paloaltonetworks.com/#/search/"
                       "indicator/url/http%3A%2F%2F0win365.com%2Fwp-"
                       "admin%2Fsites%2F/summary"
            }
        ]
    }
}

AUTOFOCUS_SHA256_RESPONSE_MOCK = {
    "indicator": {
        "indicatorValue": "7fa2c54d7dabb0503d75bdd13cc4d6a6520516a990fb7879ae0"
                          "52bad9520763b",
        "indicatorType": "FILEHASH",
        "summaryGenerationTs": 1607954098735,
        "firstSeenTsGlobal": 1605847163000,
        "lastSeenTsGlobal": 1605847163000,
        "latestPanVerdicts": {
            "WF_SAMPLE": "GRAYWARE"
        },
        "seenByDataSourceIds": [
            "WF_SAMPLE"
        ]
    },
    "tags": [
        {
            "support_id": 1,
            "tag_name": "RenameOnReboot",
            "public_tag_name": "Unit42.RenameOnReboot",
            "tag_definition_scope_id": 4,
            "tag_definition_status_id": 1,
            "count": 16068736,
            "lasthit": "2020-12-14 03:08:59",
            "description": "The PendingFileRenameOperations key stores the nam"
                           "es of files to be renamed when the system restarts"
                           ". It consists of pairs of file names. The file spe"
                           "cified in the first item of the pair is renamed to"
                           " match the second item of the pair. The system add"
                           "s this entry to the registry when a user or progra"
                           "m tries to rename a file that is in use. The file "
                           "names are stored in the value of this entry until "
                           "the system is restarted and they are renamed. Whil"
                           "e this is often a legitimate operation, it is some"
                           "times used by malware to overwrite or replace legi"
                           "timate system binaries with malicious ones.",
            "customer_name": "Palo Alto Networks Unit42",
            "customer_industry": "High Tech",
            "upVotes": None,
            "downVotes": None,
            "myVote": None,
            "source": "Unit 42",
            "tag_class_id": 5,
            "tag_definition_id": 36580
        },
        {
            "support_id": 1,
            "tag_name": "HttpNoUserAgent",
            "public_tag_name": "Unit42.HttpNoUserAgent",
            "tag_definition_scope_id": 4,
            "tag_definition_status_id": 1,
            "count": 23313610,
            "lasthit": "2020-12-14 03:39:11",
            "description": "A sample creates HTTP traffic but omits or uses a "
                           "blank user-agent field. Typically, legitimate appl"
                           "ications will include a user-agent value in HTTP r"
                           "equests. HTTP requests without the user-agent head"
                           "er or with a blank user agent value are extremely "
                           "suspect. This tag identified such suspect applicat"
                           "ions.",
            "customer_name": "Palo Alto Networks Unit42",
            "customer_industry": "High Tech",
            "upVotes": 4,
            "downVotes": None,
            "myVote": None,
            "source": "Unit 42",
            "tag_class_id": 5,
            "tag_definition_id": 41533
        },
        {
            "support_id": 1,
            "tag_name": "SelfExtractingExecutable",
            "public_tag_name": "Unit42.SelfExtractingExecutable",
            "tag_definition_scope_id": 4,
            "tag_definition_status_id": 1,
            "count": 3750321,
            "lasthit": "2020-12-13 21:31:08",
            "description": "This sample is a self-extracting executable, which"
                           " is often an attribute of legitimate executables b"
                           "ut is also commonly used by malware authors.\n\nTh"
                           "ese files allow attackers to compress their malici"
                           "ous file(s) into a single binary and launch a seri"
                           "es of commands in sequence. This often allows them"
                           " to execute a malicious binary and display a decoy"
                           " document in a simple fashion.",
            "customer_name": "Palo Alto Networks Unit42",
            "customer_industry": "High Tech",
            "upVotes": 1,
            "downVotes": None,
            "myVote": None,
            "source": "Unit 42",
            "tag_class_id": 5,
            "tag_definition_id": 42834
        }
    ],
    "bucketInfo": {
        "minutePoints": 200,
        "dailyPoints": 25000,
        "minuteBucketStart": "2020-11-20 05:02:52",
        "dailyBucketStart": "2020-11-20 04:52:40",
        "minutePointsRemaining": 196,
        "dailyPointsRemaining": 24980,
        "waitInSeconds": 0
    }
}

INTEGRATION_SHA256_RESPONSE_MOCK = {
    '/deliberate/observables': {"data": {}},
    '/observe/observables': {
        "data": {
            "judgements": {
                "count": 1,
                "docs": [
                    {
                        "confidence": "High",
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "sha256",
                            "value": "7fa2c54d7dabb0503d75bdd13cc4d6a6520516a9"
                                     "90fb7879ae052bad9520763b"
                        },
                        "priority": 85,
                        "reason": "GRAYWARE in AutoFocus",
                        "schema_version": "1.0.22",
                        "severity": "High",
                        "source": "Palo Alto AutoFocus",
                        "source_uri": "https://autofocus.paloaltonetworks.com"
                                      "/#/search/indicator/sha256/7fa2c54d7dab"
                                      "b0503d75bdd13cc4d6a6520516a990fb7879ae"
                                      "052bad9520763b",
                        "type": "judgement"
                    }
                ]
            },
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "sha256",
                            "value": "7fa2c54d7dabb0503d75bdd13cc4d6a6520516a9"
                                     "90fb7879ae052bad9520763b"
                        },
                        "type": "verdict"
                    }
                ]
            }
        }
    },
    '/refer/observables': {
        'data': [
            {
                "categories": [
                    "Search",
                    "Palo Alto AutoFocus"
                ],
                "description": "Look up this SHA256 on Palo Alto AutoFocus",
                "id": "ref-palo-alto-autofocus-search-sha256-"
                      "7fa2c54d7dabb0503d75bdd13cc4d6a6520516a990fb7879ae052ba"
                      "d9520763b",
                "title": "Search for this SHA256",
                "url": "https://autofocus.paloaltonetworks.com/#/search/"
                       "indicator/sha256/7fa2c54d7dabb0503d75bdd13cc4d6a"
                       "6520516a990fb7879ae052bad9520763b"
            }
        ]
    }
}

ENTITY_LIFETIME_MOCK = timedelta(days=7)

EXPECTED_RESPONSE_OF_JWKS_ENDPOINT = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'tSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
                 'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
                 'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
                 '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
                 'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
                 '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
                 'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
                 'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
                 'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
                 'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
                 'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
                 '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
                 'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
                 'k3jNdVM',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'pSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
                 'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
                 'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
                 '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
                 'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
                 '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
                 'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
                 'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
                 'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
                 'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
                 'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
                 '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
                 'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
                 'k3jNdVM',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
