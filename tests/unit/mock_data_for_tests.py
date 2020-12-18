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
    '/deliberate/observables': {
        "data": {
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
    '/observe/observables': {'data': {}},
    '/refer/observables': {'data': []}
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
    '/deliberate/observables': {
        "data": {
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
    '/observe/observables': {'data': {}},
    '/refer/observables': {'data': []}
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
    '/deliberate/observables': {
        "data": {
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
    '/observe/observables': {'data': {}},
    '/refer/observables': {'data': []}
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
    '/deliberate/observables': {
        "data": {
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
    '/observe/observables': {'data': {}},
    '/refer/observables': {'data': []}
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
    '/deliberate/observables': {
        "data": {
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "sha256",
                            "value": "7fa2c54d7dabb0503d75bdd13cc4d6a6520516"
                                     "a990fb7879ae052bad9520763b"
                        },
                        "type": "verdict"
                    }
                ]
            }
        }
    },
    '/observe/observables': {'data': {}},
    '/refer/observables': {'data': []}
}

ENTITY_LIFETIME_MOCK = timedelta(days=7)
