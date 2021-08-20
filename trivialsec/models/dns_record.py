from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.dns_record'
__table__ = 'dns_records'
__pk__ = 'dns_record_id'

class DnsRecord(MySQL_Row_Adapter):
    RECORDS = {
        'A': 'a host address  [RFC1035]',
        'NS': 'an authoritative name server  [RFC1035]',
        'MD': 'a mail destination (OBSOLETE - use MX)  [RFC1035]',
        'MF': 'a mail forwarder (OBSOLETE - use MX)  [RFC1035]',
        'CNAME': 'the canonical name for an alias  [RFC1035]',
        'SOA': 'marks the start of a zone of authority  [RFC1035]',
        'MB': 'a mailbox domain name (EXPERIMENTAL)  [RFC1035]',
        'MG': 'a mail group member (EXPERIMENTAL)  [RFC1035]',
        'MR': 'a mail rename domain name (EXPERIMENTAL)  [RFC1035]',
        'NULL': 'a null RR (EXPERIMENTAL)  [RFC1035]',
        'WKS': 'a well known service description  [RFC1035]',
        'PTR': 'a domain name pointer  [RFC1035]',
        'HINFO': 'host information  [RFC1035]',
        'MINFO': 'mailbox or mail list information  [RFC1035]',
        'MX': 'mail exchange  [RFC1035]',
        'TXT': 'text strings  [RFC1035]',
        'RP': 'for Responsible Person  [RFC1183]',
        'AFSDB': 'for AFS Data Base location  [RFC1183][RFC5864]',
        'X25': 'for X.25 PSDN address  [RFC1183]',
        'ISDN': 'for ISDN address  [RFC1183]',
        'RT': 'for Route Through  [RFC1183]',
        'NSAP': 'for NSAP address, NSAP style A record  [RFC1706]',
        'NSAP-PTR': 'for domain name pointer, NSAP style  [RFC1348][RFC1637][RFC1706]',
        'SIG': 'for security signature  [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]',
        'KEY': 'for security key  [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]',
        'PX': 'X.400 mail mapping information  [RFC2163]',
        'GPOS': 'Geographical Position  [RFC1712]',
        'AAAA': 'IP6 Address  [RFC3596]',
        'LOC': 'Location Information  [RFC1876]',
        'NXT': 'Next Domain (OBSOLETE)  [RFC3755][RFC2535]',
        'EID': 'Endpoint Identifier  [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]',
        'NIMLOC': 'Nimrod Locator  [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]',
        'SRV': 'Server Selection  [1][RFC2782]',
        'ATMA': 'ATM Address  [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]',
        'NAPTR': 'Naming Authority Pointer  [RFC2915][RFC2168][RFC3403]',
        'KX': 'Key Exchanger  [RFC2230]',
        'CERT': 'CERT  [RFC4398]',
        'A6': 'A6 (OBSOLETE - use AAAA)  [RFC3226][RFC2874][RFC6563]',
        'DNAME': 'DNAME  [RFC6672]',
        'SINK': 'SINK  [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]',
        'OPT': 'OPT  [RFC6891][RFC3225]',
        'APL': 'APL  [RFC3123]',
        'DS': 'Delegation Signer  [RFC4034][RFC3658]',
        'SSHFP': 'SSH KeyFindings Fingerprint  [RFC4255]',
        'IPSECKEY': 'IPSECKEY  [RFC4025]',
        'RRSIG': 'RRSIG  [RFC4034][RFC3755]',
        'NSEC': 'NSEC  [RFC4034][RFC3755]',
        'DNSKEY': 'DNSKEY  [RFC4034][RFC3755]',
        'DHCID': 'DHCID  [RFC4701]',
        'NSEC3': 'NSEC3  [RFC5155]',
        'NSEC3PARAM': 'NSEC3PARAM  [RFC5155]',
        'TLSA': 'TLSA  [RFC6698]',
        'SMIMEA': 'S/MIME cert association  [RFC8162]',
        'HIP': 'Host Identity Protocol  [RFC8005]',
        'NINFO': 'NINFO  [Jim_Reid]',
        'RKEY': 'RKEY  [Jim_Reid]',
        'TALINK': 'Trust FindingsAnchor LINK  [Wouter_Wijngaards]',
        'CDS': 'Child DS  [RFC7344]',
        'CDNSKEY': 'DNSKEY(s) the Child wants reflected in DS  [RFC7344]',
        'OPENPGPKEY': 'OpenPGP Key  [RFC7929]',
        'CSYNC': 'Child-To-Parent Synchronization  [RFC7477]',
        'ZONEMD': 'message digest for DNS zone  [draft-wessels-dns-zone-digest]',
        'SPF': '[RFC7208]',
        'UINFO': '[IANA-Reserved]',
        'UID': '[IANA-Reserved]',
        'GID': '[IANA-Reserved]',
        'UNSPEC': '[IANA-Reserved]',
        'NID': '[RFC6742]',
        'L32': '[RFC6742]',
        'L64': '[RFC6742]',
        'LP': '[RFC6742]',
        'EUI48': 'an EUI-48 address  [RFC7043]',
        'EUI64': 'an EUI-64 address  [RFC7043]',
        'TKEY': 'Transaction Key  [RFC2930]',
        'TSIG': 'Transaction Signature  [RFC2845]',
        'IXFR': 'incremental transfer  [RFC1995]',
        'AXFR': 'transfer of an entire zone  [RFC1035][RFC5936]',
        'MAILB': 'mailbox-related RRs (MB, MG or MR)  [RFC1035]',
        'MAILA': 'mail agent RRs (OBSOLETE - see MX)  [RFC1035]',
        '*': 'A request for some or all records the server has available  [RFC1035][RFC6895][RFC8482]',
        'URI': 'URI  [RFC7553]',
        'CAA': 'Certification Authority Restriction  [RFC8659]',
        'AVC': 'Application Visibility and Control  [Wolfgang_Riedel]',
        'DOA': 'Digital Object Architecture  [draft-durand-doa-over-dns]',
        'AMTRELAY': 'Automatic Multicast Tunneling Relay  [draft-ietf-mboned-driad-amt-discovery]',
        'TA': 'DNSSEC Trust Authorities  [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]',
        'DLV': 'DNSSEC Lookaside Validation (OBSOLETE)  [RFC-ietf-dnsop-obsolete-dlv-02][RFC4431]'
    }
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.dns_record_id = kwargs.get('dns_record_id')
        self.domain_id = kwargs.get('domain_id')
        self.ttl = kwargs.get('ttl')
        self.dns_class = kwargs.get('dns_class')
        self.resource = kwargs.get('resource')
        self.answer = kwargs.get('answer')
        self.raw = kwargs.get('raw')
        self.last_checked = kwargs.get('last_checked')

class DnsRecords(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('DnsRecord', __table__, __pk__)
