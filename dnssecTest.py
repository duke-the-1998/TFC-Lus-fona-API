import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype

domain = "nos.pt"
# get nameservers for target domain
response = dns.resolver.query(domain,dns.rdatatype.NS)

# we'll use the first nameserver in this example
nsname = response.rrset[0].to_text() # name
response = dns.resolver.query(nsname,dns.rdatatype.A)
nsaddr = response.rrset[0].to_text() # IPv4

# get DNSKEY for zone
request = dns.message.make_query(domain,
                                 dns.rdatatype.DNSKEY,
                                 want_dnssec=True)

# send the query
response = dns.query.udp(request,nsaddr)
if response.rcode() != 0:
    # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

# answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
    answer = response.answer
if len(answer) != 2:
    # SOMETHING WENT WRONG

# the DNSKEY should be self signed, validate it
    name = dns.name.from_text(domain)
try:
    dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
except dns.dnssec.ValidationFailure:
    print("asdasd")
