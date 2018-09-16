##  DOMAINTOOLS
https://www.domaintools.com/

### Overview

DomainTools helps security analysts turn threat data into threat intelligence. It takes indicators from your network, including domains and IP addresses, and connects them with nearly every active domain on the internet. These connections perform risk assessments, help profile attackers, guide online fraud investigations, and map cyber activity to the attacker’s infrastructure.  

The goal is to proactively stop security threats from disrupting your organization using: domain/DNS data, predictive analysis, and monitoring of trends on the internet. DomainTools collects Open Source Intelligence (OSINT) data from many sources, along with historical records, and stores it in a central database. It then indexes and analyzes the OSINT data based on various connection algorithms to deliver actionable intelligence, including domain scoring and forensic mapping.  

DomainTools has over 10 billion related DNS data points to build a map of ‘who’s doing what’ on the internet. Fortune 1000 companies, global government agencies, and leading security solution vendors use the DomainTools platform as a critical ingredient in threat investigation and mitigation.

### PRE-REQUISITES to use DomainTools and DNIF  
Outbound access required to resolve DomainTools API

| Protocol   | Source IP  | Source Port  | Direction	 | Destination Domain | Destination Port  |  
|:------------- |:-------------|:-------------|:-------------|:-------------|:-------------|  
| TCP | DS,CR,A10 | Any | Egress	| github.com | 443 |
| TCP | DS,CR,A10 | Any | Egress	| domaintools.com | 443 | 

### DomainTools lookup plugin functions
Details of the functions that can be used with the DomainTools lookup plugin are given in this section.  

#### Common response codes


The $DTResponseCode field contains the response code of a request (function call). This field is common to all the functions. Possible values of this field and their descriptions are as given below

 |Response Codes    | Description  |
|:------------- |:-------------|
| 0 | Domain is invalid |
| 206 | Unable to parse the WHOIS record |
| 400 | Incorrect syntax |
| 404 | WHOIS information not available for this domain/IP address |
| 500 | <ul><li> Rate limit reached on the DomainTools backend</li></ul> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; or  <ul><li>  Some other error related to the WHOIS server has occurred (for example, WHOIS server not responding)</li></ul>  |
| 503 | Service level limit exceeded |

#### Note

In all the functions explained below, the examples use an event store named **threatsample**.  
**This event store does not exist in DNIF by default**. However, it can be created/imported.


### get_domain_profile

This function returns basic (summarized) data about products like registrant, server, registration etc. for a domain name.

#### Input  
- Domain name

#### Example  
```
_fetch $Domain from threatsample limit 1
>>_lookup domaintools get_domain_profile $Domain
```
#### Output

Click [here](https://drive.google.com/file/d/1hMOy3tWqK4KU3BzRntgooCIJWlbWlATi/view?usp=sharing) to view the output of the above example.  
 

The output of the lookup call has the following structure (for the available data):

  | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTHistoricIPAddressEvents | Count of events for IP addresses, recorded by DOMAINTOOLS for the queried domain |
| $DTHistoricIPAddressProductURL | Permalink for more information on the events of the IP addresses for the queried domain |
| $DTHistoricIPAddressTimespaninyears | Number of years since DOMAINTOOLS has this information in its database |
| $DTHistoricNameserverEvents | Count of nameserver events recorded by DOMAINTOOLS for the queried domain |
| $DTHistoricNameserverProductURL | Permalink for more information on the events of the nameserver for the queried domain |
| $DTHistoricNameserverTimespaninyears | Number of years since DOMAINTOOLS has this information in its database |
| $DTHistoricRegistrarEvents | Count of events of the registrar recorded by DOMAINTOOLS for the queried domain |
| $DTHistoricRegistrarProductURL | Permalink for more information on the events of the registrar for the queried domain |
| $DTHistoricWhoisEarliestevent | Date of the first WHOIS record for the queried domain |
| $DTHistoricWhoisProductURL | Permalink for more information on the WHOIS history for the queried domain |
| $DTHistoricWhoisRecords | Count of WHOIS records present for the queried domain |
| $DTRegistrantDomains | Count of domains the registrant has |
| $DTRegistrantName | Name of the registrant for the domain |
| $DTRegistrantProductURL | Permalink for more information on the registrant for the queried domain |
| $DTRegistrationCreated | Domain registration date |
| $DTRegistrationExpires | Domain registration expiry date |
| $DTRegistrationUpdated | Domain registration updation date |
| $DTSeoProductURL  | Permalink for SEO details of the queried domain |
| $DTSeoScore | SEO score of the website |
| $DTServerIpaddress | IP address of the server on which other domains are hosted  |
| $DTServerOtherdomains | Count of other domains hosted on the server |
| $DTServerProductURL | Permalink for more information on the server |
| $DTWebsitedataProductURL | Permalink to the website of the product (DomainTools), which can be accessed for more information. |
| $DTWebsitedataResponsecode | Response code of the website, when accessed  |
| $DTWebsitedataServer | Server type  |
| $DTWebsitedataTitle | Title of the website  |


###  get_whois

 This function returns the WHOIS record. It includes the most recent details of the ownership record of a domain name or IP address including its basic registration details.

#### Input 
- Domain name or (valid) IP address

#### Example
```
_fetch $Domain from threatsample where $Domain=www.malware.com limit 1
>>_lookup domaintools get_whois $Domain
```

#### Output  
  Click [here](https://drive.google.com/file/d/1NPEqhZ6TvkirYKXjuQAnhv0rAlLEKwh-/view?usp=sharing) to view the output of the above example.

The output of the lookup call has the following structure (for the available data)

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTNameServers | List of nameservers |
| $DTRegistrant | Registrant details for the domain |
| $DTRegistrationCreated | Domain registration date |
| $DTRegistrationExpires | Domain registration expiry date |
| $DTRegistrationRegistrar  | Details of the registrar for the domain |
| $DTRegistrationStatuses | List of registration statuses for the domain |
| $DTRegistrationUpdated | Domain registration updation date |
| $DTWHOISDate | Date when the WHOIS record was last updated |
| $DTWHOISRecord | Raw WHOIS record received from DOMAINTOOLS |


### get_reverse_ip

This function returns a list of domain names that share the same internet host (IP address) as the one specified in the query.  

#### Input 
- IP address

#### Example

```
_fetch $SrcIP from threatsample  limit 1
>>_lookup domaintools get_reverse_ip $SrcIP
```
#### Output 
The output of the query is as shown below
![get_reverse_ip](https://user-images.githubusercontent.com/37173181/41956896-dc82815e-7a02-11e8-82a4-4610735e7848.jpg)

The output of the lookup call has the following structure (for the available data)

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTDomainCount | Count of domain names that share the same internet host (same IP address) |
| $DTDomainNames | List of domain names that share the same internet host |
| $DTIP | IP address being queried |


### get_reverse_domain

This function returns the reverse IP addresses for a specified domain name. When a domain name resolves to multiple IP addresses, the response has multiple nodes. Each node contains an IP address, a domain count and a domain names node.

#### Input 
Domain name

#### Example
```
_fetch $Domain from threatsample limit 1
>>_lookup domaintools get_reverse_domain $Domain
```
#### Output 

The output of the query is as shown below:

![get_reverse_domain](https://user-images.githubusercontent.com/37173181/41958252-1eedc964-7a07-11e8-8cba-11bd3258dea2.jpg)

The output of the lookup call has the following structure (for the available data)
  
 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTDomainCount | Count of domain names that share the same internet host |
| $DTDomainNames | List of domain names that share the same internet host |
| $DTIP | IP address that hosts these domains |



### get_reverse_nameserver

This function returns a list of domain names that share the same primary or secondary nameserver. Reverse nameserver (NS) lets you see all the domain names currently pointed to any nameserver.

#### Input 
- Domain name.

#### Example
```
_fetch $Domain from threatsample limit 1
>>_lookup domaintools get_reverse_nameserver $Domain
```

##### Output 
Click [here](https://drive.google.com/file/d/1GU91qK-dIfHOh2JwMZ8gbtNsTsbHqbVS/view?usp=sharing) to view the output of the above example.

The output of the lookup call has the following structure (for the available data)  

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTNameServerHostname | The nameserver host name |
| $DTNameServerPrimary | Count of domain names pointing to the same nameserver as the primary |
| $DTNameServerSecondary | Count of domain names pointing to the same nameserver as the secondary |
| $DTNameServerTotal | Count of all domain names pointing to the same nameservers as the primary or secondary|
| $DTPrimaryDomains | List of domain names pointing to the same nameservers as the primary |
| $DTSecondaryDomains | List of domain names pointing to the same nameservers as the secondary  |


### get_reverse_whois

This function returns a list of domain names that have your search terms listed in the WHOIS record.

#### Input 
- Terms that describe a domain owner, like an email address or a company name

#### Example
```
_fetch $Email from threatsample limit 1
>>_lookup domaintools get_reverse_whois $Email
```

#### Output  
Click [here](https://drive.google.com/file/d/1rPmzBRTYlVq-uribUGXrKxNFGLjN8ODk/view?usp=sharing)
 to view the output of the above query.

The output of the lookup call has the following structure (for the available data)  

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTDomaincountCurrent | Count of current domains that have your search terms listed in the WHOIS record |
| $DTDomaincountHistoric | Count of historic domains that have your search terms listed in the WHOIS record |
| $DTDomains | List of domain names that have your search terms listed in the WHOIS record |
| $DTReportpriceCurrent | Lists the retail price of the query if you have per-domain pricing access for current domains |
| $DTReportpriceHistoric | Lists the retail price of the query if you have per-domain pricing access for historic domains |


### get_parsed_whois

This function returns parsed information extracted from the most recent raw WHOIS record.

#### Input 
- Domain name or IP address

#### Example
```
_fetch $Domain from threatsample limit 1
>>_lookup domaintools get_parsed_whois $Domain
```

#### Output

Click [here](https://drive.google.com/file/d/1QOpNnJkE6FHhfkU41n9QDpcKhcheBSxD/view?usp=sharing)
 to view the output of the above query.

The output of the lookup call has the following structure (for the available data) , which is variable based on the queried domain present in the WHOIS record

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTCreatedDate | Date when the domain was originally registered |
| $DTUpdatedDate | Date when the domain was last updated |
| $DTExpiredDate | Date when the domain has to be renewed or will expire |
| $DTAdminCity | City of the admin contact present in the WHOIS record |
| $DTAdminCountry | Country of the admin contact present in the WHOIS record |
| $DTAdminEmail | Email of the admin contact present in the WHOIS record |
| $DTAdminName | Name of the admin contact present in the WHOIS record |
| $DTAdminOrg | Organization of the admin contact present in the WHOIS record |
| $DTAdminPhone | Phone number of the admin contact present in the WHOIS record |
| $DTAdminPostal | Postal code of the admin contact present in the WHOIS record  |
| $DTAdminState | State of the admin contact present in the WHOIS record |
| $DTAdminStreet | Street of the admin contact present in the WHOIS record |
| $DTDomain | Name of the domain present in the WHOIS record  |
| $DTNameServers | Nameserver of the domain present in the WHOIS record |
| $DTRegistrantCity | City of the registrant contact present in the WHOIS record |
| $DTRegistrantCountry | Country of the registrant contact present in the WHOIS record |
| $DTRegistrantEmail | Email of the registrant contact present in the WHOIS record |
| $DTRegistrantName | Name of the registrant contact present in the WHOIS record |
| $DTRegistrantOrg | Organization of the registrant contact present in the WHOIS record |
| $DTRegistrantPhone | Phone number of the registrant contact present in the WHOIS record |
| $DTRegistrantPostal | Postal code of the registrant contact present in the WHOIS record |
| $DTRegistrantState | State of the registrant contact present in the WHOIS record |
| $DTRegistrantStreet | Street of the registrant contact present in the WHOIS record |
| $DTRegistrarAbusecontactemail | Email-id of the registrar, to report abuse |
| $DTRegistrarAbusecontactphone | Phone number of the registrar, to report abuse |
| $DTRegistrarIanaid | IANA ID of the registrar |
| $DTRegistrarName | Name of the registrar |
| $DTRegistrarUrl | URL of the registrar |
| $DTRegistrarWhoisserver | Registrar WHOIS server |
| $DTStatuses | List of statuses for the queried domain |
| $DTTechCity | City of the technical contact present in the WHOIS record  |
| $DTTechCountry | Country of the technical contact present in the WHOIS record  |
| $DTTechEmail | Email of the technical contact present in the WHOIS record |
| $DTTechName | Name of the technical contact present in the WHOIS record |
| $DTTechOrg | Organization of the technical contact present in the WHOIS record|
| $DTTechPhone | Phone number of the technical contact present in the WHOIS record |
| $DTTechPostal | Postal code of the technical contact present in the WHOIS record |
| $DTTechState | State of the technical contact present in the WHOIS record |
| $DTTechStreet | Street address of the technical contact present in the WHOIS record |
| $DTWHOIS-Record | Raw copy of the WHOIS record |


### get_reverse_ip_whois

This function returns a list of IP network ranges with WHOIS records that match a queried IP address.

#### Input 
- IP address.

#### Example
```
_fetch $SrcIP from threatsample limit 1
>>_lookup domaintools get_reverse_ipwhois $SrcIP
```

#### Output

Click [here](https://drive.google.com/open?id=15nif8q3ynCYxhDXcIDcuPBfGHdC7wIg8) to view the output of the above query

The output of the lookup call has the following structure (for the available data), which is variable based on the queried IP address present in the WHOIS record:

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTCountry | Country of the queried IP address |
| $DTIPFrom | Start of the IP address block |
| $DTIPTo | End of the IP address block |
| $DTIPFromAlloc | Starting allocation of the range of IP addresses |
| $DTIPToAlloc | Ending allocation of the range of IP addresses |
| $DTOrganization | Name of the organization present in the WHOIS record |
| $DTRange | Range of the IP address block |
| $DTRecordDate | Date of the WHOIS record   |
| $DTRecordIP | IP address present in the WHOIS record  |
| $DTServer | Server returning the WHOIS record |
| $DTWHOISRecord | Raw WHOIS record |


### get_domain_riskscore

This function returns risk scores and threat predictions based on DomainTools Proximity and Threat Profile algorithms.

#### Input 
- Domain name

#### Example
```
_fetch $Domain from threatsample limit 1
>>_lookup domaintools get_domain_riskscore $Domain
```
#### Output 

The output of the query is as shown below

![get_riskscore](https://user-images.githubusercontent.com/37173181/41974315-40ddb998-7a35-11e8-8c59-86e7d211cc1f.jpg)

The output of the lookup call has the following structure (for the available data)

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTDomain | Domain name being queried  |
| $DTblacklistRiskScore | Blacklist risk-scoring for the domain |
| $DTRiskScore | Risk-scoring for the queried domain |


### get_domain_riskscore_evidence

This function returns risk scores and threat predictions based on DomainTools’ Proximity and Threat Profile algorithms and evidence for the categorization made by it. It helps in deeper investigation of a domain.  

#### Input 
- Domain name.

#### Example
```
_fetch $Domain from threatsample limit 1
>>_lookup domaintools get_domain_riskscore_evidence $Domain
```
##### Output 

![get_riskscore_evidence](https://user-images.githubusercontent.com/37173181/42019095-cb783c1c-7ad1-11e8-9d06-fd04da159469.jpg)


The output of the lookup call has the following structure (for available data)  

 | Fields        | Description  |
|:------------- |:-------------|
| $DTResponseCode | <ul><li> Response code of the request </li><li> Refer to the [Common response codes](https://github.com/dnif/lookup-domaintools#common-response-codes) section for details </li></ul> |
| $DTMessage | Error message corresponding to the $DTResponseCode |
| $DTDomain | Domain name being queried  |
| $DTProximityEvidence | Blacklist risk-scoring for the queried domain |
| $DTProximityRiskScore | Score associated with proximity risk |
| $DTThreatProfileRiskScore | Score associated with threat profile |
| $DTRiskScore | Risk-scoring for queried domain |


### Using the DOMAINTOOLS API and DNIF  
The DOMAINTOOLS API is found on github at 

  https://github.com/dnif/lookup-domaintools

#### Getting started with DOMAINTOOLS API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-domaintools.git domaintools
```
4. #####   Move to the `/dnif/<Deployment-key>/lookup_plugins/domaintools/` folder path and open dnifconfig.yml configuration file     
    
    Replace the <Add_your_username_here> and <Add_you_key_here> tags with your DOMAINTOOLS API username and key.
```
lookup_plugin:
  DOMAINTOOLS_USERNAME: <Add_your_username_here>
  DOMAINTOOLS_KEY: <Add_your_key_here>  
```
