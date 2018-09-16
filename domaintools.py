import yaml
import requests
import datetime
import os
import json
import sys
import re

path = os.environ["WORKDIR"]


with open(path + "/lookup_plugins/domaintools/dnifconfig.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)
    api_username = cfg['lookup_plugin']['DOMAINTOOLS_USERNAME']
    api_key = cfg['lookup_plugin']['DOMAINTOOLS_KEY']


def execute():
    print "hello the world!"


def check_config():
    print cfg['lookup_plugin']['DOMAINTOOLS_USERNAME']
    print cfg['lookup_plugin']['DOMAINTOOLS_KEY']


def get_domain_profile(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/domain-profile
    for i in inward_array:
        if var_array[0] in i:
            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/" + str(s)
            except Exception,e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' +api_username +'&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                data = json_response['response']['history']
                c = data.keys()
                for j in c:
                    for jj in data[j].keys():
                        if data[j][jj] != '' and data[j][jj] != []:
                            a= str(j)
                            if a=="ip_address":
                                a="IPAddress"
                            else:
                                a=a.replace('_','').title()
                            b=str(jj)
                            if b=="product_url":
                                b="ProductURL"
                            else:
                                b=b.replace('_','').title()
                            i['$DTHistoric'+a+b] = data[j][jj]
            except Exception:
                pass
            try:
                data = json_response['response']
                c = data.keys()

                c = [x for x in c if x !='history'and x!='name_servers']

                for j in c:
                    for jj in data[j].keys():
                        if data[j][jj] != '' and data[j][jj] != []:
                            a = str(j)
                            if a == "ip_address":
                                a = "IPAddress"
                            else:
                                a = a.replace('_', '').title()
                            b = str(jj)
                            if b == "product_url":
                                b = "ProductURL"
                            else:
                                b = b.replace('_', '').title()

                            if type(data[j][jj])!= dict:
                                i['$DT' + a + b] = data[j][jj]
                            else:
                                tmp_dict ={}
                                tmp_dict=data[j][jj]
                                if len(tmp_dict)>0:
                                    i['$DT' + a + b] = tmp_dict.values()
            except Exception:
                pass
            try:
                ns = []
                for ai in json_response['response']['name_servers']:
                        ns.append(ai['server'])
                if len(ns)>0:
                    i['$DTNameServers'] = list(set(ns))
            except Exception:
                pass
    return inward_array


def get_whois(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/whois-lookup
    for i in inward_array:
        if var_array[0] in i:
            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain or IP address"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/" + str(s) + "/whois"
            except Exception,e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' + api_username +'&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTNameServers'] = json_response['response']['name_servers']
            except Exception:
                pass
            try:
                i['$DTRegistrant'] = json_response['response']['registrant']
            except Exception:
                pass
            try:
                i['$DTRegistrationCreated'] = json_response['response']['registration']['created']
            except Exception:
                pass
            try:
                i['$DTRegistrationExpires'] = json_response['response']['registration']['expires']
            except Exception:
                pass
            try:
                i['$DTRegistrationRegistrar'] = json_response['response']['registration']['registrar']
            except Exception:
                pass
            try:
                i['$DTRegistrationUpdated'] = json_response['response']['registration']['updated']
            except Exception:
                pass
            try:
                i['$DTRegistrationStatuses'] = json_response['response']['registration']['statuses']
            except Exception:
                pass
            try:
                i['$DTWHOISDate'] = json_response['response']['whois']['date']
            except Exception:
                pass
            try:
                i['$DTWHOISRecord'] = json_response['response']['whois']['record']
            except Exception:
                pass
    return inward_array


def get_reverse_ip(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/reverse-ip
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/"+str(i[var_array[0]])+"/host-domains"

            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' + api_username
                                   + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTDomainCount'] = json_response['response']['ip_addresses']['domain_count']
            except Exception:
                pass
            try:
                i['$DTDomainNames'] = json_response['response']['ip_addresses']['domain_names']
            except Exception:
                pass
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTIP']=json_response['response']['ip_addresses']['ip_address']
            except Exception:
                pass
    return inward_array


def get_reverse_domain(inward_array,var_array):
    # https://www.domaintools.com/resources/api-documentation/reverse-ip
    for i in inward_array:
        if var_array[0] in i:
            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/" + str(s) + "/reverse-ip"
            except Exception, e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e

            try:
                i['$DTIp'] = json_response['response']['ip_addresses']['ip_address']
            except Exception:
                pass
            try:
                i['$DTDomainNames'] = json_response['response']['ip_addresses']['domain_names']
            except Exception:
                pass
            try:
                i['$DTDomainCount'] = json_response['response']['ip_addresses']['domain_count']
            except Exception:
                pass
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
    return inward_array


def get_reverse_nameserver(inward_array,var_array):
    #https: // www.domaintools.com / resources / api - documentation / reverse - name - server
    for i in inward_array:
        if var_array[0] in i:
            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/" + str(s) + "/name-server-domains"
            except Exception, e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTNameServerHostname'] = json_response['response']['name_server']['hostname']
            except Exception:
                pass
            try:
                i['$DTNameServerPrimary'] = json_response['response']['name_server']['primary']
            except Exception:
                pass
            try:
                i['$DTNameServerSecondary'] = json_response['response']['name_server']['secondary']
            except Exception:
                pass
            try:
                i['$DTNameServerTotal']=json_response['response']['name_server']['total']
            except Exception:
                pass
            try:
                i['$DTPrimaryDomains'] = list(set(json_response['response']['primary_domains']))
            except Exception:
                pass
            try:
                i['$DTSecondaryDomains'] =list(set(json_response['response']['secondary_domains']))
            except Exception:
                pass
    return inward_array


def get_ip_monitor(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/ip-monitor/?query="+str(i[var_array[0]])
            try:
                res = requests.get("https://api.domaintools.com" + params + '&api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                if json_response['response']['alerts'] != []:
                    i['$DTAlerts'] = json_response['response']['alerts']
            except Exception:
                pass
            try:
                i['$DTDate'] = json_response['response']['date']
            except Exception:
                pass
            try:
                i['$DTIPAddress'] = json_response['response']['ip_address']
            except Exception:
                pass
            try:
                i['$DTLimit'] = json_response['response']['limit']
            except Exception:
                pass
            try:
                i['$DTTotal'] = json_response['response']['total']
            except:
                pass
    return inward_array


def get_reverse_ip_whois(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/reverse-ip-whois/?ip="+str(i[var_array[0]])
            try:
                res = requests.get("https://api.domaintools.com" + params  +'&api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTCountry'] = json_response['response']['country']
            except Exception:
                pass
            try:
                i['$DTIPFrom'] = json_response['response']['ip_from']
            except Exception:
                pass
            try:
                i['$DTIPFromAlloc'] = json_response['response']['ip_from_alloc']
            except Exception:
                pass
            try:
                i['$DTIPTo'] = json_response['response']['ip_to']
            except Exception:
                pass
            try:
                i['$DTIPToAlloc'] = json_response['response']['ip_to_alloc']
            except Exception:
                pass
            try:
                i['$DTOrganization'] = json_response['response']['organization']
            except Exception:
                pass
            try:
                i['$DTRange'] = json_response['response']['range']
            except Exception:
                pass
            try:
                i['$DTRecordDate'] = json_response['response']['record_date']
            except Exception:
                pass
            try:
                i['$DTRecordIP'] = json_response['response']['record_ip']
            except Exception:
                pass
            try:
                i['$DTServer'] = json_response['response']['server']
            except Exception:
                pass
            try:
                i['$DTShortRecordIP'] = json_response['response']['short_record_ip']
            except Exception:
                pass
            try:
                i['$DTWHOISRecord'] = json_response['response']['whois_record']
            except Exception:
                pass
    return inward_array


def get_reverse_whois(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/reverse-whois
    for i in inward_array:
        if var_array[0] in i:

            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/reverse-whois/?terms=" + str(s)
            except Exception, e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '&api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                data = json_response['response']
                c = data.keys()
                c = [x for x in c if x != 'domains' ]
                for j in c:
                    for jj in data[j].keys():
                        if data[j][jj] != '' and data[j][jj] != []:
                            a= str(j)
                            a=a.replace('_','').title()
                            b=str(jj)
                            b=b.replace('_','').title()
                            i['$DT'+a+b] = data[j][jj]
            except Exception:
                pass
            try:
                i['$DTDomains'] = json_response['response']['domains']
            except Exception:
                pass
    return inward_array


def get_brand_monitor(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/brand-monitor
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/mark-alert/?query="+str(i[var_array[0]])

            try:
                res = requests.get("https://api.domaintools.com" + params + '&api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                if json_response['response']['alerts'] != []:
                    i['$DTAlerts'] = json_response['response']['alerts']
            except Exception:
                pass
            try:
                i['$DTDate'] = json_response['response']['date']
            except Exception:
                pass
            try:
                if json_response['response']['exclude'] != []:
                    i['$DTExclude'] = json_response['response']['exclude']
            except Exception:
                pass
            try:
                i['$DTLimit'] = json_response['response']['limit']
            except Exception:
                pass
            try:
                i['$DTNew'] = json_response['response']['new']
            except Exception:
                pass
            try:
                i['$DTOnHold'] = json_response['response']['on-hold']
            except Exception:
                pass
            try:
                i['$DTQuery'] = json_response['response']['query']
            except Exception:
                pass
            try:
                i['$DTTotal'] = json_response['response']['total']
            except Exception:
                pass
            try:
                i['$DTutf8'] = json_response['response']['utf8']
            except Exception:
                pass
    return inward_array


def get_nameserver_monitor(inward_array,var_array):
    #https: // www.domaintools.com / resources / api - documentation / name - server - monitor
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/name-server-monitor/?query="+str(i[var_array[0]])

            try:
                res = requests.get("https://api.domaintools.com" + params + '&api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                if json_response['response']['alerts'] != []:
                    i['$DTAlerts'] = json_response['response']['alerts']
            except Exception:
                pass
            try:
                i['$DTDate'] = json_response['response']['date']
            except Exception:
                pass
            try:
                i['$DTLimit'] = json_response['response']['limit']
            except Exception:
                pass
            try:
                i['$DTNameServer'] = json_response['response']['name_server']
            except Exception:
                pass
            try:
                i['$DTPage'] = json_response['response']['page']
            except Exception:
                pass
            try:
                i['$DTTotal'] = json_response['response']['total']
            except Exception:
                pass
            try:
                i['$DTPageCount'] = json_response['response']['page_count']
            except Exception:
                pass
    return inward_array


def get_hosting_history(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/"+str(i[var_array[0]])+"/hosting-history"

            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' + api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                ip_data = []
                for ihist in json_response['response']['ip_history']:
                    ip_data.append("Action-Date : "+str(ihist['actiondate'])
                                   +"\nAction-Description : "+ihist['action_in_words']
                                   +"\nDomain : "+ihist['domain']
                                   +"\nPre-IP : "+str(ihist['pre_ip'])
                                   +"\nPost-IP : "+str(ihist['post_ip'])+"\n")
                hist_ip = ''.join(str(e) for e in ip_data)
                i['$DTIpHistory'] = hist_ip
            except Exception:
                pass
            try:
                ns_data = []
                for nshist in json_response['response']['nameserver_history']:
                    ns_data.append("Action-Date : "+str(nshist['actiondate'])
                                   +"\nAction-Description : "+nshist['action_in_words']
                                   +"\nDomain : "+nshist['domain']
                                   +"\nPre-MNS : "+str(nshist['pre_mns'])
                                   +"\nPost-MNS : "+str(nshist['post_mns'])+"\n")
                hist_ns = ''.join(str(e) for e in ns_data)
                i['$DTNameServerHistory'] = hist_ns
            except Exception:
                pass
            try:
                reg_data = []
                for reghist in json_response['response']['registrar_history']:
                    reg_data.append("Date-Created : " + str(reghist['date_created'])
                                   + "\nDate-Expires : " +str(reghist['date_expires'])
                                   + "\nDate-LastChecked : " +str(reghist['date_lastchecked'])
                                   + "\nDate-Updated : " + str(reghist['date_updated'])
                                   + "\nDomain : " + str(reghist['domain'])
                                   + "\nRegistrar : " + str(reghist['registrar'])
                                   + "\nRegistrartag : " + str(reghist['registrartag']))
                hist_reg = ''.join(str(e) for e in reg_data)
                i['$DTRegistrarHistory'] = hist_reg
            except Exception:
                pass
    return inward_array


def get_parsed_whois(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/" + str(s) + "/whois/parsed"
            except Exception, e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '?api_username=' +api_username + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                data = json_response['response']['parsed_whois']['contacts']
                c = data.keys()
                for k in c:
                    for ii in data[k].keys():
                        if data[k][ii] != '' and data[k][ii] != []:
                            i['$DT' + str(k).title() + str(ii).title()] = data[k][ii]
            except Exception:
                pass
            try:
                rem_data = json_response['response']['parsed_whois']
                if rem_data['created_date'] != '' and rem_data['created_date'] != []:
                    i['$DTCreatedDate']=rem_data['created_date'][:rem_data['created_date'].index('+')]
            except Exception :
                pass
            try:
                if rem_data['domain'] != [] and rem_data['domain'] != '':
                    i['$DTDomain'] = rem_data['domain']
            except Exception:
                pass
            try:
                if rem_data['expired_date'] != [] and rem_data['expired_date'] != '':
                    i['$DTExpiredDate'] = rem_data['expired_date']
            except Exception:
                pass
            try:
                if rem_data['name_servers'] != [] and rem_data['name_servers'] != '':
                    i['$DTNameServers'] = rem_data['name_servers']
            except Exception:
                pass
            try:
                if rem_data['statuses'] != [] and rem_data['statuses'] != '':
                    i['$DTStatuses'] = rem_data['statuses']
            except Exception:
                pass
            try:
                if rem_data['updated_date'] != [] and rem_data['updated_date'] != '':
                    i['$DTUpdatedDate'] = rem_data['updated_date']
            except Exception:
                pass
            try:
                d = ['other_properties', 'registrar']
                for j in d:
                    for jj in rem_data[j].keys():
                        if rem_data[j][jj] != '' and rem_data[j][jj] != []:
                            i['$DT' + str(str(j).replace('_', '')).title() + str(str(jj).replace('_', '')).title()] = rem_data[j][jj]
            except Exception:
                pass
            try:
                i['$DTWHOIS-Record'] = json_response['response']['whois']['record']
            except Exception:
                pass
    return inward_array


def get_domain_riskscore(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/domain-profile
    for i in inward_array:
        if var_array[0] in i:
            try:
                data = str(i[var_array[0]])
                pattern = re.match("(?:\w+\:\/{1,})?([^//\s]+).*",data)
                if pattern is None:
                    i['$DTResponseCode'] = 0
                    i['$DTMessage'] = "Provide a valid Domain or IP address"
                    return inward_array
                else:
                    s = pattern.group(1)
                    params = "/v1/risk/?domain=" + str(s)
            except Exception,e:
                print 'Domain Name Error %s' % e
            try:
                res = requests.get("https://api.domaintools.com" + params + '&api_username=' +api_username +'&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTDomain']=json_response['response']['domain']
            except Exception:
                pass
            try:
                i['$DTRiskScore']=json_response['response']['risk_score']
            except Exception:
                pass
            try:
                role =[]
                for rl in json_response['response']['components']:
                    role.append(rl['name'])
                for r in json_response['response']['components']:
                    if r['name'] in role:
                        if r['name']=="proximity":
                            r['name']="Proximity"
                        elif r['name']=="threat_profile":
                            r['name']="ThreatProfile"
                        elif r['name']=="threat_profile_phishing":
                            r['name']="ThreatProfilePhishing"
                        elif r['name']=="threat_profile_malware":
                            r['name']="ThreatProfileMalware"
                        elif r['name']=="threat_profile_spam":
                            r['name']="ThreatProfileSpam"
                        i['$DT' + r['name']+'RiskScore']=r['risk_score']
            except Exception:
                pass
    return inward_array


def get_domain_riskscore_evidence(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/domain-profile
    for i in inward_array:
        if var_array[0] in i:
            params = "/v1/risk/evidence/?domain="+str(i[var_array[0]])
            try:
                res = requests.get("https://api.domaintools.com" + params + '&api_username=' +api_username +'&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTDomain']=json_response['response']['domain']
            except Exception:
                pass
            try:
                i['$DTRiskScore']=json_response['response']['risk_score']
            except Exception:
                pass
            try:
                role =[]
                for rl in json_response['response']['components']:
                    role.append(rl['name'])
                for r in json_response['response']['components']:
                    if r['name'] in role:
                        if r['name']=="proximity":
                            r['name']="Proximity"
                        elif r['name']=="threat_profile":
                            r['name']="ThreatProfile"
                        elif r['name']=="threat_profile_phishing":
                            r['name']="ThreatProfilePhishing"
                        elif r['name']=="threat_profile_malware":
                            r['name']="ThreatProfileMalware"
                        elif r['name']=="threat_profile_spam":
                            r['name']="ThreatProfileSpam"
                        i['$DT' + r['name']+'RiskScore']=r['risk_score']
                        i['$DT'+r['name']+'Evidence']=r['evidence']
            except Exception:
                pass
    return inward_array


def get_reverse_ip2(inward_array,var_array):
    #https://www.domaintools.com/resources/api-documentation/reverse-ip
    for i in inward_array:
        if var_array[0] in i :
            params = "/v1/reverse-ip-whois/?ip="+str(i[var_array[0]])
            param2=str(i[var_array[1]])
            try:
                res = requests.get("https://api.domaintools.com" + params+'&country=I'+param2 + '&api_username=' + api_username
                                   + '&api_key='+api_key)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$DTDomainCount'] = json_response['response']['ip_addresses']['domain_count']
            except Exception:
                pass
            try:
                i['$DTDomainNames'] = json_response['response']['ip_addresses']['domain_names']
            except Exception:
                pass
            try:
                i['$DTResponseCode']=json_response['error']['code']
                i['$DTMessage']=json_response['error']['message']
            except Exception:
                pass
            try:
                i['$DTIP']=json_response['response']['ip_addresses']['ip_address']
            except Exception:
                pass
    return inward_array