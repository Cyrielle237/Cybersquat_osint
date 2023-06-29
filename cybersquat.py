import dnstwist
import requests
import json
import os
import time
import Levenshtein
import pandas as pd


VT_KEY = "ENTER THE KEY"
class Domain_check:

    def __init__(self):
        
        self.data = ""
        pass
    
    def cybersquatting_list(self, domain):
        print("Starting, please the retrieval might be very long depending on the domain name popularity. \nLet the program run!")
        data = dnstwist.run(domain=domain, registered=True, format='null')

        #Save the file in result
        with open(f"results/cybersquatting_results/{domain}.json", 'w') as file:
            json.dump(data, file, indent=4)
        
        return data
        

    def malicious_verif(self):
        domain_name = input("Please, enter the  domain to test in the form **domain.name** please \n \t")
        
        #If the domain in scanned for the first time, do the scan and save it
        if not os.path.exists(f"results/cybersquatting_results/{domain_name}.json"):
            self.data = self.cybersquatting_list(domain_name)
                
        else :
            print("The file exists, let us use it to check for malicious intent \n")
            with open(f"results/cybersquatting_results/{domain_name}.json", "r") as file:
                content = file.read()
                if len(content.strip()) == 0:
                    self.data = self.cybersquatting_list(domain_name)
                else:
                    try:
                        self.data= json.loads(content)
                    except json.JSONDecodeError:
                        return False
                           
            #return
            # Take the scanned file and check if it is malicious or not
            
            # Read data 
            print(f"Please, we check for malicious any activity, it will take some minutes\n") 
            
             
            
        original_domain = self.data[0]['domain']       
             
        for domain_dict in self.data:
            domain_dict['similarity_score'] = Levenshtein.distance(original_domain, domain_dict['domain'])
            
            malicious_check = {}
            if domain_dict['fuzzer'] != '*original':                   
                url = f"https://www.virustotal.com/api/v3/domains/{domain_dict['domain']}"
                    
                headers = {
                    "accept": "application/json",
                    "x-apikey": VT_KEY   
                }
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = json.loads(response.text)
                    for record in data['data']["attributes"]["last_dns_records"]: 
                        if 'dns_a' in domain_dict and record['value']not in domain_dict['dns_a'] and record["type"] == "A" :
                            domain_dict['dns_a'].append(record['value']) 
                            
                        if data['data']["attributes"]["last_analysis_stats"]['malicious'] > 0:
                            domain_dict['potentially_malicious'] = 'Y'
                            if 'last_https_certificate' in data['data']["attributes"]:
                                domain_dict['alternative_domain_names'] = data['data']["attributes"]["last_https_certificate"]['extensions']['subject_alternative_name']
                        else:
                            domain_dict['potentially_malicious'] = 'N'
                elif response.status_code == 404:
                    # We notify it with the message
                    domain_dict['comment'] = 'Nothing found fot this domain name'
                else:
                    #we add a default value
                    domain_dict['comment'] = f'message error {response.status_code}'
            time.sleep(35)
            
        with open(f"results/report_files/{domain_name}_final.json", 'w') as file:
            json.dump(self.data, file, indent=4)
 
    
process = Domain_check()  
process.malicious_verif()

    