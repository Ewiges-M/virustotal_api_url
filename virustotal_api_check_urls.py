import requests
import time
import csv
start_time = time.time()
print("Search list of IP from Virustotal. Input format is 8.8.8.8,1.1.1.1 ")
user_input = input('Enter list of IP : ').split(',')
apikey = input('Enter Virustotal API Key : ')
list_ip = user_input
total_data_to_csv = []

def connectToVirustotal(ip):
        try:
            
            url = 'https://www.virustotal.com/vtapi/v2/url/report'

            params = {'apikey': str(apikey), 'resource': ip}

            response = requests.get(url, params=params)
            
            result = response.json()
            
            print (ip + " Connected")
            
            if result["response_code"] == 1:
                positives_tools = str(result["positives"])
                total_tools = str(result["total"])
                detected_tools = result['scans']
                detected_as_malware_site = []
                detected_as_malicious_site = []
                detected_as_suspicious_site = []
                for key in detected_tools.keys():
                    resultScan = detected_tools[key]['result']
                    if resultScan == 'malware site':
                        detected_as_malware_site.append(key)
                    elif resultScan == 'malicious site':
                        detected_as_malicious_site.append(key)
                    elif resultScan == 'suspicious site':
                        detected_as_suspicious_site.append(key)
                data = [ip,positives_tools,total_tools,', '.join(detected_as_malware_site),', '.join(detected_as_malicious_site),', '.join(detected_as_suspicious_site)]
                total_data_to_csv.append(data)
            else:
                print(ip + " was not present in VirusTotal's dataset")
                data = [ip, 'N/A', 'N/A', 'N/A', 'N/A', 'N/A']
                total_data_to_csv.append(data)
        except:
            print(ip + " Can't connect to Virustotal")

def writeToFile():
    header = ['IP', 'Positives', 'Totals', 'Detected as Malware site', 'Detected as Malicious site', 'Detected as Suspicious site']

    with open('result-from-virustotal.csv', 'w', encoding='UTF8', newline='') as f:
        print("writing data to file result-from-virustotal.csv ...")
        writer = csv.writer(f)

        writer.writerow(header)

        writer.writerows(total_data_to_csv)
    print("Succussful write data to file result-from-virustotal.csv")
    
def main():
    count_for_wait_api = 0
    for ip in list_ip:
        print(count_for_wait_api)
        if count_for_wait_api < 3:
            connectToVirustotal(ip)
            count_for_wait_api = count_for_wait_api + 1
        else:
            print("Sleep for 1 min")
            time.sleep(70)
            connectToVirustotal(ip)
            count_for_wait_api = 0
    writeToFile()
    print("--- %s seconds ---" % (time.time() - start_time))
   
main()



    
