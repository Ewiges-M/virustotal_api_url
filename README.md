# Virustotal_api_url_check
Check multiple URL with Virustotal Api

The program will loop to check each URL with Virustotal and store result to "result-from-virustotal.csv" file.

"result-from-virustotal.csv" file contain fields of

1. IP : IP or URL
2. Positives : number of tools deteced by virustotal
3. Totals : totals score
4. Detected as Malware site : List tools that detected IP/URL as Malware site
5. Detected as Malicious site : List tools that detected IP/URL as Malicious site
6. Detected as Suspicious site : List tools that detected IP/URL as Suspicious site

**Usage**

python3 virustotal_api_check_urls.py

![image](https://user-images.githubusercontent.com/70726596/125559042-4293be2c-e799-4838-aafe-3506c27a000f.png)


**Program Input**

1. Multiple URLs split by "," Ex. 1.1.1.1,2.2.2.2,8.8.8.8,...
2. Public Virustotal API key


**How to get apikey**

https://support.virustotal.com/hc/en-us/articles/115002100149-API


**Example result**

![image](https://user-images.githubusercontent.com/70726596/125560032-1365fd06-2608-47eb-85e5-128abe7129a8.png)


**Note**

- This program made for Public Virustotal API.
- The Public Virustotal API is limited to 500 requests per day and a rate of 4 requests per minute. (That why I need to sleep 1 minute for each 4 requests ).
- Some IP was not present in VirusTotal's dataset, result in excel file is "N/A"
