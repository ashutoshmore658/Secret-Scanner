import os
import re
import concurrent.futures
import json
import boto3

# Function to check if a file exists at the given file_path
def checkFileExist(file_path):
    return os.path.isfile(file_path)

# Function to match key patterns in the file content and update the detected_keys dictionary
def matchContent(file_path, file_content, key_pattern, detected_keys, key_type):
    matches = re.findall(key_pattern, file_content)
    if matches:
        if file_path not in detected_keys.keys():
            detected_keys[file_path] = {}
        duplicates = []
        match_num = 0
        for match in matches:
            if match not in duplicates:
                match_num = match_num + 1
                duplicates.append(match)
                match_dict = {"Key Type" : key_type,
                              "Key Value" : match}
                if match_num not in detected_keys[file_path].keys():
                    detected_keys[file_path][match_num] = []
                    detected_keys[file_path][match_num].append(match_dict)
                else:
                    detected_keys[file_path][match_num].append(match_dict)
    else:
        print(f"[+] File {file_path}   :   Clean (Ready to be pushed)\n")

# Function to scan a file for specific key patterns
def scanner(file_path, detected_keys):
    key_patterns = {"AWS_access_key" : r"(A3T[A-Z0-9]{16}|AKIA[A-Z0-9]{16}|AGPA[A-Z0-9]{16}|AIDA[A-Z0-9]{16}|AROA[A-Z0-9]{16}|AIPA[A-Z0-9]{16}|ANPA[A-Z0-9]{16}|ANVA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})",
                    "AWS_secret_token" : r"(?<![A-Za-z0-9/+=])(?!^[a-z]+$)[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"}
    if checkFileExist(file_path):
        try:
            with open(file_path, "r", encoding = "utf-8") as file_to_read:
                file_content = file_to_read.read()
        except UnicodeDecodeError as error:
            print(f"[+] Skipping file {file_path} cause a error  :  {error}\n")
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers = 2) as executor: #concurrently executing 2 threds each time
            for key_type, key_pattern in key_patterns.items():
                if file_content != "":
                    future = executor.submit(matchContent, file_path, file_content, key_pattern, detected_keys, key_type)
                    future.result()
                else:
                    print("[+] Empty file so skipping the file\n")

# Function to recursively scan a directory and collect file paths
def scanDir(directory, list_files):
    not_include = [".git"]
    with concurrent.futures.ThreadPoolExecutor(max_workers = 5) as executor: #Conccurently executing (5 threads each time)
        for item in os.listdir(directory):
            if item not in not_include:
                item_path = directory + "/" + item
                if os.path.isdir(item_path):
                    future = executor.submit(scanDir, item_path, list_files)
                    future.result()
                else:
                    list_files.append(item_path)

# Function to dump the detected keys into a result file
def dumpData(detected_keys):
    res_file_path = os.environ["report_file_keys"]
    if res_file_path == "" or res_file_path == None:
        print("[+] please provide the environment variable for result file\n")
    with open(res_file_path, "w") as res_file:
        json.dump(detected_keys, res_file)
    print("[+] Dumped resultant data into the result file\n")

def parseResultFile(res_file_path):
    keys_dict = {}
    keys_list = []
    with open(res_file_path, "r") as read_file:
        keys_dict = json.load(read_file)
    for file, keys in keys_dict.items():
        file_keys = []
        file_keys.append(file)
        for key in keys.values():
            key_pair = []
            for pairs in key:
                if pairs["Key Type"] == "AWS_access_key":
                    key_pair.append(pairs["Key Value"])
                if pairs["Key Type"] == "AWS_secret_token":
                    key_pair.append(pairs["Key Value"])
            file_keys.append(key_pair)
        keys_list.append(file_keys)
    return keys_list
    
def checkValidityOfCreds(aws_access_key, aws_secret_key, validity_dict, file):
    print(f"[+] Setting up AWS sts client and checking validity of the keys for {file}\n")
    client = boto3.client('sts', aws_access_key_id = aws_access_key, aws_secret_access_key = aws_secret_key)
    credentials_dict = {}
    credentials_dict["AWS Access Key"] = aws_access_key
    credentials_dict["AWS Secret Key"] = aws_secret_key
    try:
        print("[+] Getting results from the sts client\n")
        identity_dict = client.get_caller_identity()
        print("[+] Got response from STS client\n")
        credentials_dict["Validity"] = "Valid"
        credentials_dict["AWS STS Response"] = identity_dict
    except:
        print("[+] Not found any match for the keys, No results\n")
        credentials_dict["Validity"] = "Invalid"
        credentials_dict["AWS STS Response"] = None
    validity_dict[file].append(credentials_dict)

def dumpValidityData(validity_dict):
    res_file_path = os.environ["validity_report_file"]
    if res_file_path == "" or res_file_path == None:
        print("[+] please provide the environment variable for validity report file\n")
    with open(res_file_path, "w") as res_file:
        json.dump(validity_dict, res_file)
    print("[+] Dumped resultant data into the validity report file\n")



# Main function to handle the scanning process
def keyScanhandler():
    directory = os.environ["repo_to_be_scanned"]
    valid_flag = True
    if not os.path.exists(directory):
        print("[+] Provided path is invalid please enter valid path\n")
        valid_flag = False
    else:
        list_files = []
        detected_keys = {}
        if os.path.isfile(directory):
            print("[+] Given path is only single file so scanning the file only\n")
            scanner(directory, detected_keys)
        else:
            if directory == "" or directory == None:
                print("[+] please enter valid directory to scan")
            scanDir(directory, list_files)
            if len(list_files) != 0:
                with concurrent.futures.ThreadPoolExecutor(max_workers = 5) as executor: #Concurrently executing (5 threds one time)
                    for file in list_files:
                        if os.path.exists(file):
                            print(f"[+] scanning   :   {file}\n")
                            future = executor.submit(scanner, file, detected_keys)
                            future.result()
            else:
                print("[+] The provided directory is empty directory\n")
    if valid_flag and len(detected_keys) != 0:
        print("[+] Dumping data into the result file\n")
        dumpData(detected_keys)
    elif valid_flag and len(detected_keys) == 0:
        print("[+] Not found any keys so not producing any result file\n")
    else:
        print("[+] Provide path was invalid not producing any result file\n")
    print("[+] Checking whether we got the result file or not\n")
    if os.path.isfile(os.environ["report_file_keys"]):
        print("[+] Yes we got the result file\n")
        print("[+] parsing the file\n")
        res_file_path = os.environ["report_file_keys"]
        keys_list = parseResultFile(res_file_path)
        print("[+] Parsed the result file\n")
        print("[+] Sendig keys to STS client for checking validity of keys\n")
        validity_dict = {}
        for lists in keys_list:
            validity_dict[lists[0]] = []
            for keys in lists[1:]:
                print(f"[+] cheking validity of {keys[0]} and {keys[1]}\n")
                checkValidityOfCreds(keys[0], keys[1], validity_dict, lists[0])
        print("[+] Checked validity of all found keys\n")
        dumpValidityData(validity_dict)
    else:
        print("[+] No need to check for validity, no keys found\n")












        
        

