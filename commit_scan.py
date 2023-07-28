
import os
import subprocess
import re
import json
import boto3
import scan as saviour
import concurrent.futures

# Function to perform content matching for detected keys
# Parameters:
# parsed_content (string): The content of the commit parsed from the git show output.
# key_pattern (string): Regular expression pattern to match the keys.
# key_type (string): Type of the key (e.g., "AWS_access_key", "AWS_secret_token").
# detected_keys (dict): A dictionary containing detected keys for each commit.
# header_data (dict): A dictionary containing header information of the commit.
def contentMatching(parsed_content, key_pattern, key_type, detected_keys, header_data):
    # Find all matches of the key pattern in the commit content
    matches = re.findall(key_pattern, parsed_content)
    # Find matches for bad patterns (e.g., short hexadecimal strings)
    bad_pattern = r"\b[0-9a-f]{5,40}\b"
    bad_matches = re.findall(bad_pattern, parsed_content)
    bad_flag = True
    for secret in matches:
        # Check if the match is also present in bad matches; if yes, consider it a bad match
       if secret not in bad_matches:
           bad_flag = False
    if bad_flag:
       print("[+] We got some bad matches returning\n")
       return
     # Extract the commit hash from the header data
    commit_hash = header_data["commit_hash"]
    if matches:
        match_num = 0
        # Create a new entry in detected_keys dictionary if commit_hash is not already present
        if commit_hash not in detected_keys.keys():
            detected_keys[commit_hash] = {}
            detected_keys[commit_hash]["Commited By"] = header_data["commited_by"]
            detected_keys[commit_hash]["Commit Date&Time"] = (header_data["commit_data"]).strip()
            detected_keys[commit_hash]["Secrets"] = []
        duplicates = []
        # Process each match and add it to the detected_keys dictionary
        for match in matches:
            match_num = match_num + 1
            if match not in duplicates:
                if (key_type == "AWS_access_key" and len(match) == 20) or (key_type == "AWS_secret_token" and len(match) ==40):
                    duplicates.append(match)
                    match_dict = {
                        "Key Type" : key_type,
                        "Key Pattern" : match,
                        "Secret Pair No." : match_num
                    }
                    detected_keys[commit_hash]["Secrets"].append(match_dict)
                else:
                    print("[+] A bad match\n")
                    print(f"[+] Commit {commit_hash}   :   Clean \n")           
    else:
        print(f"[+] Commit {commit_hash}   :   Clean \n")


# Function to parse the content of a commit and extract header information
# Parameters:
# commit (string): The commit ID for which the content needs to be parsed.
# header_data (dict): A dictionary to store header information for the commit.
# Return Value:
# parsed_content (string): The parsed content of the commit without the header information.
def commitContentParser(commit, header_data):
    print(f"[+] Parsing contents of {commit} commit\n")
    # Get the commit diff using git show command
    show_commit_diff = subprocess.run(["git", "show", commit], check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    list_commit_data = ((show_commit_diff.stdout).decode()).split("\n")
    commit_hash = ((list_commit_data[0].split(" "))[1]).strip()
    header_data["commit_hash"] = commit_hash
    author = ((list_commit_data[1].split(" "))[1]).strip() + " " + "->" + " " + ((list_commit_data[1].split(" "))[2]).strip()
    header_data["commited_by"] = author
    date_and_time = ""
    print(f"[+] Got headers for {commit}\n")
    for val in list_commit_data[2].split(" ")[1:]:
        date_and_time = date_and_time + " " + val.strip()
    header_data["commit_data"] = date_and_time
    parsed_content = ""
    for data in list_commit_data[3:]:
        parsed_content = parsed_content + " " + data[1:]
    print(f"[+] Prased contents of {commit} commit\n")
    return parsed_content


# Function to scan a commit for potential keys using content matching
# Parameters:
# commit (string): The commit ID to be scanned.
# detected_keys (dict): A dictionary to store detected keys for each commit.
def commitScanner(commit, detected_keys):
    # Define key patterns for AWS access keys and secret tokens
    key_patterns = {"AWS_access_key" : r"(A3T[A-Z0-9]{16}|AKIA[A-Z0-9]{16}|AGPA[A-Z0-9]{16}|AIDA[A-Z0-9]{16}|AROA[A-Z0-9]{16}|AIPA[A-Z0-9]{16}|ANPA[A-Z0-9]{16}|ANVA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})",
                    "AWS_secret_token" : r"(?<![A-Za-z0-9/+=])(?!^[a-z]+$)[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"}
    header_data = {}
    if(commit == ""):
        print("[+] Not a Commit returning")
        return
    parsed_content = commitContentParser(commit, header_data)
    # Execute contentMatching function concurrently for each key pattern
    with concurrent.futures.ThreadPoolExecutor(max_workers = 2) as executor:
        for key_type, key_pattern in key_patterns.items():
            if len(parsed_content) != 0:
                future = executor.submit(contentMatching, parsed_content, key_pattern, key_type, detected_keys, header_data)
                future.result()
            else:
                print("[+] Empty comment so skipped\n")
    
    
# Function to get the commit history of the repository
# Parameters:
# list_commits (list): A list to store commit IDs from the git log.
def getCommitHistory(list_commits):
    print("[+] Getting commit history of repo\n")
    commit_history = subprocess.run(["git", "log", "--all", "--oneline"],check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    commits = ((commit_history.stdout).decode()).split("\n")
    for commit in commits[:-1]:
        list_commits.append((commit.split(" ")[0]).strip())
    print("[+] Got the commit history\n")


# Function to dump the detected_keys dictionary into a result file
# Parameters:
# detected_keys (dict): A dictionary containing detected keys for each commit.
def dumpData(detected_keys):
    res_file_path = os.environ["report_file_keys"]
    if res_file_path == "" or res_file_path == None:
        print("[+] please provide the environment variable for result file\n")
    with open(res_file_path, "w") as res_file:
        json.dump(detected_keys, res_file)
    print("[+] Dumped resultant data into the result file\n")
    return res_file_path

#  Check the validity of AWS credentials by using the AWS STS (Security Token Service) client.
#     Parameters:
#         aws_access_key (str): AWS Access Key ID to be checked.
#         aws_secret_key (str): AWS Secret Access Key corresponding to the Access Key ID.
#         validity_dict (dict): A dictionary to store the validity results for different commits.
#         commit (str): A unique identifier for the commit to which the credentials belong.
#     Prints:
#         The function prints the process of setting up the AWS STS client and checking the validity of the keys.
#         It also provides information about the results obtained from the STS client.
#     Returns:
#         None: The function directly updates the `validity_dict` with the results for the given `commit`.
def checkValidityOfCreds(aws_access_key, aws_secret_key, validity_dict, commit):
    print(f"[+] Setting up AWS sts client and checking validity of the keys for {commit}\n")
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
    validity_dict[commit].append(credentials_dict)

# Parse the result file containing commit-specific secret information and extract relevant details.
# Parameters:
#     res_file_path (str): The file path to the result file containing the commit-specific secret details.
# Returns:
#     list: A list containing commit details and associated secret information in a structured format.
# Note:
#     - The function reads the result file in JSON format, which is assumed to have a specific structure.
#     - The result file should contain a dictionary with commit IDs as keys and their associated details as values.
#     - Each commit may have details such as the committer's name and a list of associated secrets.
#     - The function extracts and structures the commit details and secret information for each commit.
def parseResultFile(res_file_path):
    with open(res_file_path, "r") as read_file:
        secret = json.load(read_file)
    credentials_list = []
    for commit, creds in secret.items():
        commit_details = []
        commit_details.append(commit)
        for keys in creds.keys():
            if keys == "Commited By":
                commit_details.append(creds["Commited By"])
            if keys == "Secrets":
                secret_dict = {}
                for secrets in creds["Secrets"]:
                    secret_num = secrets["Secret Pair No."]
                    if secret_num not in secret_dict.keys():
                        secret_dict[secret_num] = []
                    key_dict = {
                        "Key Type" : secrets["Key Type"],
                        "Key Pattern" : secrets["Key Pattern"]
                    }
                    secret_dict[secret_num].append(key_dict)
                commit_details.append(secret_dict)
        credentials_list.append(commit_details)
    return credentials_list


# Dump the validity check data into a JSON file.
# Parameters:
#     validity_dict (dict): A dictionary containing the validity check data.
# Prints:
#     The function prints the process of dumping the data.
# Note:
#     - The function takes a dictionary `validity_dict` that holds the validity check data.
#     - It writes the data to a JSON file specified by the `validity_report_file` environment variable.
#     - The `validity_report_file` should be set as an environment variable before calling this function.
#     - If the file already exists, its contents will be overwritten with the new validity check data.
#     - If the file does not exist, it will be created in the specified location.
#     - The data in the `validity_dict` is saved in a structured JSON format.        
def dumpValidityData(validity_dict):
    print("[+] Dumping validity check data\n")
    res_file_path = os.environ["validity_report_file"]
    with open(res_file_path, "w") as write_file:
        json.dump(validity_dict, write_file)
    print("[+] Dumped validity check data\n")
    

# Function to handle the commit scanning process
def commitScanHandler():
    detected_keys = {}
    list_commits = []
    valid_path_flag = True
    version_control_flag = True
    res_file_path = ""
    saviour_script_flag = False
    ch_directory = os.environ["repo_to_be_scanned"]
    if os.path.isdir(ch_directory):
        last_char = ch_directory[-1]
        if not (len(ch_directory)==1 and last_char == "/") and last_char == "/":
            ch_directory = ch_directory[:-1]
        if(os.getcwd() != ch_directory):
            print(f"[+] Provided directory is not current working directory : Chnaging to ==> {ch_directory}\n")
            os.chdir(ch_directory)
        try:
            print(f"[+] Checking {ch_directory} is under version control...")
            check_under_version_control = subprocess.run(['git', 'rev-parse', '--is-inside-work-tree'], check = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            print(f"[+] {check_under_version_control.stdout.decode()}\n")
            print(f"[+] {ch_directory} is under version control!!.. proceeding to scan...\n")
            getCommitHistory(list_commits)
            if len(list_commits) != 0:
                with concurrent.futures.ThreadPoolExecutor(max_workers = 5) as executor:
                    for commit in list_commits:
                        print(f"*************************************************   Scanning for {commit}   ************************************************************\n")
                        future = executor.submit(commitScanner, commit, detected_keys)
                        future.result()
            else:
                valid_path_flag = False
                print("[+] Repo with 0 commits\n")
        except Exception as e:
            version_control_flag = False
            print(" [+] The directory is not tracked under version control\n")
            print("[+] Passing control over to saviour script\n")
            saviour.keyScanhandler()
            saviour_script_flag = True

    else:
        if os.path.isfile(ch_directory):
            version_control_flag = False
            saviour.keyScanhandler()
            saviour_script_flag = True
        else:
            print("[+] Provided path for repo to be scanned is invalid\n")
            valid_path_flag = False
    if valid_path_flag and version_control_flag:
        if len(detected_keys) != 0:
            print("[+] Dumping secrets into resulant file\n")
            res_file_path = dumpData(detected_keys)
        else:
            print("[+] All seem to be fine..No secrets found\n")
    else:
        if not valid_path_flag and not version_control_flag:
            print("[+] Something went wrong please look at logs above\n")
            return
        elif valid_path_flag and not version_control_flag:
            print("[+] Saviour script saved us\n")
    if not saviour_script_flag:
        print("[+] Checking whether we got reult file or not\n")
        validity_dict = {}
        credentials_list = []
        if os.path.isfile(res_file_path):
            print("[+] Yes we got a result file\n")
            print("[+] Parsing result file to get credentials\n")
            credentials_list = parseResultFile(res_file_path)
            print("[+] Parsed result file..!!\n")
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                for credential in credentials_list:
                    commit = credential[0]
                    commited_by = credential[1]
                    validity_dict[commit] = []
                    print(f"[+] Checking validity of credentials under {commit} commit\n")
                    for keys in credential[2:]:
                        for cred_num, val in keys.items():
                            aws_access_key = ""
                            aws_secret_key = ""
                            for item in val:
                                if item["Key Type"] == "AWS_access_key":
                                    aws_access_key = item["Key Pattern"]
                                if item["Key Type"] == "AWS_secret_token":
                                    aws_secret_key = item["Key Pattern"]
                            future = executor.submit(checkValidityOfCreds, aws_access_key, aws_secret_key, validity_dict, commit)
                            #checkValidityOfCreds(aws_access_key, aws_secret_key, validity_dict, commit)
                            future.result()
                    validity_dict[commit].append({"Commited By" : commited_by})
                print("[+] Checked validity of the found keys\n")
                dumpValidityData(validity_dict)
        else:
            print("[+] No result file found on the given location so no need to do validity check of keys\n")
            




        

# Entry point for the script 
print("Starting Scan....!!!\n\n")
commitScanHandler()
print("Done...!!")


