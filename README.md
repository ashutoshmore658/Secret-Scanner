### Keys Scanner

How to use the keys-scanner:


Export the environment variables to store the result files:

# export the path of repo to be scanned

export repo_to_be_scanned= < absolute path of repo to be scanned(if not covered under version control then also its fine script will handle this)>

# export the result Json file

export report_file_keys=< absolute path of result json file which will contaim found keys >

# export json file to get info about the valid and invalid keys

export valididty_report_file=< absolute path of report file to give info about validity of keys >

# execute the script:

python3 commit_scan.py

You will get both the result files into the provided locations.


