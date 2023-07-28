Export the variables:

# export the path of repo to be scanned

export repo_to_be_scanned=< absolute path of repo to be scanned(if not covered under version control then also its fine script will handle this)>

# export the result Json file

export report_file_keys=<absolute path of result json file>

# export json file to get info about the valid and invalid keys

export valididty_report_file=<absolute path of report file to give info about validity of keys>

Then execute the script:

python3 commit_scan.py

you will get the result Json file in the location that you provided with that name

and the valididty file on the location you given


