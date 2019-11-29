# url_checker
Simple tool to check urls

Url_checker simply check a url or a list of url.

Checks are specified through rules.

It takes in input a url (and optionally a port and a path) and it tryies to get the address based on the rules

E.g. url = www.url_checker.kkk

rule 1: verify if exist https://www.url_checker.kkk:9443/path/to/file

url_checker.py -u www.url_checker.com -p 9443 -t /path/to/file

url_checker tries to get the url and report on the result, following every type of redirect

See rules.txt for some example rules

Options:

-f <file>: a file with a list of url and optionally port and path semicolon separated (url;port;path). See test_url for some examples.

-u <url>: url to test

-p <port>: port to test

-t <path>: path to test

-o <output>: output file

-h: Help
