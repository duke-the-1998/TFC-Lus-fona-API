config = {
    "attack": [
        "http"
    ],
    "ignore": [
        "127.0.0.1"
    ],
    "user_agent": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0"
    ],
    "timeout": 3,
    "threads": 50,
    "wordlist": {
        "local": "wordlist.txt",
        "remote": [
            "google",
            "duckduckgo",
            "virustotal"
        ],
        "default": [
            "local",
            "remote"
        ]
    },
    "dns": "1.1.1.1",
    "api": {
        "virustotal": ""
    },
    "no_http_code": [],
    "report": {
        "save": True,
        "folder": "knockpy_report",
        "strftime": "%Y_%m_%d_%H_%M_%S"
    }
}