# wsproxy
A Secure High-Performace Proxy Based on Websocket.



## usage

1. Prepare Environment

   ```
   git clone https://github.com/hikerell/wsproxy
   cd wsproxy
   pip3 install -r requirements.txt
   ```

2. config server endpoint

   config server.cfg:

   ```
   {
       "client": {},
       "server": {
           "host": "0.0.0.0",
           "port": 12345,
           "password": "password"
       },
       "log": {
           "path": "log/server.log"
       }
   }
   
   ```

   start wsproxy server:

   ```
   python3 main.py server start server.cfg
   ```

3. config client endpoint

   config client.cfg:

   ```
   {
       "client": {
           "socks": {"host": "0.0.0.0", "port": 1080},
           "http":  {"host": "0.0.0.0", "port": 1081},
           "pac":   {"host": "0.0.0.0", "port": 1082}
       },
       "server": {
           "balance": "off",
           "default": "sg",
           "all":{
               "us": { "ip": "8.8.8.8", "port": 12345, "password": "password" }
           }
       },
       "log": {
           "path": "log/client.log"
       }
   }
   ```

   start wsproxy client:

   ```
   python3 main.py client start client.cfg
   ```



## Command Options

```
python3 main.py -h
```

>wsproxy: A Secure High-Performace Proxy Based on Websocket
>
>
>
>Usage:
>
>​    wsproxy.py -h
>
>​    wsproxy.py server start <config> [-d] [-v]
>
>​    wsproxy.py client start <config> [-d] [-v]
>
>​    wsproxy.py server (stop|status)
>
>​    wsproxy.py client (stop|status)
>
>
>
>Options:
>
>​    -h --help       show help message
>
>​    -d --daemon     daemon mode
>
>​    -v --verbose    verbose mode



## Statements And Declarations

> This project's ultimate goal is to become a network traffic analysis framework, but not to VPN or the similar.  
>
> The project is prohibited from illegal activities.
>
> Anyone using the project is responsible for their actions.
>
> Project developers will not be held liable for any illegal usage involved the project.