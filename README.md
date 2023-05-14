# Port Scanner
This application was ment to be used as fast tool for scanning the ports to find 
what services are running on the server and which ports are unlocked.
So you can say it is sort of a clone of [nmap](https://nmap.org/) - and in fact it is. 
In compare to *nmap*, port scanner does not have some functionality
like domain resolving. But you can build any tools you need into that application.

## Future
I always wanted to come back to that project and improve for example connectors.
For that perpose I've started to writing my own library to handle websockets,
which will be integrated into that project, when I will finalized my Buchelors thesis.

Another features, I wanted to add in future are more advanced attack vectors 
and a little hidden from traffic monitoring on the server (which would slower down performance).

## Usage
```
usage: portscan <Ip address> <Ip mask> [-t <timeout in ms>]
                [-f | --fast] [-p <from> <to>]
                [-TCP] [-UDP] [-ALL] [-h | --help]
                [-th <threads>] [--no-threads]
                [--crazy]

--crazy
        For every request create a new thread.
        Not recommended, but it's really fast.
        Anyway, you should probably set timeout to 5-10s,
        because the function is to fast
```

## License
I am publishing this program under the **MIT license**, 
so you can do whatever you want with that code. However, 
you are required to acknowledge me as the original author.
