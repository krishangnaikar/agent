# Docker container project to handle many python scripts.

Simple docker container project to handle many python scripts running in the background and monitor them using the supervisord web interface.

### How to run?
1. Build a docker image
    ```
    docker build -t supervisor .
    ```
2. Run the container
    ```
    docker run -dp 9001:9001 --name supervisor supervisor
    ```
3. Now you can go to http://localhost:9001 in your browser and log in using the data from the supervisord.conf file

### Configuration of scripts
The supervisor configuration can be found in the supervisord.conf file.

To add a new script for monitoring, add at the end of the document:
```
[program:script]
command=python /app/healthCheck.py
stdout_logfile=/var/log/supervisor/%(program_name)s.log 
```