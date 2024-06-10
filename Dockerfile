"""
This Dockerfile sets up an environment for running a Python application using Supervisor for process control.

1. `FROM python:3.10.5-slim-buster`: Specifies the base image as Python 3.10.5 on Debian Buster (Slim variant).

2. `RUN apt-get -y update && apt-get -y upgrade`: Updates the package lists and upgrades the installed packages in the image.

3. `RUN apt-get -y install supervisor`: Installs the Supervisor package, which is used for process control.

4. `RUN apt-get -y install vim`: Installs the Vim text editor.

5. `WORKDIR /app`: Sets the working directory inside the container to `/app`.

6. `COPY . .`: Copies the local directory (presumably containing the application code) into the `/app` directory in the container.

7. `COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf`: Copies the `supervisord.conf` file from the local directory into the Supervisor configuration directory in the container.

8. `RUN pip install -r requirement.txt`: Installs Python dependencies listed in the `requirement.txt` file.

9. `CMD ['/usr/bin/supervisord']`: Specifies the command to run when the container starts, which in this case is to start Supervisor to manage the application processes.
"""

FROM python:3.10.5-slim-buster

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install supervisor
RUN apt-get -y install vim

WORKDIR /app

COPY . .

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN pip install -r requirement.txt

CMD ["/usr/bin/supervisord"]
